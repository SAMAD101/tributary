# AF_XDP backend (Linux, feature `afxdp`)

`crates/capture/src/afxdp.rs`. Library: xsk-rs 0.9 (libxdp/libbpf via `libxdp-sys`, built from vendored source). Compile-checked and clippy-clean in Docker (`scripts/check_linux_afxdp.sh`, `rust:1-bookworm`). Not yet run against a NIC.

## Build

```sh
sudo apt install clang llvm libelf-dev zlib1g-dev pkg-config m4 make
cargo build --release -p tributary --features afxdp
```

## Run — one process/thread per RSS queue

```sh
IF=enp1s0f0
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages            # UMEM: 4096 × 2 KiB per queue, huge-page backed
sudo ethtool -L $IF combined 4                             # RSS queues = capture cores
sudo ethtool -N $IF flow-type udp4 dst-port 10378 action 0 # optional steering
grep $IF /proc/interrupts
echo 2 | sudo tee /proc/irq/<irq-of-queue-0>/smp_affinity  # queue 0 IRQ → core 1
# kernel cmdline: isolcpus=1-4 nohz_full=1-4 rcu_nocbs=1-4
sudo ./target/release/tributary live --backend afxdp --iface $IF --queue 0 --core 1
sudo ./target/release/tributary live --backend afxdp --iface $IF --queue 1 --core 2
```

Requires root or CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN. libxdp attaches `xsk_def_xdp_prog` (XSKMAP redirect) on the first socket; unmatched queues fall through to the kernel stack.

## Design

* One UMEM per queue, all frames posted to the fill ring at start.
* `poll`: read RX ring (userspace atomics) → `&umem[frame]` to the sink → descriptors back on the fill ring. No syscall, no allocation.
* `XDP_ZEROCOPY`: NIC DMA into the UMEM; fails if the driver cannot (`zero_copy: false` for veth/virtio copy mode).
* `XDP_USE_NEED_WAKEUP`: one `poll(fd, 0)` when the RX ring is empty and the flag is set.
* Timestamps: `CLOCK_REALTIME` (vDSO) once per batch. Per-packet NIC hardware timestamps: custom XDP program with `bpf_xdp_metadata_rx_timestamp()` (kernel ≥ 6.3, driver support) writing into frame headroom; `poll()` reads `umem.headroom(desc)`.

```
NIC RSS queue q ──> AF_XDP socket q ──> pinned core q: parse → gapdetect (per session)
                                                   └─> SPSC ring → arbiter/store core
```

Queues needed = `target_pps / per_core_pps` (BENCHMARKS.md §7).
