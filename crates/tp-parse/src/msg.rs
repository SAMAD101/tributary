//! DEEP 1.0 / TOPS 1.6 message bodies.
//!
//! Every message starts with a 1-byte type, a 1-byte type-specific flag/char,
//! an 8-byte little-endian timestamp (ns since epoch, the *matching-engine
//! event time*), and — for all types except System Event — an 8-byte
//! space-padded symbol. Prices are `i64` in units of 1e-4 USD.
//!
//! Layouts below are from the DEEP 1.0 and TOPS 1.6 specs (both use identical
//! encodings for the shared types) and were cross-checked against
//! rob-blackbourn/iex_parser struct strings and real HIST data.
//!
//! ```text
//! type  name                        total len   fields after [type,flag,ts,symbol]
//! 'S'   System Event                 10        (no symbol)
//! 'D'   Security Directory           31        round_lot_size u32, adjusted_poc_price i64, luld_tier u8
//! 'H'   Trading Status               22        reason [u8;4]
//! 'I'   Retail Liquidity Indicator   18
//! 'O'   Operational Halt             18
//! 'P'   Short Sale Price Test        19        detail u8
//! 'Q'   Quote Update                 42        bid_size u32, bid_price i64, ask_price i64, ask_size u32
//! 'T'   Trade Report                 38        size u32, price i64, trade_id i64
//! 'X'   Official Price               26        price i64
//! 'B'   Trade Break                  38        size u32, price i64, trade_id i64
//! 'A'   Auction Information          80        see [`AuctionInformation`]
//! '8'   Price Level Update (buy)     30        size u32, price i64
//! '5'   Price Level Update (sell)    30        size u32, price i64
//! 'E'   Security Event               18
//! ```

use crate::{read_pod, ParseError, Pod};

/// 8-byte, space-padded ASCII symbol.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Symbol(pub [u8; 8]);

impl Symbol {
    #[inline]
    pub fn as_str(&self) -> &str {
        let end = self.0.iter().position(|&c| c == b' ' || c == 0).unwrap_or(8);
        core::str::from_utf8(&self.0[..end]).unwrap_or("?")
    }
}
impl core::fmt::Debug for Symbol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}
impl core::fmt::Display for Symbol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

macro_rules! raw {
    ($name:ident { $($f:ident : $t:ty),* $(,)? } = $len:expr) => {
        #[repr(C, packed)]
        #[derive(Clone, Copy)]
        struct $name { $($f: $t),* }
        unsafe impl Pod for $name {}
        const _: () = assert!(core::mem::size_of::<$name>() == $len);
    };
}

raw!(RawSystemEvent { kind: u8, event: u8, ts: i64 } = 10);
raw!(RawCommon { kind: u8, flag: u8, ts: i64, symbol: [u8; 8] } = 18);
raw!(RawSecurityDirectory { kind: u8, flags: u8, ts: i64, symbol: [u8; 8], round_lot_size: u32, adjusted_poc_price: i64, luld_tier: u8 } = 31);
raw!(RawTradingStatus { kind: u8, status: u8, ts: i64, symbol: [u8; 8], reason: [u8; 4] } = 22);
raw!(RawShortSale { kind: u8, status: u8, ts: i64, symbol: [u8; 8], detail: u8 } = 19);
raw!(RawQuote { kind: u8, flags: u8, ts: i64, symbol: [u8; 8], bid_size: u32, bid_price: i64, ask_price: i64, ask_size: u32 } = 42);
raw!(RawTrade { kind: u8, flags: u8, ts: i64, symbol: [u8; 8], size: u32, price: i64, trade_id: i64 } = 38);
raw!(RawOfficialPrice { kind: u8, price_type: u8, ts: i64, symbol: [u8; 8], price: i64 } = 26);
raw!(RawPriceLevel { kind: u8, flags: u8, ts: i64, symbol: [u8; 8], size: u32, price: i64 } = 30);
raw!(RawAuction {
    kind: u8, auction_type: u8, ts: i64, symbol: [u8; 8], paired_shares: u32, reference_price: i64,
    indicative_clearing_price: i64, imbalance_shares: u32, imbalance_side: u8, extension_number: u8,
    scheduled_auction_time: u32, auction_book_clearing_price: i64, collar_reference_price: i64,
    lower_auction_collar: i64, upper_auction_collar: i64
} = 80);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemEvent { pub event: u8, pub timestamp: i64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityDirectory { pub flags: u8, pub timestamp: i64, pub symbol: Symbol, pub round_lot_size: u32, pub adjusted_poc_price: i64, pub luld_tier: u8 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradingStatus { pub status: u8, pub timestamp: i64, pub symbol: Symbol, pub reason: [u8; 4] }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortSalePriceTest { pub status: u8, pub timestamp: i64, pub symbol: Symbol, pub detail: u8 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteUpdate { pub flags: u8, pub timestamp: i64, pub symbol: Symbol, pub bid_size: u32, pub bid_price: i64, pub ask_price: i64, pub ask_size: u32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeReport { pub sale_condition_flags: u8, pub timestamp: i64, pub symbol: Symbol, pub size: u32, pub price: i64, pub trade_id: i64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfficialPrice { pub price_type: u8, pub timestamp: i64, pub symbol: Symbol, pub price: i64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceLevelUpdate { pub buy: bool, pub event_flags: u8, pub timestamp: i64, pub symbol: Symbol, pub size: u32, pub price: i64 }
/// Generic `[type, char, ts, symbol]` shape shared by 'I', 'O', 'E'.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolEvent { pub kind: u8, pub value: u8, pub timestamp: i64, pub symbol: Symbol }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuctionInformation {
    pub auction_type: u8, pub timestamp: i64, pub symbol: Symbol, pub paired_shares: u32, pub reference_price: i64,
    pub indicative_clearing_price: i64, pub imbalance_shares: u32, pub imbalance_side: u8, pub extension_number: u8,
    pub scheduled_auction_time: u32, pub auction_book_clearing_price: i64, pub collar_reference_price: i64,
    pub lower_auction_collar: i64, pub upper_auction_collar: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    SystemEvent(SystemEvent),
    SecurityDirectory(SecurityDirectory),
    TradingStatus(TradingStatus),
    RetailLiquidityIndicator(SymbolEvent),
    OperationalHalt(SymbolEvent),
    ShortSalePriceTest(ShortSalePriceTest),
    QuoteUpdate(QuoteUpdate),
    TradeReport(TradeReport),
    OfficialPrice(OfficialPrice),
    TradeBreak(TradeReport),
    AuctionInformation(AuctionInformation),
    PriceLevelUpdate(PriceLevelUpdate),
    SecurityEvent(SymbolEvent),
}

impl Message {
    /// Message type byte as sent on the wire.
    #[inline]
    pub fn kind(&self) -> u8 {
        match self {
            Message::SystemEvent(_) => b'S',
            Message::SecurityDirectory(_) => b'D',
            Message::TradingStatus(_) => b'H',
            Message::RetailLiquidityIndicator(_) => b'I',
            Message::OperationalHalt(_) => b'O',
            Message::ShortSalePriceTest(_) => b'P',
            Message::QuoteUpdate(_) => b'Q',
            Message::TradeReport(_) => b'T',
            Message::OfficialPrice(_) => b'X',
            Message::TradeBreak(_) => b'B',
            Message::AuctionInformation(_) => b'A',
            Message::PriceLevelUpdate(p) => if p.buy { b'8' } else { b'5' },
            Message::SecurityEvent(_) => b'E',
        }
    }

    /// Matching-engine event timestamp (ns since epoch).
    #[inline]
    pub fn timestamp(&self) -> i64 {
        match self {
            Message::SystemEvent(m) => m.timestamp,
            Message::SecurityDirectory(m) => m.timestamp,
            Message::TradingStatus(m) => m.timestamp,
            Message::RetailLiquidityIndicator(m) | Message::OperationalHalt(m) | Message::SecurityEvent(m) => m.timestamp,
            Message::ShortSalePriceTest(m) => m.timestamp,
            Message::QuoteUpdate(m) => m.timestamp,
            Message::TradeReport(m) | Message::TradeBreak(m) => m.timestamp,
            Message::OfficialPrice(m) => m.timestamp,
            Message::AuctionInformation(m) => m.timestamp,
            Message::PriceLevelUpdate(m) => m.timestamp,
        }
    }

    /// Symbol, if the message carries one (System Event does not).
    #[inline]
    pub fn symbol(&self) -> Option<Symbol> {
        Some(match self {
            Message::SystemEvent(_) => return None,
            Message::SecurityDirectory(m) => m.symbol,
            Message::TradingStatus(m) => m.symbol,
            Message::RetailLiquidityIndicator(m) | Message::OperationalHalt(m) | Message::SecurityEvent(m) => m.symbol,
            Message::ShortSalePriceTest(m) => m.symbol,
            Message::QuoteUpdate(m) => m.symbol,
            Message::TradeReport(m) | Message::TradeBreak(m) => m.symbol,
            Message::OfficialPrice(m) => m.symbol,
            Message::AuctionInformation(m) => m.symbol,
            Message::PriceLevelUpdate(m) => m.symbol,
        })
    }
}

/// Peek the message type byte and event timestamp without full decoding.
/// Works for every DEEP/TOPS message (all share the `[type, x, ts:i64]` prefix).
#[inline]
pub fn peek_kind_ts(body: &[u8]) -> Result<(u8, i64), ParseError> {
    let r: RawSystemEvent = read_pod(body)?;
    Ok((r.kind, i64::from_le(r.ts)))
}

/// Decode one message body (starting at the type byte).
#[inline]
pub fn decode(body: &[u8]) -> Result<Message, ParseError> {
    let kind = *body.first().ok_or(ParseError::Short { need: 1, have: 0 })?;
    Ok(match kind {
        b'S' => {
            let r: RawSystemEvent = read_pod(body)?;
            Message::SystemEvent(SystemEvent { event: r.event, timestamp: i64::from_le(r.ts) })
        }
        b'D' => {
            let r: RawSecurityDirectory = read_pod(body)?;
            Message::SecurityDirectory(SecurityDirectory {
                flags: r.flags, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol),
                round_lot_size: u32::from_le(r.round_lot_size), adjusted_poc_price: i64::from_le(r.adjusted_poc_price), luld_tier: r.luld_tier,
            })
        }
        b'H' => {
            let r: RawTradingStatus = read_pod(body)?;
            Message::TradingStatus(TradingStatus { status: r.status, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol), reason: r.reason })
        }
        b'I' | b'O' | b'E' => {
            let r: RawCommon = read_pod(body)?;
            let e = SymbolEvent { kind, value: r.flag, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol) };
            match kind { b'I' => Message::RetailLiquidityIndicator(e), b'O' => Message::OperationalHalt(e), _ => Message::SecurityEvent(e) }
        }
        b'P' => {
            let r: RawShortSale = read_pod(body)?;
            Message::ShortSalePriceTest(ShortSalePriceTest { status: r.status, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol), detail: r.detail })
        }
        b'Q' => {
            let r: RawQuote = read_pod(body)?;
            Message::QuoteUpdate(QuoteUpdate {
                flags: r.flags, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol),
                bid_size: u32::from_le(r.bid_size), bid_price: i64::from_le(r.bid_price),
                ask_price: i64::from_le(r.ask_price), ask_size: u32::from_le(r.ask_size),
            })
        }
        b'T' | b'B' => {
            let r: RawTrade = read_pod(body)?;
            let t = TradeReport {
                sale_condition_flags: r.flags, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol),
                size: u32::from_le(r.size), price: i64::from_le(r.price), trade_id: i64::from_le(r.trade_id),
            };
            if kind == b'T' { Message::TradeReport(t) } else { Message::TradeBreak(t) }
        }
        b'X' => {
            let r: RawOfficialPrice = read_pod(body)?;
            Message::OfficialPrice(OfficialPrice { price_type: r.price_type, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol), price: i64::from_le(r.price) })
        }
        b'A' => {
            let r: RawAuction = read_pod(body)?;
            Message::AuctionInformation(AuctionInformation {
                auction_type: r.auction_type, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol),
                paired_shares: u32::from_le(r.paired_shares), reference_price: i64::from_le(r.reference_price),
                indicative_clearing_price: i64::from_le(r.indicative_clearing_price), imbalance_shares: u32::from_le(r.imbalance_shares),
                imbalance_side: r.imbalance_side, extension_number: r.extension_number,
                scheduled_auction_time: u32::from_le(r.scheduled_auction_time),
                auction_book_clearing_price: i64::from_le(r.auction_book_clearing_price),
                collar_reference_price: i64::from_le(r.collar_reference_price),
                lower_auction_collar: i64::from_le(r.lower_auction_collar), upper_auction_collar: i64::from_le(r.upper_auction_collar),
            })
        }
        b'8' | b'5' => {
            let r: RawPriceLevel = read_pod(body)?;
            Message::PriceLevelUpdate(PriceLevelUpdate {
                buy: kind == b'8', event_flags: r.flags, timestamp: i64::from_le(r.ts), symbol: Symbol(r.symbol),
                size: u32::from_le(r.size), price: i64::from_le(r.price),
            })
        }
        other => return Err(ParseError::UnknownType(other)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trade_report_roundtrip() {
        // Worked example from the DEEP spec style: T, flags 0, ts, "ZIEXT   ", size 100, price 99.05, trade id 429974
        let mut b = vec![b'T', 0x00];
        b.extend_from_slice(&1_471_980_632_572_715_948i64.to_le_bytes());
        b.extend_from_slice(b"ZIEXT   ");
        b.extend_from_slice(&100u32.to_le_bytes());
        b.extend_from_slice(&990_500i64.to_le_bytes());
        b.extend_from_slice(&429_974i64.to_le_bytes());
        assert_eq!(b.len(), 38);
        let m = decode(&b).unwrap();
        assert_eq!(m, Message::TradeReport(TradeReport { sale_condition_flags: 0, timestamp: 1_471_980_632_572_715_948, symbol: Symbol(*b"ZIEXT   "), size: 100, price: 990_500, trade_id: 429_974 }));
        assert_eq!(m.symbol().unwrap().as_str(), "ZIEXT");
        assert_eq!(m.kind(), b'T');
        assert_eq!(peek_kind_ts(&b).unwrap(), (b'T', 1_471_980_632_572_715_948));
        assert_eq!(decode(&b[..30]).unwrap_err(), ParseError::Short { need: 38, have: 30 });
    }

    #[test]
    fn unknown_type() {
        assert_eq!(decode(b"Zxxxxxxxxxxxxxxxxxxxxxxxxxxx").unwrap_err(), ParseError::UnknownType(b'Z'));
    }
}
