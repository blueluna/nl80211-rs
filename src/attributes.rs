include!(concat!(env!("OUT_DIR"), "/attributes.rs"));


bitflags! {
    pub struct RegulatoryFlags: u32 {
        const NO_OFDM       = 1 << 0;
        const NO_CCK        = 1 << 1;
        const NO_INDOOR     = 1 << 2;
        const NO_OUTDOOR    = 1 << 3;
        const DFS           = 1 << 4;
        const PTP_ONLY      = 1 << 5;
        const PTMP_ONLY     = 1 << 6;
        const NO_IR         = 1 << 7;
        const NO_IBSS       = 1 << 8;
        const AUTO_BW       = 1 << 11;
        const IR_CONCURRENT = 1 << 12;
        const HT40MINUS     = 1 << 13;
        const HT40PLUS      = 1 << 14;
        const NO_80MHZ      = 1 << 15;
        const NO_160MHZ     = 1 << 16;
    }
}