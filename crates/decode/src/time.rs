//! DIS timestamp encoding.
//!
//! The 32-bit DIS timestamp counts time past the current hour in units of
//! 3600 s / 2^31 (about 1.676 µs) in the upper 31 bits. The least significant
//! bit is 1 for an absolute timestamp (synchronised clocks) and 0 for a
//! relative one.

/// Number of timestamp units in one hour.
const UNITS_PER_HOUR: f64 = 2_147_483_648.0; // 2^31

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct DisTimestamp(pub u32);

impl DisTimestamp {
    /// Build a timestamp from seconds past the hour (wrapped into 0..3600).
    pub fn from_seconds_past_hour(seconds: f64, absolute: bool) -> Self {
        let s = seconds.rem_euclid(3600.0);
        let units = ((s / 3600.0) * UNITS_PER_HOUR) as u64;
        let units = units.min((1u64 << 31) - 1) as u32;
        DisTimestamp((units << 1) | absolute as u32)
    }

    pub fn is_absolute(self) -> bool {
        self.0 & 1 == 1
    }

    /// Seconds past the hour this timestamp represents.
    pub fn seconds_past_hour(self) -> f64 {
        (self.0 >> 1) as f64 / UNITS_PER_HOUR * 3600.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_within_resolution() {
        for s in [0.0, 1.5, 59.25, 1799.999, 3599.9] {
            let t = DisTimestamp::from_seconds_past_hour(s, true);
            assert!(t.is_absolute());
            assert!((t.seconds_past_hour() - s).abs() < 1e-5, "{s}");
        }
        let rel = DisTimestamp::from_seconds_past_hour(10.0, false);
        assert!(!rel.is_absolute());
    }

    #[test]
    fn wraps_past_the_hour() {
        let t = DisTimestamp::from_seconds_past_hour(3610.0, false);
        assert!((t.seconds_past_hour() - 10.0).abs() < 1e-5);
    }
}
