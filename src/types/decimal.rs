//! Exact-decimal monetary arithmetic newtype (`ExactDecimal`) with zero floating-point usage.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Sub};
use std::str::FromStr;

/// Exact fixed-point decimal money amount (never uses binary floating point).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct ExactDecimal(Decimal);

impl ExactDecimal {
    /// Constant zero amount.
    pub const ZERO: Self = Self(Decimal::ZERO);

    /// Construct from a `rust_decimal::Decimal`.
    pub fn from_decimal(d: Decimal) -> Self {
        Self(d.normalize())
    }

    /// Parse from decimal string.
    pub fn parse_str(s: &str) -> Result<Self, String> {
        Decimal::from_str(s.trim())
            .map(|d| Self(d.normalize()))
            .map_err(|e| e.to_string())
    }

    /// Construct from integer cents/micro-units (`value * 10^-scale`).
    pub fn from_i64_with_scale(num: i64, scale: u32) -> Self {
        Self(Decimal::new(num, scale).normalize())
    }

    /// Borrow underlying `Decimal`.
    pub fn inner(self) -> Decimal {
        self.0
    }

    /// True if strictly positive.
    pub fn is_positive(self) -> bool {
        self.0 > Decimal::ZERO
    }

    /// Checked subtraction returning `None` if result would be negative or overflow.
    pub fn checked_sub_nonneg(self, rhs: Self) -> Option<Self> {
        let res = self.0.checked_sub(rhs.0)?;
        if res < Decimal::ZERO {
            None
        } else {
            Some(Self(res.normalize()))
        }
    }

    /// Checked addition.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(|d| Self(d.normalize()))
    }

    /// Checked multiplication.
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        self.0.checked_mul(rhs.0).map(|d| Self(d.normalize()))
    }

    /// Checked division.
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        if rhs.0.is_zero() {
            return None;
        }
        self.0.checked_div(rhs.0).map(|d| Self(d.normalize()))
    }

    /// Compute exact token cost in USD: `(total_tokens * usd_per_million) / 1_000_000`.
    pub fn token_cost_usd(total_tokens: u64, usd_per_million: Self) -> Self {
        let tokens = Decimal::from(total_tokens);
        let million = Decimal::from(1_000_000u64);
        let raw = tokens
            .checked_mul(usd_per_million.0)
            .and_then(|num| num.checked_div(million))
            .unwrap_or(Decimal::ZERO);
        Self(raw.round_dp(6).normalize())
    }
}

impl Add for ExactDecimal {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0 + rhs.0).normalize())
    }
}

impl Sub for ExactDecimal {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self((self.0 - rhs.0).normalize())
    }
}

impl fmt::Display for ExactDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.normalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_decimal_no_negative_balance() {
        let a = ExactDecimal::parse_str("10.00").unwrap();
        let b = ExactDecimal::parse_str("10.01").unwrap();
        assert!(a.checked_sub_nonneg(b).is_none());
        let c = ExactDecimal::parse_str("3.25").unwrap();
        assert_eq!(a.checked_sub_nonneg(c).unwrap().to_string(), "6.75");
    }

    #[test]
    fn exact_decimal_token_cost_usd() {
        let rate = ExactDecimal::from_i64_with_scale(25, 2); // $0.25 / 1M tokens
        let cost = ExactDecimal::token_cost_usd(1_000_000, rate);
        assert_eq!(cost.to_string(), "0.25");
        let small = ExactDecimal::token_cost_usd(1_000, rate);
        assert_eq!(small.to_string(), "0.00025");
    }
}
