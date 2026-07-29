//! Per-device protocol logic.
//!
//! Where a decoder module under [`crate::decoder`] recognises a vendor frame and
//! extracts fields, a `device` submodule goes deeper into one product family —
//! its GATT control channel, framing, crypto and command set — the parts that a
//! generic advertising/GATT decoder does not cover.

pub mod midea;
