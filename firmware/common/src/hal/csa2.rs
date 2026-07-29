//! Channel Selection Algorithm #2.
//!
//! Core v5.4 Vol 6 Part B §4.5.8.3. Where CSA#1 walks a running index forward by
//! a fixed hop, CSA#2 derives each event's channel from the event counter alone,
//! through a pseudo-random function seeded by the Access Address. A connection
//! uses it when the initiator set the ChSel bit in its CONNECT_IND; periodic
//! advertising trains always use it, keyed on the periodic AA and paEventCounter.

use super::radio::data_ch_freq;

/// The `channelIdentifier` (§4.5.8.3.1): the two halves of the Access Address
/// XORed together. It seeds every event's pseudo-random number, so a follower
/// computes it once per connection / periodic train.
pub const fn chan_id(aa: u32) -> u16 {
    ((aa >> 16) ^ (aa & 0xFFFF)) as u16
}

/// §4.5.8.3.2 permutation: the bits of each octet reversed in place, with the
/// two octets left in their original order.
const fn perm(v: u16) -> u16 {
    ((((v >> 8) as u8).reverse_bits() as u16) << 8) | ((v as u8).reverse_bits() as u16)
}

/// §4.5.8.3.2 MAM: multiply by 17, add, keep the low 16 bits.
const fn mam(a: u16, b: u16) -> u16 {
    a.wrapping_mul(17).wrapping_add(b)
}

/// The event's pseudo-random number `prn_e` (§4.5.8.3.3): counter XOR channel
/// identifier, three rounds of permute-then-MAM, then one more XOR.
const fn prn_e(counter: u16, chan_id: u16) -> u16 {
    let mut prn = counter ^ chan_id;
    let mut round = 0;
    while round < 3 {
        prn = mam(perm(prn), chan_id);
        round += 1;
    }
    prn ^ chan_id
}

/// Channel Selection Algorithm #2: the data channel index for event `counter`
/// (§4.5.8.3.4).
///
/// `prn_e mod 37` picks an unmapped index. When that index is in the map it is
/// the answer; otherwise `prn_e` scaled by the used-channel count picks a
/// position in the map, which spreads a sparse map's events across all of its
/// channels rather than concentrating them where the modulo happens to land.
///
/// A pure function of `(counter, chan_id, chm)`: a CSA#2 link needs no per-event
/// channel state in the follower, and skipping events costs only an advance of
/// the counter.
pub const fn index(counter: u16, chan_id: u16, chm: &[u8; 5]) -> Option<u8> {
    let prn_e = prn_e(counter, chan_id);
    let unmapped = (prn_e % 37) as u8;
    if chm[(unmapped / 8) as usize] & (1 << (unmapped % 8)) != 0 {
        return Some(unmapped);
    }
    let mut count: u32 = 0;
    let mut b = 0;
    while b < 5 {
        count += chm[b].count_ones();
        b += 1;
    }
    if count == 0 {
        return None;
    }
    let target = ((count * prn_e as u32) >> 16) as u8;
    let mut k = 0u8;
    let mut idx = 0u8;
    while idx < 37 {
        if chm[(idx / 8) as usize] & (1 << (idx % 8)) != 0 {
            if k == target {
                return Some(idx);
            }
            k += 1;
        }
        idx += 1;
    }
    None
}

/// [`index`] resolved to the `(channel index, nRF frequency)` pair the radio needs.
pub fn channel(counter: u16, chan_id: u16, chm: &[u8; 5]) -> Option<(u8, u8)> {
    let ch = index(counter, chan_id, chm)?;
    data_ch_freq(ch).map(|f| (ch, f))
}

/// The Core spec's own CSA#2 sample data (Vol 6 Part C §3), checked at compile
/// time: access address `0x8E89BED6` → channelIdentifier `0x305F`, run against
/// the full 37-channel map and a 9-channel map that exercises the remap branch.
///
/// This is the one part of channel selection whose correctness is arithmetic
/// rather than RF, so it is pinned here instead of on the bench. A wrong constant
/// would otherwise surface only as a follower sitting on the wrong channel, which
/// looks exactly like an anchor error.
const _: () = {
    const fn is(got: Option<u8>, want: u8) -> bool {
        match got {
            Some(ch) => ch == want,
            None => false,
        }
    }
    const ALL_37: [u8; 5] = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F];
    const NINE: [u8; 5] = [0x00, 0x06, 0xE0, 0x00, 0x1E];
    assert!(chan_id(0x8E89_BED6) == 0x305F);
    assert!(is(index(0, 0x305F, &ALL_37), 25));
    assert!(is(index(1, 0x305F, &ALL_37), 20));
    assert!(is(index(2, 0x305F, &ALL_37), 6));
    assert!(is(index(3, 0x305F, &ALL_37), 21));
    assert!(is(index(6, 0x305F, &NINE), 23));
    assert!(is(index(7, 0x305F, &NINE), 9));
    assert!(is(index(8, 0x305F, &NINE), 34));
};
