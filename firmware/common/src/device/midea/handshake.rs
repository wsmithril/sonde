//! Midea control-channel handshake state machine, ported from midea-ble-go
//! (`internal/proto/handshake.go`). Builds the outbound c1/c2/c3/business frames
//! and parses inbound frames; it holds no I/O or timing — a driver over the GATT
//! connection (write to `0xFFA1`, notify from `0xFFA2`) owns those.
//!
//! Flow: **c1** (send openId, rootKey-encrypted) → device **c1** ack → **c2**
//! (empty, rootKey) → device **c2** carries its P-256 public key → derive the
//! sessionKey, send **c3** (our public key + sessionKey-encrypted advertisData,
//! rootKey-wrapped) → device **c3** result≠0 means the link is up → **biz** (c4,
//! sessionKey-encrypted) carries appliance commands.
//!
//! RNG: nonces, the ECDH keypair and the initial sequence numbers must come from
//! a cryptographically-secure source (the nRF hardware RNG / CC310 TRNG), not the
//! LCG in [`crate::Rng`]. The methods are generic over `rand_core` so the caller
//! supplies one.
#![allow(dead_code)]

use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};

use super::crypto;
use super::frame::{self, Frame};

/// One byte of randomness in `1..=255` (sequence numbers never use 0).
fn seq_seed<R: RngCore>(rng: &mut R) -> u8 {
    let mut b = [0u8; 1];
    rng.fill_bytes(&mut b);
    if b[0] == 0 { 1 } else { b[0] }
}

fn nonce<R: RngCore>(rng: &mut R) -> [u8; 8] {
    let mut n = [0u8; 8];
    rng.fill_bytes(&mut n);
    n
}

/// A parsed inbound frame.
pub enum Recv {
    /// Connection-layer get-version reply.
    T1,
    /// c1 acknowledgement with its result byte.
    C1(u8),
    /// c2 carrying the device's P-256 public key (`X‖Y`).
    C2([u8; 64]),
    /// c3 result byte (non-zero = handshake accepted).
    C3(u8),
    /// A decrypted business (c4) body.
    Biz(Frame),
    /// Short error frame (`ff04` security failure / `ff05` counter error).
    SecError,
    /// Anything else.
    Unknown,
}

pub struct Handshake {
    advertis_data: heapless::Vec<u8, 15>,
    open_id6: [u8; 6],
    root_key: [u8; 16],
    session_key: Option<[u8; 16]>,
    my_pub64: Option<[u8; 64]>,
    conn_seq: u8,
    sec_seq: u8,
}

impl Handshake {
    /// Initialise from the advertised `advertisData` (0xAC‖SN8‖MAC_rev) and the
    /// 6-byte client open-id, deriving the rootKey. Sequence numbers seed from
    /// the RNG.
    pub fn new<R: RngCore>(advertis_data: &[u8], open_id6: [u8; 6], rng: &mut R) -> Option<Self> {
        if advertis_data.len() < 11 {
            return None;
        }
        let mut ad = heapless::Vec::new();
        ad.extend_from_slice(advertis_data).ok()?;
        Some(Self {
            root_key: crypto::derive_root_key(advertis_data),
            advertis_data: ad,
            open_id6,
            session_key: None,
            my_pub64: None,
            conn_seq: seq_seed(rng),
            sec_seq: seq_seed(rng),
        })
    }

    fn next_conn_seq(&mut self) -> u8 {
        self.conn_seq = self.conn_seq.wrapping_add(1);
        if self.conn_seq == 0 {
            self.conn_seq = 1;
        }
        self.conn_seq
    }

    fn next_sec_seq(&mut self) -> u8 {
        self.sec_seq = self.sec_seq.wrapping_add(1);
        if self.sec_seq == 0 {
            self.sec_seq = 1;
        }
        self.sec_seq
    }

    /// `true` once c2 has been processed and the sessionKey is known.
    pub fn ready(&self) -> bool {
        self.session_key.is_some()
    }

    /// conn t1 + fixed get-version body.
    pub fn build_get_version(&mut self) -> Option<Frame> {
        frame::encode_conn(frame::T1, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0], self.next_conn_seq())
    }

    /// c1: body = openId6, rootKey-encrypted, conn type t2.
    pub fn build_c1<R: RngCore>(&mut self, rng: &mut R) -> Option<Frame> {
        let open = self.open_id6;
        self.wrap_root(frame::C1, &open, rng)
    }

    /// c2: empty body, rootKey-encrypted.
    pub fn build_c2<R: RngCore>(&mut self, rng: &mut R) -> Option<Frame> {
        self.wrap_root(frame::C2, &[], rng)
    }

    /// After receiving the device's c2 public key, generate our keypair and
    /// derive the sessionKey. Must precede [`Self::build_c3`].
    pub fn complete_c2<R: RngCore + CryptoRng>(
        &mut self,
        peer_pub64: &[u8; 64],
        rng: &mut R,
    ) -> Option<()> {
        let (my_priv, my_pub) = crypto::create_keypair(rng);
        self.session_key = Some(crypto::derive_session_key(&my_priv, peer_pub64)?);
        self.my_pub64 = Some(my_pub);
        Some(())
    }

    /// c3: body = ourPub(64) ‖ CipherMsg(sessionKey, advertisData), rootKey-wrapped.
    pub fn build_c3<R: RngCore>(&mut self, rng: &mut R) -> Option<Frame> {
        let sk = self.session_key?;
        let pub64 = self.my_pub64?;
        let n = nonce(rng);
        let inner = crypto::cipher_msg(&sk, &self.advertis_data, &n)?;
        let mut body: Frame = Frame::new();
        body.extend_from_slice(&pub64).ok()?;
        body.extend_from_slice(&inner).ok()?;
        self.wrap_root(frame::C3, &body, rng)
    }

    /// c4 business frame: `EncodeBiz` → sessionKey-encrypted → conn type t3.
    pub fn build_biz<R: RngCore>(
        &mut self,
        biz_type: u8,
        biz_body: &[u8],
        rng: &mut R,
    ) -> Option<Frame> {
        let sk = self.session_key?;
        let biz = frame::encode_biz(biz_type, biz_body)?;
        let sec = frame::encode_security(frame::C4, &biz, self.next_sec_seq())?;
        let enc = crypto::cipher_msg(&sk, &sec, &nonce(rng))?;
        frame::encode_conn(frame::T3, &enc, self.next_conn_seq())
    }

    /// Build a rootKey-encrypted security frame and wrap it in a conn t2 frame.
    fn wrap_root<R: RngCore>(&mut self, cmd: u8, body: &[u8], rng: &mut R) -> Option<Frame> {
        let sec = frame::encode_security(cmd, body, self.next_sec_seq())?;
        let enc = crypto::cipher_msg(&self.root_key, &sec, &nonce(rng))?;
        frame::encode_conn(frame::T2, &enc, self.next_conn_seq())
    }

    /// Parse one complete inbound conn frame.
    pub fn on_recv(&self, raw: &[u8]) -> Option<Recv> {
        let (typ, _seq, body) = frame::decode_conn(raw)?;
        if typ == frame::T1 {
            return Some(Recv::T1);
        }
        if (typ == frame::T2 || typ == frame::T3) && body.len() < 16 {
            return Some(Recv::SecError);
        }
        let inner = match typ {
            frame::T2 => crypto::decipher_msg(&self.root_key, body)?,
            frame::T3 => crypto::decipher_msg(self.session_key.as_ref()?, body)?,
            _ => return Some(Recv::Unknown),
        };
        let (cmd, _sseq, sbody) = frame::decode_security(&inner)?;
        Some(match cmd {
            frame::C1 => Recv::C1(sbody.first().copied().unwrap_or(0)),
            frame::C2 if sbody.len() >= 64 => {
                let mut p = [0u8; 64];
                p.copy_from_slice(&sbody[..64]);
                Recv::C2(p)
            }
            frame::C3 => Recv::C3(sbody.first().copied().unwrap_or(0)),
            frame::C4 => {
                let b = frame::decode_biz(sbody)?;
                let mut f = Frame::new();
                f.extend_from_slice(b).ok()?;
                Recv::Biz(f)
            }
            _ => Recv::Unknown,
        })
    }
}
