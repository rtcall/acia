use anyhow::{bail, Result};
use lut::*;
use std::fs::File;
use std::io::{stdout, BufReader, Read, Write};

mod lut;

pub enum Cipher {
    Ecb128,
    Ecb192,
    Ecb256,
}

struct AesCipher {
    key: Vec<u32>,
}

type Cols = (u8, u8, u8, u8);

macro_rules! rotl {
    ($x: expr, $n: expr) => {
        $x >> (32 - 8 * $n) | $x << (8 * $n)
    };
}

macro_rules! rotr {
    ($x: expr, $n: expr) => {
        $x << (32 - 8 * $n) | $x >> (8 * $n)
    };
}

impl AesCipher {
    fn sub_sbox(n: u32, lut: &[u8]) -> u32 {
        (lut[(n >> 24) as usize] as u32) << 24
            | (lut[(n >> 16 & 0xff) as usize] as u32) << 16
            | (lut[(n >> 8 & 0xff) as usize] as u32) << 8
            | lut[(n & 0xff) as usize] as u32
    }

    fn expand_key(key: Vec<u8>, cipher: Cipher) -> Vec<u32> {
        let mut exp = Vec::new();
        let (nwords, rounds) = match cipher {
            Cipher::Ecb128 => (4, 10),
            Cipher::Ecb192 => (6, 12),
            Cipher::Ecb256 => (8, 14),
        };

        exp.resize((rounds + 1) * 4, 0);

        for i in 0..nwords {
            exp[i] = (key[i * 4] as u32) << 24
                | (key[i * 4 + 1] as u32) << 16
                | (key[i * 4 + 2] as u32) << 8
                | (key[i * 4 + 3] as u32);
        }

        for i in (nwords..4 * (rounds + 1)).step_by(nwords) {
            exp[i] = exp[i - 1];
            exp[i] = rotl!(exp[i], 1);
            exp[i] = Self::sub_sbox(exp[i], &SBOX);
            exp[i] ^= (RCON[i / nwords - 1] as u32) << 24;
            exp[i] ^= exp[i - nwords];

            for j in 1..=3 {
                exp[i + j] = exp[i + j - 1] ^ exp[i + j - nwords];
            }
        }

        for i in (0..exp.len()).step_by(4) {
            let e = &mut exp[i..i + 4];
            let mut t: [u32; 4] = [0; 4];

            for (j, k) in e.iter().enumerate() {
                t[0] |= (k >> 24) << (8 * (3 - j));
                t[1] |= (k >> 16 & 0xff) << (8 * (3 - j));
                t[2] |= (k >> 8 & 0xff) << (8 * (3 - j));
                t[3] |= (k & 0xff) << (8 * (3 - j));
            }

            e.copy_from_slice(&t);
        }

        exp
    }

    // state array layout
    // 0 4 8  12
    // 1 5 9  13
    // 2 6 10 14
    // 3 7 11 15

    fn to_state(src: &[u8; 16], dst: &mut [u32; 4]) {
        for (i, c) in dst.iter_mut().enumerate() {
            *c = (src[i] as u32) << 24
                | (src[i + 4] as u32) << 16
                | (src[i + 8] as u32) << 8
                | src[i + 12] as u32;
        }
    }

    fn from_state(src: &[u32; 4], dst: &mut [u8; 16]) {
        for (i, c) in src.iter().enumerate() {
            dst[i] = (*c >> 24) as u8;
            dst[i + 4] = (*c >> 16) as u8;
            dst[i + 8] = (*c >> 8) as u8;
            dst[i + 12] = *c as u8;
        }
    }

    fn rounds(&self) -> usize {
        self.key.len() / 4 - 2
    }

    fn add_round_key(&self, state: &mut [u32], idx: usize) {
        let key = &self.key[idx..idx + 4];
        state.iter_mut().enumerate().for_each(|(i, c)| *c ^= key[i]);
    }

    fn sub_bytes(&self, state: &mut [u32; 4], lut: &[u8]) {
        for i in state.iter_mut() {
            *i = Self::sub_sbox(*i, lut);
        }
    }

    fn shift_rows(&self, state: &mut [u32; 4]) {
        for (i, row) in state.iter_mut().enumerate().skip(1) {
            *row = rotl!(*row, i as u32);
        }
    }

    fn inv_shift_rows(&self, state: &mut [u32; 4]) {
        for (i, row) in state.iter_mut().enumerate().skip(1) {
            *row = rotr!(*row, i as u32);
        }
    }

    fn apply_cols(&self, state: &mut [u32; 4], func: fn(Cols) -> Cols) {
        for i in 0..4 {
            let a0 = ((state[0] >> ((3 - i) * 8)) & 0xff) as u8;
            let a1 = ((state[1] >> ((3 - i) * 8)) & 0xff) as u8;
            let a2 = ((state[2] >> ((3 - i) * 8)) & 0xff) as u8;
            let a3 = ((state[3] >> ((3 - i) * 8)) & 0xff) as u8;

            let (r0, r1, r2, r3) = func((a0, a1, a2, a3));

            let mut mask: u32 = 0xff << ((3 - i) * 8);
            mask = !mask;

            state[0] = (state[0] & mask) | ((r0 as u32) << ((3 - i) * 8));
            state[1] = (state[1] & mask) | ((r1 as u32) << ((3 - i) * 8));
            state[2] = (state[2] & mask) | ((r2 as u32) << ((3 - i) * 8));
            state[3] = (state[3] & mask) | ((r3 as u32) << ((3 - i) * 8));
        }
    }

    fn mix_cols(&self, state: &mut [u32; 4]) {
        self.apply_cols(state, |a| {
            (
                GMUL_2[a.0 as usize] ^ GMUL_3[a.1 as usize] ^ a.2 ^ a.3,
                a.0 ^ GMUL_2[a.1 as usize] ^ GMUL_3[a.2 as usize] ^ a.3,
                a.0 ^ a.1 ^ GMUL_2[a.2 as usize] ^ GMUL_3[a.3 as usize],
                GMUL_3[a.0 as usize] ^ a.1 ^ a.2 ^ GMUL_2[a.3 as usize],
            )
        });
    }

    fn inv_mix_cols(&self, state: &mut [u32; 4]) {
        self.apply_cols(state, |a| {
            (
                GMUL_14[a.0 as usize]
                    ^ GMUL_11[a.1 as usize]
                    ^ GMUL_13[a.2 as usize]
                    ^ GMUL_9[a.3 as usize],
                GMUL_9[a.0 as usize]
                    ^ GMUL_14[a.1 as usize]
                    ^ GMUL_11[a.2 as usize]
                    ^ GMUL_13[a.3 as usize],
                GMUL_13[a.0 as usize]
                    ^ GMUL_9[a.1 as usize]
                    ^ GMUL_14[a.2 as usize]
                    ^ GMUL_11[a.3 as usize],
                GMUL_11[a.0 as usize]
                    ^ GMUL_13[a.1 as usize]
                    ^ GMUL_9[a.2 as usize]
                    ^ GMUL_14[a.3 as usize],
            )
        });
    }

    fn encrypt(&self, src: &[u8; 16], dst: &mut [u8; 16]) {
        let mut state: [u32; 4] = [0; 4];
        Self::to_state(src, &mut state);

        let mut idx = 0;
        self.add_round_key(&mut state, idx);
        idx += 4;

        for _ in 0..self.rounds() {
            self.sub_bytes(&mut state, &SBOX);
            self.shift_rows(&mut state);
            self.mix_cols(&mut state);
            self.add_round_key(&mut state, idx);
            idx += 4;
        }

        self.sub_bytes(&mut state, &SBOX);
        self.shift_rows(&mut state);
        self.add_round_key(&mut state, idx);

        Self::from_state(&state, dst);
    }

    fn decrypt(&self, src: &[u8; 16], dst: &mut [u8; 16]) {
        let mut state: [u32; 4] = [0; 4];
        Self::to_state(src, &mut state);

        let mut idx = self.key.len() - 4;
        self.add_round_key(&mut state, idx);
        idx -= 4;

        for _ in 0..self.rounds() {
            self.inv_shift_rows(&mut state);
            self.sub_bytes(&mut state, &SBOX_INV);
            self.add_round_key(&mut state, idx);
            idx -= 4;
            self.inv_mix_cols(&mut state);
        }

        self.inv_shift_rows(&mut state);
        self.sub_bytes(&mut state, &SBOX_INV);
        self.add_round_key(&mut state, idx);

        Self::from_state(&state, dst);
    }

    fn new(key: Vec<u8>, cipher: Cipher) -> Self {
        Self {
            key: Self::expand_key(key, cipher),
        }
    }

    fn from_str(key: &str, cipher: Cipher) -> Self {
        Self::new(key.as_bytes().to_vec(), cipher)
    }
}

pub fn run(key: String, path: String, cipher: u32, decrypt: bool) -> Result<()> {
    let bcipher = match cipher {
        128 => Cipher::Ecb128,
        192 => Cipher::Ecb192,
        256 => Cipher::Ecb256,
        _ => bail!("unknown cipher length"),
    };

    if key.len() != (cipher / 8) as usize {
        bail!("bad key (must be {} bytes)", cipher / 8);
    }

    let f = File::open(path)?;
    let aes = AesCipher::from_str(&key, bcipher);

    let mut buf: [u8; 16] = [0; 16];
    let mut reader = BufReader::new(f);
    while reader.read_exact(&mut buf).is_ok() {
        let mut output: [u8; 16] = [0; 16];

        if decrypt {
            aes.decrypt(&buf, &mut output);
        } else {
            aes.encrypt(&buf, &mut output);
        }

        stdout().write_all(&output)?;
    }

    Ok(())
}
