pub struct IceKey {
    size: usize,
    rounds: usize,
    ice_sbox: [[u64; 4]; 1024],
    keysched: Vec<[u64; 3]>
}

impl IceKey {
    const ICE_SMOD: [[u32; 4]; 4] = [
        [333, 313, 505, 369],
        [379, 375, 319, 391],
        [361, 445, 451, 397],
        [397, 425, 395, 505]
    ];

    const ICE_SXOR: [[u32; 4]; 4] = [
        [0x83, 0x85, 0x9b, 0xcd],
        [0xcc, 0xa7, 0xad, 0x41],
        [0x4b, 0x2e, 0xd4, 0x33],
        [0xea, 0xcb, 0x2e, 0x04]
    ];

    const ICE_PBOX: [u64; 32] = [
        0x00000001, 0x00000080, 0x00000400, 0x00002000,
		0x00080000, 0x00200000, 0x01000000, 0x40000000,
		0x00000008, 0x00000020, 0x00000100, 0x00004000,
		0x00010000, 0x00800000, 0x04000000, 0x20000000,
		0x00000004, 0x00000010, 0x00000200, 0x00008000,
		0x00020000, 0x00400000, 0x08000000, 0x10000000,
		0x00000002, 0x00000040, 0x00000800, 0x00001000,
		0x00040000, 0x00100000, 0x02000000, 0x80000000
    ];

    const ICE_KEYROT: [u32; 16] = [
        0, 1, 2, 3, 2, 1, 3, 0,
		1, 3, 2, 0, 3, 1, 0, 2
    ];

    pub fn new(length: usize) -> Self {
        let size: usize;
        let rounds: usize;

        if length < 1 {
            size = 1;
            rounds = 8;
        } else {
            size = length;
            rounds = length * 16;
        }

        let mut keysched: Vec<[u64; 3]> = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            keysched.push([0; 3]);
        }

        Self {
            size,
            rounds,
            ice_sbox: Self::init_sbox(),
            keysched
        }
    }

    pub fn set(&mut self, key: Vec<u8>) {
        let mut kb: [u16; 4] = [0; 4];

        if self.rounds == 8 {
            for i in 0..4 {
                kb[3 - i] = ((key[i*2] as u16) << 8) | key[i*2 + 1] as u16;
            }

            _ = self.schedule_build(kb, 0, 0);
            return;
        }

        for i in 0..self.size {
            for j in 0..4 {
                kb[3 - j] = ((key[i * 8 + j * 2] as u16 & 0xFF) << 8) | (key[i * 8 + j * 2 + 1] as u16 & 0xFF);
            }

            kb = self.schedule_build(kb, i*8, 0);
            _ = self.schedule_build(kb, self.rounds - 8 - i*8, 8);
        }
    }

    pub fn decrypt_all(&self, mut ctext: Vec<u8>) -> Vec<u8> {
        let mut ptext: Vec<u8> = Vec::new();

        let index = 8 - (ctext.len() % 8);
        for _ in 0..index {
            ctext.push(0);
        }

        for chunk in ctext.chunks_exact(8) {
            for byte in self.decrypt(Vec::from(chunk)) {
                ptext.push(byte);
            }
        }

        ptext
    }

    pub fn encrypt_all(&self, mut ptext: Vec<u8>) -> Vec<u8> {
        let mut ctext: Vec<u8> = Vec::new();

        let index = 8 - (ptext.len() % 8);
        for _ in 0..index {
            ptext.push(0);
        }

        for chunk in ptext.chunks_exact(8) {
            for byte in self.encrypt(Vec::from(chunk)) {
                ctext.push(byte);
            }
        }

        ctext
    }

    pub fn decrypt(&self, ctext: Vec<u8>) -> Vec<u8> {
        let mut ptext: [u8; 8] = [0; 8];
        let mut i: usize = self.rounds;

        let mut l = (ctext[0] as u64) << 24 | (ctext[1] as u64) << 16 | (ctext[2] as u64) << 8 | ctext[3] as u64;
        let mut r: u64 = (ctext[4] as u64) << 24 | (ctext[5] as u64) << 16 | (ctext[6] as u64) << 8 | ctext[7] as u64;

        while i > 0 {
            l ^= Self::ice_f(&self, r, self.keysched[i-1]);
            r ^= Self::ice_f(&self, l, self.keysched[i-2]);

            i -= 2;
        }

        for j in 0..4 {
            ptext[3 - j] = (r & 0xFF) as u8;
            ptext[7 - j] = (l & 0xFF) as u8;

            r >>= 8;
            l >>= 8;
        }

        ptext.to_vec()
    }

    pub fn encrypt(&self, ptext: Vec<u8>) -> Vec<u8> {
        let mut ctext: [u8; 8] = [0; 8];
        let mut i: usize = 0;

        let mut l: u64 = (ptext[0] as u64) << 24 | (ptext[1] as u64) << 16 | (ptext[2] as u64) << 8 | ptext[3] as u64;
        let mut r: u64 = (ptext[4] as u64) << 24 | (ptext[5] as u64) << 16 | (ptext[6] as u64) << 8 | ptext[7] as u64;

        while i < self.rounds {
            l ^= Self::ice_f(&self, r, self.keysched[i]);
            r ^= Self::ice_f(&self, l, self.keysched[i+1]);

            i += 2;
        }

        for j in 0..4 {
            ctext[3 - j] = (r & 0xFF) as u8;
            ctext[7 - j] = (l & 0xFF) as u8;

            r >>= 8;
            l >>= 8;
        }

        ctext.to_vec()
    }

    pub fn rounds(&self) -> usize {
        self.rounds.clone()
    }

    pub fn size(&self) -> usize {
        self.size.clone()
    }

    fn init_sbox() -> [[u64; 4]; 1024] {
        let mut sbox: [[u64; 4]; 1024] = [[0; 4]; 1024];

        for i in 0..1024 {
            let col: u32 = (i >> 1) & 0xFF;
            let row: usize = (((i & 0x1) | ((i & 0x200) >> 8))) as usize;
            let mut x: u64;

            x = Self::gf_exp7(col ^ Self::ICE_SXOR[0][row], Self::ICE_SMOD[0][row]) << 24;
            sbox[i as usize][0] = Self::ice_perm32(x);

            x = Self::gf_exp7(col ^ Self::ICE_SXOR[1][row], Self::ICE_SMOD[1][row]) << 16;
            sbox[i as usize][1] = Self::ice_perm32(x);

            x = Self::gf_exp7(col ^ Self::ICE_SXOR[2][row], Self::ICE_SMOD[2][row]) << 8;
            sbox[i as usize][2] = Self::ice_perm32(x);

            x = Self::gf_exp7(col ^ Self::ICE_SXOR[3][row], Self::ICE_SMOD[3][row]);
            sbox[i as usize][3] = Self::ice_perm32(x);
        }

        sbox
    }

    fn ice_perm32(mut x: u64) -> u64 {
        let mut res: u64 = 0;
        let mut i: usize = 0;

        while x != 0 {
            if x & 1 == 1 {
                res |= Self::ICE_PBOX[i];
            }
            
            i += 1;
            x >>= 1;
        }

        res
    }

    fn gf_mult(mut a: u32, mut b: u32, m: u32) -> u32 {
        let mut res: u32 = 0;

        while b != 0 {
            if b & 1 == 1 {
                res ^= a;
            }

            a <<= 1;
            b >>= 1;

            if a >= 256 {
                a ^= m;
            }
        }

        res
    }

    fn gf_exp7(b: u32, m: u32) -> u64 {
        let mut x: u32;

        if b == 0 {
            return 0;
        }

        x = Self::gf_mult(b, b, m);
        x = Self::gf_mult(b, x, m);
        x = Self::gf_mult(x, x, m);

        Self::gf_mult(b, x, m).into()
    }

    fn ice_f(&self, p: u64, sk: [u64; 3]) -> u64 {
        let tl: u64 = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00);
        let tr: u64 = (p & 0x3FF) | ((p << 2) & 0xFFC00);
        let mut al: u64;
        let mut ar: u64;

        al = sk[2] & (tl ^ tr);
        ar = al ^ tr;
        al ^= tl;

        al ^= sk[0];
        ar ^= sk[1];

        self.ice_sbox[al as usize >> 10][0] | self.ice_sbox[al as usize & 0x3FF][1] | self.ice_sbox[ar as usize >> 10][2] | self.ice_sbox[ar as usize & 0x3FF][3]
    }

    fn schedule_build(&mut self, mut kb: [u16; 4], n: usize, l: usize) -> [u16; 4] {
        for i in 0..8 {
            let kr = Self::ICE_KEYROT[i + l];
            let mut subkey: [u64; 3] = self.keysched[n + i];

            for j in 0..3 {
                subkey[j] = 0;
            }

            for j in 0..15 {
                let curr_sk: usize = j % 3;

                for k in 0..4 {
                    let curr_kb = kb[((kr + k) & 3) as usize];
                    let bit: u16 = curr_kb & 1;

                    subkey[curr_sk] = (subkey[curr_sk] << 1) | bit as u64;
                    kb[((kr + k) & 3) as usize] = (curr_kb >> 1) | ((bit ^ 1) << 15);
                }
            }

            self.keysched[n + i] = subkey;
        }

        kb
    }
}