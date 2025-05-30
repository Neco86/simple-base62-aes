const AES = (() => {
    const SBOX = [
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171,
        118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164,
        114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113,
        216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39,
        178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227,
        47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76,
        88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60,
        159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16,
        255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61,
        100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20,
        222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98,
        145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244,
        234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221,
        116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53,
        87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155,
        30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104,
        65, 153, 45, 15, 176, 84, 187, 22,
    ];

    const INV_SBOX = (() => {
        let inv = new Array(256);
        for (let i = 0; i < 256; i++) inv[SBOX[i]] = i;
        return inv;
    })();

    const RCON = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    ];

    const subByte = (b) => SBOX[b];
    const invSubByte = (b) => INV_SBOX[b];

    const keyExpansion = (key) => {
        const Nk = 4,
            Nr = 10;
        let w = new Uint32Array(4 * (Nr + 1));
        for (let i = 0; i < Nk; i++)
            w[i] =
                (key[4 * i] << 24) |
                (key[4 * i + 1] << 16) |
                (key[4 * i + 2] << 8) |
                key[4 * i + 3];
        for (let i = Nk; i < 4 * (Nr + 1); i++) {
            let temp = w[i - 1];
            if (i % Nk === 0) {
                temp =
                    (subByte((temp >>> 16) & 0xff) << 24) |
                    (subByte((temp >>> 8) & 0xff) << 16) |
                    (subByte(temp & 0xff) << 8) |
                    subByte(temp >>> 24);
                temp ^= RCON[i / Nk] << 24;
            }
            w[i] = w[i - Nk] ^ temp;
        }
        return w;
    };

    const addRoundKey = (state, w, round) => {
        for (let i = 0; i < 4; i++) {
            let k = w[round * 4 + i];
            state[i] ^= (k >>> 24) & 0xff;
            state[i + 4] ^= (k >>> 16) & 0xff;
            state[i + 8] ^= (k >>> 8) & 0xff;
            state[i + 12] ^= k & 0xff;
        }
    };

    const subBytes = (state) => {
        for (let i = 0; i < 16; i++) state[i] = subByte(state[i]);
    };
    const invSubBytes = (state) => {
        for (let i = 0; i < 16; i++) state[i] = invSubByte(state[i]);
    };

    const shiftRows = (state) => {
        let t = new Uint8Array(16);
        t[0] = state[0];
        t[1] = state[5];
        t[2] = state[10];
        t[3] = state[15];
        t[4] = state[4];
        t[5] = state[9];
        t[6] = state[14];
        t[7] = state[3];
        t[8] = state[8];
        t[9] = state[13];
        t[10] = state[2];
        t[11] = state[7];
        t[12] = state[12];
        t[13] = state[1];
        t[14] = state[6];
        t[15] = state[11];
        for (let i = 0; i < 16; i++) state[i] = t[i];
    };

    const invShiftRows = (state) => {
        let t = new Uint8Array(16);
        t[0] = state[0];
        t[1] = state[13];
        t[2] = state[10];
        t[3] = state[7];
        t[4] = state[4];
        t[5] = state[1];
        t[6] = state[14];
        t[7] = state[11];
        t[8] = state[8];
        t[9] = state[5];
        t[10] = state[2];
        t[11] = state[15];
        t[12] = state[12];
        t[13] = state[9];
        t[14] = state[6];
        t[15] = state[3];
        for (let i = 0; i < 16; i++) state[i] = t[i];
    };

    const xtime = (b) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;

    const mixColumns = (state) => {
        for (let c = 0; c < 4; c++) {
            let i = c * 4;
            let a = state.slice(i, i + 4);
            let b = a.map((x) => xtime(x));
            state[i] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
            state[i + 1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
            state[i + 2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
            state[i + 3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
        }
    };

    const invMixColumns = (state) => {
        for (let c = 0; c < 4; c++) {
            let i = c * 4;
            let a = state.slice(i, i + 4);
            const mul = (x, n) => {
                let r = 0;
                for (let i = 0; i < 8; i++) {
                    if (n & 1) r ^= x;
                    let hbit = x & 0x80;
                    x = (x << 1) & 0xff;
                    if (hbit) x ^= 0x1b;
                    n >>= 1;
                }
                return r;
            };
            state[i] =
                mul(a[0], 14) ^ mul(a[1], 11) ^ mul(a[2], 13) ^ mul(a[3], 9);
            state[i + 1] =
                mul(a[0], 9) ^ mul(a[1], 14) ^ mul(a[2], 11) ^ mul(a[3], 13);
            state[i + 2] =
                mul(a[0], 13) ^ mul(a[1], 9) ^ mul(a[2], 14) ^ mul(a[3], 11);
            state[i + 3] =
                mul(a[0], 11) ^ mul(a[1], 13) ^ mul(a[2], 9) ^ mul(a[3], 14);
        }
    };

    const encryptBlock = (input, w) => {
        let state = new Uint8Array(input);
        addRoundKey(state, w, 0);
        for (let round = 1; round < 10; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, w, round);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, w, 10);
        return state;
    };

    const decryptBlock = (input, w) => {
        let state = new Uint8Array(input);
        addRoundKey(state, w, 10);
        for (let round = 9; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, w, round);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, w, 0);
        return state;
    };

    const pad = (data) => {
        const padLen = 16 - (data.length % 16);
        const res = new Uint8Array(data.length + padLen);
        res.set(data);
        res.fill(padLen, data.length);
        return res;
    };

    const unpad = (data) => {
        let padLen = data[data.length - 1];
        return data.slice(0, data.length - padLen);
    };

    const toBytes = (str) => new TextEncoder().encode(str);
    const fromBytes = (bytes) => new TextDecoder().decode(bytes);

    // base62编码（a-zA-Z0-9）
    const base62chars =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    const base62Encode = (bytes) => {
        let num = BigInt(0);
        for (let b of bytes) {
            num = (num << 8n) + BigInt(b);
        }
        if (num === 0n) return "0";
        let s = "";
        while (num > 0n) {
            s = base62chars[Number(num % 62n)] + s;
            num /= 62n;
        }
        return s;
    };

    const base62Decode = (str) => {
        let num = BigInt(0);
        for (let c of str) {
            let val = base62chars.indexOf(c);
            if (val < 0) throw new Error("Invalid base62 char");
            num = num * 62n + BigInt(val);
        }
        // 转回字节数组
        let bytes = [];
        while (num > 0n) {
            bytes.unshift(Number(num & 0xffn));
            num >>= 8n;
        }
        return Uint8Array.from(bytes);
    };

    const xorBlock = (block, iv) => {
        let res = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            res[i] = block[i] ^ iv[i];
        }
        return res;
    };

    const encrypt = (plaintext, keyStr, ivStr) => {
        const key = toBytes(keyStr);
        if (key.length !== 16) throw new Error("Key length must be 16 bytes");
        const w = keyExpansion(key);
        let data = pad(toBytes(plaintext));
        let output = new Uint8Array(data.length);

        let iv = ivStr ? toBytes(ivStr) : new Uint8Array(16).fill(0);
        if (iv.length !== 16) throw new Error("IV length must be 16 bytes");

        for (let i = 0; i < data.length; i += 16) {
            let block = data.slice(i, i + 16);
            let xored = xorBlock(block, iv);
            let encryptedBlock = encryptBlock(xored, w);
            output.set(encryptedBlock, i);
            iv = encryptedBlock;
        }
        return base62Encode(output);
    };

    const decrypt = (ciphertext, keyStr, ivStr) => {
        const key = toBytes(keyStr);
        if (key.length !== 16) throw new Error("Key length must be 16 bytes");
        const w = keyExpansion(key);
        let data = base62Decode(ciphertext);
        if (data.length % 16 !== 0)
            throw new Error("Invalid ciphertext length");

        let output = new Uint8Array(data.length);

        let iv = ivStr ? toBytes(ivStr) : new Uint8Array(16).fill(0);
        if (iv.length !== 16) throw new Error("IV length must be 16 bytes");

        for (let i = 0; i < data.length; i += 16) {
            let block = data.slice(i, i + 16);
            let decryptedBlock = decryptBlock(block, w);
            let xored = xorBlock(decryptedBlock, iv);
            output.set(xored, i);
            iv = block;
        }
        output = unpad(output);
        return fromBytes(output);
    };

    return { encrypt, decrypt };
})();

const encrypt = AES.encrypt;
const decrypt = AES.decrypt;

export { encrypt, decrypt };
