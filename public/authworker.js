/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
const INPUT_ERROR = "input is invalid type";
const FINALIZE_ERROR = "finalize already called";
const HEX_CHARS = "0123456789abcdef".split("");
const SHAKE_PADDING = [31, 7936, 2031616, 520093696];
const CSHAKE_PADDING = [4, 1024, 262144, 67108864];
const KECCAK_PADDING = [1, 256, 65536, 16777216];
const PADDING = [6, 1536, 393216, 100663296];
const SHIFT = [0, 8, 16, 24];
const RC = [
  1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0,
  2147483649, 0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0,
  2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905,
  2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0,
  2147483658, 2147483648, 2147516545, 2147483648, 32896, 2147483648, 2147483649,
  0, 2147516424, 2147483648,
];
const OUTPUT_TYPES = ["hex", "buffer", "arrayBuffer", "array", "digest"];

const createOutputMethod = function (bits, padding, outputType) {
  return function (message) {
    return new Keccak(bits, padding, bits).update(message)[outputType]();
  };
};

const createOutputMethods = function (method, createMethod, bits, padding) {
  for (let i = 0; i < OUTPUT_TYPES.length; ++i) {
    const type = OUTPUT_TYPES[i];
    method[type] = createMethod(bits, padding, type);
  }
  return method;
};

const createMethod = function (bits, padding) {
  const method = createOutputMethod(bits, padding, "hex");
  method.create = function () {
    return new Keccak(bits, padding, bits);
  };
  method.update = function (message) {
    return method.create().update(message);
  };
  return createOutputMethods(method, createOutputMethod, bits, padding);
};

const keccak256 = createMethod(256, KECCAK_PADDING);

function Keccak(bits, padding, outputBits) {
  this.blocks = [];
  this.s = [];
  this.padding = padding;
  this.outputBits = outputBits;
  this.reset = true;
  this.finalized = false;
  this.block = 0;
  this.start = 0;
  this.blockCount = (1600 - (bits << 1)) >> 5;
  this.byteCount = this.blockCount << 2;
  this.outputBlocks = outputBits >> 5;
  this.extraBytes = (outputBits & 31) >> 3;

  for (let i = 0; i < 50; ++i) {
    this.s[i] = 0;
  }
}

Keccak.prototype.update = function (message) {
  if (this.finalized) {
    throw new Error(FINALIZE_ERROR);
  }
  let notString,
    type = typeof message;
  if (type !== "string") {
    if (type === "object") {
      if (message === null) {
        throw new Error(INPUT_ERROR);
      } else if (message.constructor === ArrayBuffer) {
        message = new Uint8Array(message);
      } else if (!Array.isArray(message)) {
      }
    } else {
      throw new Error(INPUT_ERROR);
    }
    notString = true;
  }
  let blocks = this.blocks,
    byteCount = this.byteCount,
    length = message.length,
    blockCount = this.blockCount,
    index = 0,
    s = this.s,
    i,
    code;

  while (index < length) {
    if (this.reset) {
      this.reset = false;
      blocks[0] = this.block;
      for (i = 1; i < blockCount + 1; ++i) {
        blocks[i] = 0;
      }
    }
    if (notString) {
      for (i = this.start; index < length && i < byteCount; ++index) {
        blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
      }
    } else {
      for (i = this.start; index < length && i < byteCount; ++index) {
        code = message.charCodeAt(index);
        if (code < 0x80) {
          blocks[i >> 2] |= code << SHIFT[i++ & 3];
        } else if (code < 0x800) {
          blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
          blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
        } else if (code < 0xd800 || code >= 0xe000) {
          blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
          blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
          blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
        } else {
          code =
            0x10000 +
            (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
          blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
          blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
          blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
          blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
        }
      }
    }
    this.lastByteIndex = i;
    if (i >= byteCount) {
      this.start = i - byteCount;
      this.block = blocks[blockCount];
      for (i = 0; i < blockCount; ++i) {
        s[i] ^= blocks[i];
      }
      f(s);
      this.reset = true;
    } else {
      this.start = i;
    }
  }
  return this;
};

Keccak.prototype.encode = function (x, right) {
  let o = x & 255,
    n = 1;
  let bytes = [o];
  x = x >> 8;
  o = x & 255;
  while (o > 0) {
    bytes.unshift(o);
    x = x >> 8;
    o = x & 255;
    ++n;
  }
  if (right) {
    bytes.push(n);
  } else {
    bytes.unshift(n);
  }
  this.update(bytes);
  return bytes.length;
};

Keccak.prototype.encodeString = function (str) {
  let notString,
    type = typeof str;
  if (type !== "string") {
    if (type === "object") {
      if (str === null) {
        throw new Error(INPUT_ERROR);
      } else if (ARRAY_BUFFER && str.constructor === ArrayBuffer) {
        str = new Uint8Array(str);
      } else if (!Array.isArray(str)) {
        if (!ARRAY_BUFFER || !ArrayBuffer.isView(str)) {
          throw new Error(INPUT_ERROR);
        }
      }
    } else {
      throw new Error(INPUT_ERROR);
    }
    notString = true;
  }
  let bytes = 0,
    length = str.length;
  if (notString) {
    bytes = length;
  } else {
    for (let i = 0; i < str.length; ++i) {
      const code = str.charCodeAt(i);
      if (code < 0x80) {
        bytes += 1;
      } else if (code < 0x800) {
        bytes += 2;
      } else if (code < 0xd800 || code >= 0xe000) {
        bytes += 3;
      } else {
        code =
          0x10000 + (((code & 0x3ff) << 10) | (str.charCodeAt(++i) & 0x3ff));
        bytes += 4;
      }
    }
  }
  bytes += this.encode(bytes * 8);
  this.update(str);
  return bytes;
};

Keccak.prototype.bytepad = function (strs, w) {
  let bytes = this.encode(w);
  for (let i = 0; i < strs.length; ++i) {
    bytes += this.encodeString(strs[i]);
  }
  const paddingBytes = w - (bytes % w);
  const zeros = [];
  zeros.length = paddingBytes;
  this.update(zeros);
  return this;
};

Keccak.prototype.finalize = function () {
  if (this.finalized) {
    return;
  }
  this.finalized = true;
  let blocks = this.blocks,
    i = this.lastByteIndex,
    blockCount = this.blockCount,
    s = this.s;
  blocks[i >> 2] |= this.padding[i & 3];
  if (this.lastByteIndex === this.byteCount) {
    blocks[0] = blocks[blockCount];
    for (i = 1; i < blockCount + 1; ++i) {
      blocks[i] = 0;
    }
  }
  blocks[blockCount - 1] |= 0x80000000;
  for (i = 0; i < blockCount; ++i) {
    s[i] ^= blocks[i];
  }
  f(s);
};

Keccak.prototype.toString = Keccak.prototype.hex = function () {
  this.finalize();

  let blockCount = this.blockCount,
    s = this.s,
    outputBlocks = this.outputBlocks,
    extraBytes = this.extraBytes,
    i = 0,
    j = 0;
  let hex = "",
    block;
  while (j < outputBlocks) {
    for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
      block = s[i];
      hex +=
        HEX_CHARS[(block >> 4) & 0x0f] +
        HEX_CHARS[block & 0x0f] +
        HEX_CHARS[(block >> 12) & 0x0f] +
        HEX_CHARS[(block >> 8) & 0x0f] +
        HEX_CHARS[(block >> 20) & 0x0f] +
        HEX_CHARS[(block >> 16) & 0x0f] +
        HEX_CHARS[(block >> 28) & 0x0f] +
        HEX_CHARS[(block >> 24) & 0x0f];
    }
    if (j % blockCount === 0) {
      f(s);
      i = 0;
    }
  }
  if (extraBytes) {
    block = s[i];
    hex += HEX_CHARS[(block >> 4) & 0x0f] + HEX_CHARS[block & 0x0f];
    if (extraBytes > 1) {
      hex += HEX_CHARS[(block >> 12) & 0x0f] + HEX_CHARS[(block >> 8) & 0x0f];
    }
    if (extraBytes > 2) {
      hex += HEX_CHARS[(block >> 20) & 0x0f] + HEX_CHARS[(block >> 16) & 0x0f];
    }
  }
  return hex;
};

Keccak.prototype.arrayBuffer = function () {
  this.finalize();

  let blockCount = this.blockCount,
    s = this.s,
    outputBlocks = this.outputBlocks,
    extraBytes = this.extraBytes,
    i = 0,
    j = 0;
  let bytes = this.outputBits >> 3;
  let buffer;
  if (extraBytes) {
    buffer = new ArrayBuffer((outputBlocks + 1) << 2);
  } else {
    buffer = new ArrayBuffer(bytes);
  }
  const array = new Uint32Array(buffer);
  while (j < outputBlocks) {
    for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
      array[j] = s[i];
    }
    if (j % blockCount === 0) {
      f(s);
    }
  }
  if (extraBytes) {
    array[i] = s[i];
    buffer = buffer.slice(0, bytes);
  }
  return buffer;
};

Keccak.prototype.buffer = Keccak.prototype.arrayBuffer;

Keccak.prototype.digest = Keccak.prototype.array = function () {
  this.finalize();

  let blockCount = this.blockCount,
    s = this.s,
    outputBlocks = this.outputBlocks,
    extraBytes = this.extraBytes,
    i = 0,
    j = 0;
  let array = [],
    offset,
    block;
  while (j < outputBlocks) {
    for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
      offset = j << 2;
      block = s[i];
      array[offset] = block & 0xff;
      array[offset + 1] = (block >> 8) & 0xff;
      array[offset + 2] = (block >> 16) & 0xff;
      array[offset + 3] = (block >> 24) & 0xff;
    }
    if (j % blockCount === 0) {
      f(s);
    }
  }
  if (extraBytes) {
    offset = j << 2;
    block = s[i];
    array[offset] = block & 0xff;
    if (extraBytes > 1) {
      array[offset + 1] = (block >> 8) & 0xff;
    }
    if (extraBytes > 2) {
      array[offset + 2] = (block >> 16) & 0xff;
    }
  }
  return array;
};

function Kmac(bits, padding, outputBits) {
  Keccak.call(this, bits, padding, outputBits);
}

Kmac.prototype = new Keccak();

Kmac.prototype.finalize = function () {
  this.encode(this.outputBits, true);
  return Keccak.prototype.finalize.call(this);
};

const f = function (s) {
  let h,
    l,
    n,
    c0,
    c1,
    c2,
    c3,
    c4,
    c5,
    c6,
    c7,
    c8,
    c9,
    b0,
    b1,
    b2,
    b3,
    b4,
    b5,
    b6,
    b7,
    b8,
    b9,
    b10,
    b11,
    b12,
    b13,
    b14,
    b15,
    b16,
    b17,
    b18,
    b19,
    b20,
    b21,
    b22,
    b23,
    b24,
    b25,
    b26,
    b27,
    b28,
    b29,
    b30,
    b31,
    b32,
    b33,
    b34,
    b35,
    b36,
    b37,
    b38,
    b39,
    b40,
    b41,
    b42,
    b43,
    b44,
    b45,
    b46,
    b47,
    b48,
    b49;
  for (n = 0; n < 48; n += 2) {
    c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
    c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
    c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
    c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
    c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
    c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
    c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
    c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
    c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
    c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];

    h = c8 ^ ((c2 << 1) | (c3 >>> 31));
    l = c9 ^ ((c3 << 1) | (c2 >>> 31));
    s[0] ^= h;
    s[1] ^= l;
    s[10] ^= h;
    s[11] ^= l;
    s[20] ^= h;
    s[21] ^= l;
    s[30] ^= h;
    s[31] ^= l;
    s[40] ^= h;
    s[41] ^= l;
    h = c0 ^ ((c4 << 1) | (c5 >>> 31));
    l = c1 ^ ((c5 << 1) | (c4 >>> 31));
    s[2] ^= h;
    s[3] ^= l;
    s[12] ^= h;
    s[13] ^= l;
    s[22] ^= h;
    s[23] ^= l;
    s[32] ^= h;
    s[33] ^= l;
    s[42] ^= h;
    s[43] ^= l;
    h = c2 ^ ((c6 << 1) | (c7 >>> 31));
    l = c3 ^ ((c7 << 1) | (c6 >>> 31));
    s[4] ^= h;
    s[5] ^= l;
    s[14] ^= h;
    s[15] ^= l;
    s[24] ^= h;
    s[25] ^= l;
    s[34] ^= h;
    s[35] ^= l;
    s[44] ^= h;
    s[45] ^= l;
    h = c4 ^ ((c8 << 1) | (c9 >>> 31));
    l = c5 ^ ((c9 << 1) | (c8 >>> 31));
    s[6] ^= h;
    s[7] ^= l;
    s[16] ^= h;
    s[17] ^= l;
    s[26] ^= h;
    s[27] ^= l;
    s[36] ^= h;
    s[37] ^= l;
    s[46] ^= h;
    s[47] ^= l;
    h = c6 ^ ((c0 << 1) | (c1 >>> 31));
    l = c7 ^ ((c1 << 1) | (c0 >>> 31));
    s[8] ^= h;
    s[9] ^= l;
    s[18] ^= h;
    s[19] ^= l;
    s[28] ^= h;
    s[29] ^= l;
    s[38] ^= h;
    s[39] ^= l;
    s[48] ^= h;
    s[49] ^= l;

    b0 = s[0];
    b1 = s[1];
    b32 = (s[11] << 4) | (s[10] >>> 28);
    b33 = (s[10] << 4) | (s[11] >>> 28);
    b14 = (s[20] << 3) | (s[21] >>> 29);
    b15 = (s[21] << 3) | (s[20] >>> 29);
    b46 = (s[31] << 9) | (s[30] >>> 23);
    b47 = (s[30] << 9) | (s[31] >>> 23);
    b28 = (s[40] << 18) | (s[41] >>> 14);
    b29 = (s[41] << 18) | (s[40] >>> 14);
    b20 = (s[2] << 1) | (s[3] >>> 31);
    b21 = (s[3] << 1) | (s[2] >>> 31);
    b2 = (s[13] << 12) | (s[12] >>> 20);
    b3 = (s[12] << 12) | (s[13] >>> 20);
    b34 = (s[22] << 10) | (s[23] >>> 22);
    b35 = (s[23] << 10) | (s[22] >>> 22);
    b16 = (s[33] << 13) | (s[32] >>> 19);
    b17 = (s[32] << 13) | (s[33] >>> 19);
    b48 = (s[42] << 2) | (s[43] >>> 30);
    b49 = (s[43] << 2) | (s[42] >>> 30);
    b40 = (s[5] << 30) | (s[4] >>> 2);
    b41 = (s[4] << 30) | (s[5] >>> 2);
    b22 = (s[14] << 6) | (s[15] >>> 26);
    b23 = (s[15] << 6) | (s[14] >>> 26);
    b4 = (s[25] << 11) | (s[24] >>> 21);
    b5 = (s[24] << 11) | (s[25] >>> 21);
    b36 = (s[34] << 15) | (s[35] >>> 17);
    b37 = (s[35] << 15) | (s[34] >>> 17);
    b18 = (s[45] << 29) | (s[44] >>> 3);
    b19 = (s[44] << 29) | (s[45] >>> 3);
    b10 = (s[6] << 28) | (s[7] >>> 4);
    b11 = (s[7] << 28) | (s[6] >>> 4);
    b42 = (s[17] << 23) | (s[16] >>> 9);
    b43 = (s[16] << 23) | (s[17] >>> 9);
    b24 = (s[26] << 25) | (s[27] >>> 7);
    b25 = (s[27] << 25) | (s[26] >>> 7);
    b6 = (s[36] << 21) | (s[37] >>> 11);
    b7 = (s[37] << 21) | (s[36] >>> 11);
    b38 = (s[47] << 24) | (s[46] >>> 8);
    b39 = (s[46] << 24) | (s[47] >>> 8);
    b30 = (s[8] << 27) | (s[9] >>> 5);
    b31 = (s[9] << 27) | (s[8] >>> 5);
    b12 = (s[18] << 20) | (s[19] >>> 12);
    b13 = (s[19] << 20) | (s[18] >>> 12);
    b44 = (s[29] << 7) | (s[28] >>> 25);
    b45 = (s[28] << 7) | (s[29] >>> 25);
    b26 = (s[38] << 8) | (s[39] >>> 24);
    b27 = (s[39] << 8) | (s[38] >>> 24);
    b8 = (s[48] << 14) | (s[49] >>> 18);
    b9 = (s[49] << 14) | (s[48] >>> 18);

    s[0] = b0 ^ (~b2 & b4);
    s[1] = b1 ^ (~b3 & b5);
    s[10] = b10 ^ (~b12 & b14);
    s[11] = b11 ^ (~b13 & b15);
    s[20] = b20 ^ (~b22 & b24);
    s[21] = b21 ^ (~b23 & b25);
    s[30] = b30 ^ (~b32 & b34);
    s[31] = b31 ^ (~b33 & b35);
    s[40] = b40 ^ (~b42 & b44);
    s[41] = b41 ^ (~b43 & b45);
    s[2] = b2 ^ (~b4 & b6);
    s[3] = b3 ^ (~b5 & b7);
    s[12] = b12 ^ (~b14 & b16);
    s[13] = b13 ^ (~b15 & b17);
    s[22] = b22 ^ (~b24 & b26);
    s[23] = b23 ^ (~b25 & b27);
    s[32] = b32 ^ (~b34 & b36);
    s[33] = b33 ^ (~b35 & b37);
    s[42] = b42 ^ (~b44 & b46);
    s[43] = b43 ^ (~b45 & b47);
    s[4] = b4 ^ (~b6 & b8);
    s[5] = b5 ^ (~b7 & b9);
    s[14] = b14 ^ (~b16 & b18);
    s[15] = b15 ^ (~b17 & b19);
    s[24] = b24 ^ (~b26 & b28);
    s[25] = b25 ^ (~b27 & b29);
    s[34] = b34 ^ (~b36 & b38);
    s[35] = b35 ^ (~b37 & b39);
    s[44] = b44 ^ (~b46 & b48);
    s[45] = b45 ^ (~b47 & b49);
    s[6] = b6 ^ (~b8 & b0);
    s[7] = b7 ^ (~b9 & b1);
    s[16] = b16 ^ (~b18 & b10);
    s[17] = b17 ^ (~b19 & b11);
    s[26] = b26 ^ (~b28 & b20);
    s[27] = b27 ^ (~b29 & b21);
    s[36] = b36 ^ (~b38 & b30);
    s[37] = b37 ^ (~b39 & b31);
    s[46] = b46 ^ (~b48 & b40);
    s[47] = b47 ^ (~b49 & b41);
    s[8] = b8 ^ (~b0 & b2);
    s[9] = b9 ^ (~b1 & b3);
    s[18] = b18 ^ (~b10 & b12);
    s[19] = b19 ^ (~b11 & b13);
    s[28] = b28 ^ (~b20 & b22);
    s[29] = b29 ^ (~b21 & b23);
    s[38] = b38 ^ (~b30 & b32);
    s[39] = b39 ^ (~b31 & b33);
    s[48] = b48 ^ (~b40 & b42);
    s[49] = b49 ^ (~b41 & b43);

    s[0] ^= RC[n];
    s[1] ^= RC[n + 1];
  }
};

const B256 = 2n ** 256n; // secp256k1 is short weierstrass curve
const P = B256 - 0x1000003d1n; // curve's field prime
const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn; // curve (group) order
const _a = 0n; // a equation's param
const _b = 7n; // b equation's param
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n; // base point x
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n; // base point y
const CURVE = { P, n: N, a: _a, b: _b, Gx, Gy }; // exported variables
const fLen = 32; // field / group byte length
const crv = (x) => mod(mod(x * mod(x * x)) + _a * x + _b); // x³ + ax + b weierstrass formula
const err = (m = "") => {
  throw new Error(m);
}; // error helper, messes-up stack trace
const big = (n) => typeof n === "bigint"; // is big integer
const str = (s) => typeof s === "string"; // is string
const fe = (n) => big(n) && 0n < n && n < P; // is field element (invertible)
const ge = (n) => big(n) && 0n < n && n < N; // is group element
const au8 = (
  a,
  l // is Uint8Array (of specific length)
) =>
  !(a instanceof Uint8Array) ||
  (typeof l === "number" && l > 0 && a.length !== l)
    ? err("Uint8Array expected")
    : a;
const u8n = (data) => new Uint8Array(data); // creates Uint8Array
const u8fr = (arr) => Uint8Array.from(arr); // another shortcut
const toU8 = (a, len) => au8(str(a) ? h2b(a) : a, len); // normalize (hex/u8a) to u8a
const toPriv = (p) => {
  if (!big(p)) p = b2n(toU8(p, fLen)); // convert to bigint when bytes
  return ge(p) ? p : err("private key out of range"); // check if bigint is in range
};
let Gpows = undefined; // precomputes for base point G
const isPoint = (p) => (p instanceof Point ? p : err("Point expected")); // is 3d point
class Point {
  constructor(px, py, pz) {
    this.px = px;
    this.py = py;
    this.pz = pz;
  } // z is optional
  get x() {
    return this.aff().x;
  } // .x, .y will call expensive toAffine.
  get y() {
    return this.aff().y;
  } // Should be used with care.
  equals(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = isPoint(other); // isPoint() checks class equality
    const X1Z2 = mod(X1 * Z2),
      X2Z1 = mod(X2 * Z1);
    const Y1Z2 = mod(Y1 * Z2),
      Y2Z1 = mod(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  neg() {
    return new Point(this.px, mod(-this.py), this.pz);
  } // negate, flips point over y coord
  dbl() {
    return this.add(this);
  } // point doubling
  add(other) {
    const { px: X1, py: Y1, pz: Z1 } = this; // formula from Renes-Costello-Batina
    const { px: X2, py: Y2, pz: Z2 } = isPoint(other); // https://eprint.iacr.org/2015/1060, algo 1
    const { a, b } = CURVE;
    let X3 = 0n,
      Y3 = 0n,
      Z3 = 0n; // Cost: 12M + 0S + 3*a + 3*b3 + 23add
    const b3 = mod(b * 3n);
    let t0 = mod(X1 * X2),
      t1 = mod(Y1 * Y2),
      t2 = mod(Z1 * Z2),
      t3 = mod(X1 + Y1); // step 1
    let t4 = mod(X2 + Y2); // step 5
    t3 = mod(t3 * t4);
    t4 = mod(t0 + t1);
    t3 = mod(t3 - t4);
    t4 = mod(X1 + Z1);
    let t5 = mod(X2 + Z2); // step 10
    t4 = mod(t4 * t5);
    t5 = mod(t0 + t2);
    t4 = mod(t4 - t5);
    t5 = mod(Y1 + Z1);
    X3 = mod(Y2 + Z2); // step 15
    t5 = mod(t5 * X3);
    X3 = mod(t1 + t2);
    t5 = mod(t5 - X3);
    Z3 = mod(a * t4);
    X3 = mod(b3 * t2); // step 20
    Z3 = mod(X3 + Z3);
    X3 = mod(t1 - Z3);
    Z3 = mod(t1 + Z3);
    Y3 = mod(X3 * Z3);
    t1 = mod(t0 + t0); // step 25
    t1 = mod(t1 + t0);
    t2 = mod(a * t2);
    t4 = mod(b3 * t4);
    t1 = mod(t1 + t2);
    t2 = mod(t0 - t2); // step 30
    t2 = mod(a * t2);
    t4 = mod(t4 + t2);
    t0 = mod(t1 * t4);
    Y3 = mod(Y3 + t0);
    t0 = mod(t5 * t4); // step 35
    X3 = mod(t3 * X3);
    X3 = mod(X3 - t0);
    t0 = mod(t3 * t1);
    Z3 = mod(t5 * Z3);
    Z3 = mod(Z3 + t0); // step 40
    return new Point(X3, Y3, Z3);
  }
  mul(n, safe = true) {
    if (!safe && n === 0n) return I; // in unsafe mode, allow zero
    if (!ge(n)) err("invalid scalar"); // must be 0 < n < CURVE.n
    if (this.equals(G)) return wNAF(n).p; // Use precomputes for base point
    let p = I,
      f = G; // init result point & fake point
    for (let d = this; n > 0n; d = d.dbl(), n >>= 1n) {
      // double-and-add ladder
      if (n & 1n) p = p.add(d);
      // if bit is present, add to point
      else if (safe) f = f.add(d); // if not, add to fake for timing safety
    }
    return p;
  }
  mulAddQUns(R, u1, u2) {
    return this.mul(u1, false).add(R.mul(u2, false)).ok(); // Unsafe: do NOT use for stuff related
  } // to private keys. Doesn't use Shamir trick
  aff() {
    const { px: x, py: y, pz: z } = this; // (x, y, z) ∋ (x=x/z, y=y/z)
    if (this.equals(I)) return { x: 0n, y: 0n }; // fast-path for zero point
    if (z === 1n) return { x, y }; // if z is 1, pass affine coordinates as-is
    const iz = inv(z); // z^-1: invert z
    if (mod(z * iz) !== 1n) err("invalid inverse"); // (z * z^-1) must be 1, otherwise bad math
    return { x: mod(x * iz), y: mod(y * iz) }; // x = x*z^-1; y = y*z^-1
  }
  ok() {
    const { x, y } = this.aff(); // convert to 2d xy affine point.
    if (!fe(x) || !fe(y)) err("Point invalid: x or y"); // x and y must be in range 0 < n < P
    return mod(y * y) === crv(x) // y² = x³ + ax + b, must be equal
      ? this
      : err("Point invalid: not on curve");
  }
  multiply(n) {
    return this.mul(n);
  } // Aliases for compatibilty
  negate() {
    return this.neg();
  }
  toAffine() {
    return this.aff();
  }
  assertValidity() {
    return this.ok();
  }
  static fromHex(hex) {
    hex = toU8(hex); // converts hex string to Uint8Array
    let p = undefined;
    const head = hex[0],
      tail = hex.subarray(1); // first byte is prefix, rest is data
    const x = slcNum(tail, 0, fLen),
      len = hex.length; // next 32 bytes are x coordinate
    if (len === 33 && [0x02, 0x03].includes(head)) {
      // compressed points: 33b, start
      if (!fe(x)) err("Point hex invalid: x not FE"); // with byte 0x02 or 0x03. Check if 0<x<P
      let y = sqrt(crv(x)); // x³ + ax + b is right side of equation
      const isYOdd = (y & 1n) === 1n; // y² is equivalent left-side. Calculate y²:
      const headOdd = (head & 1) === 1; // y = √y²; there are two solutions: y, -y
      if (headOdd !== isYOdd) y = mod(-y); // determine proper solution
      p = new Point(x, y, 1n); // create point
    } // Uncompressed points: 65b, start with 0x04
    if (len === 65 && head === 0x04)
      p = new Point(x, slcNum(tail, fLen, 2 * fLen), 1n);
    return p ? p.ok() : err("Point is not on curve"); // Verify the result
  }
  toHex(isCompressed = true) {
    const { x, y } = this.aff(); // Convert to 2d xy affine point
    const head = isCompressed ? ((y & 1n) === 0n ? "02" : "03") : "04"; // 0x02, 0x03, 0x04 prefix
    return `${head}${n2h(x)}${isCompressed ? "" : n2h(y)}`; // prefix||x and ||y
  }
  toRawBytes(isCompressed = true) {
    return h2b(this.toHex(isCompressed)); // Re-use toHex(), convert hex to bytes
  }
  static fromPrivateKey(n) {
    return G.mul(toPriv(n)); // base point by bigint(n)
  }
}
Point.BASE = new Point(Gx, Gy, 1n); // generator / base point.
Point.ZERO = new Point(0n, 1n, 0n); // identity / zero point
const { BASE: G, ZERO: I } = Point; // Generator, identity points
const mod = (a, b = P) => {
  let r = a % b;
  return r >= 0n ? r : b + r;
}; // mod division
const inv = (num, md = P) => {
  if (num === 0n || md <= 0n) err(`no inverse n=${num} mod=${md}`); // negative exponent not supported
  let a = mod(num, md),
    b = md,
    x = 0n,
    y = 1n,
    u = 1n,
    v = 0n;
  while (a !== 0n) {
    // uses euclidean gcd algorithm
    const q = b / a,
      r = b % a; // not constant-time
    const m = x - u * q,
      n = y - v * q;
    (b = a), (a = r), (x = u), (y = v), (u = m), (v = n);
  }
  return b === 1n ? mod(x, md) : err("no inverse"); // b is gcd at this point
};
const pow = (num, e, md = P) => {
  if (md <= 0n || e < 0n) err("pow invalid"); // exponentiation by squaring
  if (md === 1n) return 0n; // the ladder can leak exponent bits
  let res = 1n; // and is vulnerable to timing attacks
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) res = (res * num) % md;
    num = (num * num) % md;
  }
  return res;
};
const sqrt = (n) => {
  const r = pow(n, (P + 1n) / 4n, P); // So, a special, fast case. Paper: "Square
  return mod(r * r) === n ? r : err("sqrt invalid"); // Roots from 1;24,51,10 to Dan Shanks"
};
const padh = (num, pad) => num.toString(16).padStart(pad, "0");
const b2h = (b) =>
  Array.from(b)
    .map((e) => padh(e, 2))
    .join(""); // bytes to hex
const h2n = (hex) => (str(hex) ? BigInt(`0x${hex || "0"}`) : err()); // hex to number
const h2b = (hex) => {
  const l = hex.length; // error if not string,
  if (!str(hex) || l % 2) err("hex invalid"); // or has odd length like 3, 5.
  const arr = u8n(l / 2); // create result array
  for (let i = 0; i < arr.length; i++) {
    const j = i * 2;
    const h = hex.slice(j, j + 2); // hexByte. slice is faster than substr
    const b = Number.parseInt(h, 16); // byte, created from string part
    if (Number.isNaN(b) || b < 0) err("hex invalid"); // byte must be valid 0 <= byte < 256
    arr[i] = b;
  }
  return arr;
};
const b2n = (b) => h2n(b2h(b)); // bytes to number
const slcNum = (b, from, to) => b2n(b.slice(from, to)); // slice bytes num
const n2b = (num) => {
  return big(num) && num >= 0n && num < B256
    ? h2b(padh(num, 2 * fLen))
    : err("bigint expected");
};
const n2h = (num) => b2h(n2b(num)); // number to hex
const concatB = (...arrs) => {
  const r = u8n(arrs.reduce((sum, a) => sum + a.length, 0)); // create u8a of summed length
  let pad = 0; // walk through each array, ensure
  arrs.forEach((a) => {
    r.set(au8(a), pad);
    pad += a.length;
  }); // they have proper type
  return r;
};
const moreThanHalfN = (n) => n > N >> 1n; // if a number is bigger than CURVE.n/2
const getPublicKey = (privKey, isCompressed = true) => {
  return Point.fromPrivateKey(privKey).toRawBytes(isCompressed); // key from private
};
class Signature {
  constructor(r, s, recovery) {
    this.r = r;
    this.s = s;
    this.recovery = recovery;
    this.ok();
  }
  ok() {
    return ge(this.r) && ge(this.s) ? this : err();
  } // 0 < r or s < CURVE.n
  static fromCompact(hex) {
    hex = toU8(hex, 64); // compact repr is (32b r)||(32b s)
    return new Signature(slcNum(hex, 0, fLen), slcNum(hex, fLen, 2 * fLen));
  }
  hasHighS() {
    return moreThanHalfN(this.s);
  }
  recoverPublicKey(msgh) {
    const { r, s, recovery: rec } = this; // secg.org/sec1-v2.pdf 4.1.6
    if (![0, 1, 2, 3].includes(rec)) err("recovery id invalid"); // check recovery id
    const h = bits2int_modN(toU8(msgh, 32)); // Truncate hash
    const radj = rec === 2 || rec === 3 ? r + N : r; // If rec was 2 or 3, q.x is bigger than n
    if (radj >= P) err("q.x invalid"); // ensure q.x is still a field element
    const prefix = (rec & 1) === 0 ? "02" : "03"; // prefix is 0x02 or 0x03
    const R = Point.fromHex(`${prefix}${n2h(radj)}`); // concat prefix + hex repr of r
    const ir = inv(radj, N); // r^-1
    const u1 = mod(-h * ir, N); // -hr^-1
    const u2 = mod(s * ir, N); // sr^-1
    return G.mulAddQUns(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
  }
  toCompactRawBytes() {
    return h2b(this.toCompactHex());
  } // Uint8Array 64b compact repr
  toCompactHex() {
    return n2h(this.r) + n2h(this.s);
  } // hex 64b compact repr
}
const bits2int = (bytes) => {
  const delta = bytes.length * 8 - 256; // RFC suggests optional truncating via bits2octets
  const num = b2n(bytes); // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which
  return delta > 0 ? num >> BigInt(delta) : num; // matches bits2int. bits2int can produce res>N.
};
const bits2int_modN = (bytes) => {
  return mod(bits2int(bytes), N); // with 0: BAD for trunc as per RFC vectors
};
const i2o = (num) => n2b(num); // int to octets
const cr = () =>
  // We support: 1) browsers 2) node.js 19+
  typeof globalThis === "object" && "crypto" in globalThis
    ? globalThis.crypto
    : undefined;
let _hmacSync; // Can be redefined by use in utils; built-ins don't provide it
const stdo = { lowS: true }; // opts for sign()
const vstdo = { lowS: true }; // standard opts for verify()
const prepSig = (msgh, priv, opts = stdo) => {
  if (["der", "recovered", "canonical"].some((k) => k in opts))
    // Ban legacy options
    err("sign() legacy options not supported");
  let { lowS } = opts; // generates low-s sigs by default
  if (lowS == null) lowS = true; // RFC6979 3.2: we skip step A, because
  const h1i = bits2int_modN(toU8(msgh));
  const h1o = i2o(h1i);
  const d = toPriv(priv); // validate private key, convert to bigint
  const seed = [i2o(d), h1o]; // Step D of RFC6979 3.2
  let ent = opts.extraEntropy; // RFC6979 3.6: additional k' (optional)
  if (ent != null) {
    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
    if (ent === true) ent = etc.randomBytes(fLen); // if true, use CSPRNG to generate data
    const e = toU8(ent); // convert Hex|Bytes to Bytes
    if (e.length !== fLen) err(); // Expected 32 bytes of extra data
    seed.push(e);
  }
  const m = h1i; // convert msg to bigint
  const k2sig = (kBytes) => {
    const k = bits2int(kBytes); // Transforms k into Signature
    if (!ge(k)) return; // Check 0 < k < CURVE.n
    const ik = inv(k, N); // k^-1 mod n, NOT mod P
    const q = G.mul(k).aff(); // q = Gk
    const r = mod(q.x, N); // r = q.x mod n
    if (r === 0n) return; // r=0 invalid
    const s = mod(ik * mod(m + mod(d * r, N), N), N); // s = k^-1(m + rd) mod n
    if (s === 0n) return; // s=0 invalid
    let normS = s;
    let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n); // recovery bit
    if (lowS && moreThanHalfN(s)) {
      // if lowS was passed, ensure s is always
      normS = mod(-s, N); // in the bottom half of CURVE.n
      rec ^= 1;
    }
    return new Signature(r, normS, rec); // use normS, not s
  };
  return { seed: concatB(...seed), k2sig };
};
function hmacDrbg(asynchronous) {
  let v = u8n(fLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
  let k = u8n(fLen); // Steps B, C of RFC6979 3.2: set hashLen, in our case always same
  let i = 0; // Iterations counter, will throw when over 1000
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const _e = "drbg: tried 1000 values";
  if (asynchronous) {
    // asynchronous=true
    const h = (...b) => etc.hmacSha256Async(k, v, ...b); // hmac(k)(v, ...values)
    const reseed = async (seed = u8n()) => {
      k = await h(u8fr([0x00]), seed); // k = hmac(K || V || 0x00 || seed)
      v = await h(); // v = hmac(K || V)
      if (seed.length === 0) return;
      k = await h(u8fr([0x01]), seed); // k = hmac(K || V || 0x01 || seed)
      v = await h(); // v = hmac(K || V)
    };
    const gen = async () => {
      if (i++ >= 1000) err(_e);
      v = await h(); // v = hmac(K || V)
      return v;
    };
    return async (seed, pred) => {
      reset(); // the returned fn, don't, it's: 1. slower (JIT). 2. unsafe (async race conditions)
      await reseed(seed); // Steps D-G
      let res = undefined; // Step H: grind until k is in [1..n-1]
      while (!(res = pred(await gen()))) await reseed();
      reset();
      return res;
    };
  } else {
    const h = (...b) => {
      const f = _hmacSync;
      if (!f) err("utils.hmacSha256Sync not set");
      return f(k, v, ...b); // hmac(k)(v, ...values)
    };
    const reseed = (seed = u8n()) => {
      k = h(u8fr([0x00]), seed); // k = hmac(k || v || 0x00 || seed)
      v = h(); // v = hmac(k || v)
      if (seed.length === 0) return;
      k = h(u8fr([0x01]), seed); // k = hmac(k || v || 0x01 || seed)
      v = h(); // v = hmac(k || v)
    };
    const gen = () => {
      if (i++ >= 1000) err(_e);
      v = h(); // v = hmac(k || v)
      return v;
    };
    return (seed, pred) => {
      reset();
      reseed(seed); // Steps D-G
      let res = undefined; // Step H: grind until k is in [1..n-1]
      while (!(res = pred(gen()))) reseed();
      reset();
      return res;
    };
  }
}
// ECDSA sig generation via secg.org/sec1-v2.pdf 4.1.2. hmacDrbg()
const signAsync = async (msgh, priv, opts = stdo) => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);
  const genUntil = hmacDrbg(true);
  return genUntil(seed, k2sig);
};
const sign = (msgh, priv, opts = stdo) => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);
  const genUntil = hmacDrbg(false);
  return genUntil(seed, k2sig);
};
const verify = (sig, msgh, pub, opts = vstdo) => {
  let { lowS } = opts; // ECDSA signature verification
  if (lowS == null) lowS = true; // Default lowS=true
  if ("strict" in opts) err("verify() legacy options not supported"); // legacy param
  let sig_, h, P; // secg.org/sec1-v2.pdf 4.1.4
  const rs = sig && typeof sig === "object" && "r" in sig; // Previous ver supported DER sigs. We
  if (!rs && toU8(sig).length !== 2 * fLen)
    // throw error when DER is suspected now.
    err("signature must be 64 bytes");
  try {
    sig_ = rs ? new Signature(sig.r, sig.s).ok() : Signature.fromCompact(sig);
    h = bits2int_modN(toU8(msgh, fLen)); // Truncate hash
    P = pub instanceof Point ? pub.ok() : Point.fromHex(pub); // Validate public key
  } catch (e) {
    return false;
  } // Check sig for validity in both cases
  if (!sig_) return false;
  const { r, s } = sig_;
  if (lowS && moreThanHalfN(s)) return false; // lowS bans sig.s >= CURVE.n/2
  let R;
  try {
    const is = inv(s, N); // s^-1
    const u1 = mod(h * is, N); // u1 = hs^-1 mod n
    const u2 = mod(r * is, N); // u2 = rs^-1 mod n
    R = G.mulAddQUns(P, u1, u2).aff(); // R = u1⋅G + u2⋅P
  } catch (error) {
    return false;
  }
  if (!R) return false; // stop if R is identity / zero point
  const v = mod(R.x, N);
  return v === r; // mod(R.x, n) == r
};
const getSharedSecret = (privA, pubB, isCompressed = true) => {
  return Point.fromHex(pubB).mul(toPriv(privA)).toRawBytes(isCompressed); // ECDH
};
const hashToPrivateKey = (hash) => {
  hash = toU8(hash); // produces private keys with modulo bias
  const minLen = fLen + 8; // being neglible.
  if (hash.length < minLen || hash.length > 1024) err("expected proper params");
  const num = mod(b2n(hash), N - 1n) + 1n; // takes at least n+8 bytes
  return n2b(num);
};
const etc = {
  hexToBytes: h2b,
  bytesToHex: b2h,
  concatBytes: concatB,
  bytesToNumberBE: b2n,
  numberToBytesBE: n2b,
  mod,
  invert: inv,
  hmacSha256Async: async (key, ...msgs) => {
    const m = concatB(...msgs); // HMAC-SHA256 async. No sync built-in!
    const crypto = cr();
    if (!crypto) return err("utils.hmacSha256Async not set");
    const s = crypto.subtle;
    const k = await s.importKey(
      "raw",
      key,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign"]
    );
    return u8n(await s.sign("HMAC", k, m));
  },
  hmacSha256Sync: _hmacSync,
  hashToPrivateKey,
  randomBytes: (len) => {
    const crypto = cr(); // Can be shimmed in node.js <= 18 to prevent error:
    // import { webcrypto } from 'node:crypto';
    // if (!globalThis.crypto) globalThis.crypto = webcrypto;
    if (!crypto) err("crypto.getRandomValues must be defined");
    return crypto.getRandomValues(u8n(len));
  },
};
const utils = {
  normPrivateKeyToScalar: toPriv,
  randomPrivateKey: () => hashToPrivateKey(etc.randomBytes(fLen + 8)),
  isValidPrivateKey: (key) => {
    try {
      return !!toPriv(key);
    } catch (e) {
      return false;
    }
  },
  precompute(p, windowSize = 8) {
    return p;
  }, // no-op
};
Object.defineProperties(etc, {
  hmacSha256Sync: {
    configurable: false,
    get() {
      return _hmacSync;
    },
    set(f) {
      if (!_hmacSync) _hmacSync = f;
    },
  },
});
const W = 8; // Precomputes-related code. W = window size
const precompute = () => {
  const points = []; // 10x sign(), 2x verify(). To achieve this,
  const windows = 256 / W + 1; // app needs to spend 40ms+ to calculate
  let p = G,
    b = p; // a lot of points related to base point G.
  for (let w = 0; w < windows; w++) {
    // Points are stored in array and used
    b = p; // any time Gx multiplication is done.
    points.push(b); // They consume 16-32 MiB of RAM.
    for (let i = 1; i < 2 ** (W - 1); i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.dbl(); // Precomputes don't speed-up getSharedKey,
  } // which multiplies user point by scalar,
  return points; // when precomputes are using base point
};
const wNAF = (n) => {
  // Compared to other point mult methods,
  const comp = Gpows || (Gpows = precompute()); // stores 2x less points using subtraction
  const neg = (cnd, p) => {
    let n = p.neg();
    return cnd ? n : p;
  }; // negate
  let p = I,
    f = G; // f must be G, or could become I in the end
  const windows = 1 + 256 / W; // W=8 17 windows
  const wsize = 2 ** (W - 1); // W=8 128 window size
  const mask = BigInt(2 ** W - 1); // W=8 will create mask 0b11111111
  const maxNum = 2 ** W; // W=8 256
  const shiftBy = BigInt(W); // W=8 8
  for (let w = 0; w < windows; w++) {
    const off = w * wsize;
    let wbits = Number(n & mask); // extract W bits.
    n >>= shiftBy; // shift number by W bits.
    if (wbits > wsize) {
      wbits -= maxNum;
      n += 1n;
    } // split if bits > max: +224 => 256-32
    const off1 = off,
      off2 = off + Math.abs(wbits) - 1; // offsets, evaluate both
    const cnd1 = w % 2 !== 0,
      cnd2 = wbits < 0; // conditions, evaluate both
    if (wbits === 0) {
      f = f.add(neg(cnd1, comp[off1])); // bits are 0: add garbage to fake point
    } else {
      //          ^ can't add off2, off2 = I
      p = p.add(neg(cnd2, comp[off2])); // bits are 1: add to result point
    }
  }
  return { p, f }; // return both real and fake points for JIT
}; // !! you can disable precomputes by commenting-out call of the wNAF() inside Point#mul()
const ProjectivePoint = Point;

/* END OF LIBRARIES */

let privateKey = null;
let RSA_KEYS = null;
const encryptionKeys = new Map(); // <string, CryptoKey>

function generatePrefix(messageLength) {
  return new TextEncoder().encode(
    `\x19Ethereum Signed Message:\n${messageLength + 3}RzR`
  );
  // TODO: this mitigitates the problem a little so, that no arbitrary signatures can be requested, not sure if it's necessary though, given the strict format.
}

function initialize(data) {
  const crypto = cr();
  return crypto.subtle
    .generateKey(
      {
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        name: "RSA-OAEP",
        modulusLength: 4096,
        hash: "SHA-256",
      },
      true,
      ["wrapKey", "unwrapKey"]
    )
    .then((keys) => {
      privateKey = new Uint8Array(data);
      RSA_KEYS = keys;
      return new Uint8Array();
    });
}

function signData(data) {
  const timestamp = n2b(BigInt(Math.floor(new Date().getTime() / 1000))).slice(
    26
  );

  const message = concatB(timestamp, data);

  const messageHash = h2b(
    keccak256(new Uint8Array([...generatePrefix(message.length), ...message]))
  );

  return signAsync(messageHash, privateKey).then((signature) =>
    concatB(
      timestamp,
      n2b(signature.r),
      n2b(signature.s),
      new Uint8Array([27 + signature.recovery])
    )
  );
}

function getKey(identity) {
  return encryptionKeys.get(b2h(identity));
}

function signAndEncrypt(identity, data) {
  const key = getKey(identity);
  if (!key) return new Uint8Array();
  const crypto = cr();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  return Promise.all([
    crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data),
    signData(data),
  ]).then(([cipher, timestampAndSignature]) =>
    concatB(timestampAndSignature, iv, new Uint8Array(cipher))
  );
}

function decrypt(identity, iv, data) {
  const key = encryptionKeys.get(b2h(identity));
  if (!key) return new Uint8Array();

  const crypto = cr();

  return crypto.subtle
    .decrypt({ name: "AES-GCM", iv }, key, data)
    .then((result) => new Uint8Array(result))
    .catch(() => new Uint8Array());
}

function exportPublicKey(identity) {
  const crypto = cr();
  return crypto.subtle
    .exportKey("spki", RSA_KEYS.publicKey)
    .then((exportedKey) =>
      signData(concatB(identity, new Uint8Array(exportedKey))).then(
        (timestampAndSignature) =>
          concatB(timestampAndSignature, new Uint8Array(exportedKey))
      )
    );
}

function generateAndWrapKey(identity, publicKey) {
  const crypto = cr();
  return crypto.subtle
    .generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
    )
    .then((key) => {
      encryptionKeys.set(b2h(identity), key);
      return crypto.subtle.importKey(
        "spki",
        publicKey,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
          modulusLength: 4096,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        },
        true,
        ["wrapKey"]
      );
    })
    .then((key) =>
      crypto.subtle.wrapKey("raw", encryptionKeys.get(b2h(identity)), key, {
        name: "RSA-OAEP",
      })
    )
    .then((wrappedKeyBuffer) => {
      const wrappedKey = new Uint8Array(wrappedKeyBuffer);

      return signData(concatB(identity, wrappedKey)).then((signature) =>
        concatB(signature, wrappedKey)
      );
    });
}

function unwrapAndSaveKey(identity, data) {
  const crypto = cr();
  return crypto.subtle
    .unwrapKey(
      "raw",
      data.buffer,
      RSA_KEYS.privateKey,
      "RSA-OAEP",
      "AES-GCM",
      true,
      ["encrypt", "decrypt"]
    )
    .then((key) => {
      encryptionKeys.set(b2h(identity), key);
      return new Uint8Array([1]);
    })
    .catch(() => new Uint8Array([0]));
}

const MESSAGE_TYPES = Object.freeze({
  [0]: "INITIALIZE",
  [1]: "SIGN",
  [2]: "SIGN_AND_ENCRYPT",
  [3]: "DECRYPT",
  [4]: "EXPORT_PUBLIC_KEY",
  [5]: "GENERATE_AND_WRAP_KEY",
  [6]: "UNWRAP_AND_SAVE_KEY",
  INITIALIZE: 0,
  SIGN: 1,
  SIGN_AND_ENCRYPT: 2,
  DECRYPT: 3,
  EXPORT_PUBLIC_KEY: 4,
  GENERATE_AND_WRAP_KEY: 5,
  UNWRAP_AND_SAVE_KEY: 6,
});

function processRequest(task, data) {
  switch (task) {
    case MESSAGE_TYPES.INITIALIZE:
      return initialize(data);
    case MESSAGE_TYPES.SIGN:
      return signData(data);
    case MESSAGE_TYPES.SIGN_AND_ENCRYPT:
      return signAndEncrypt(data.slice(0, 20), data.slice(20));
    case MESSAGE_TYPES.DECRYPT:
      return decrypt(data.slice(0, 20), data.slice(20, 32), data.slice(32));
    case MESSAGE_TYPES.EXPORT_PUBLIC_KEY:
      return exportPublicKey(data);
    case MESSAGE_TYPES.GENERATE_AND_WRAP_KEY:
      return generateAndWrapKey(data.slice(0, 20), data.slice(20));
    case MESSAGE_TYPES.UNWRAP_AND_SAVE_KEY:
      return unwrapAndSaveKey(data.slice(0, 20), data.slice(20));
    default:
  }
}

onmessage = (e) => {
  // actually this is false, communication language will probably be arraybuffer
  if (!au8(e.data) || e.data.length > 1048576)
    throw new Error(`invalid data supplied to worker`);

  const requestId = e.data.slice(1, 5);
  const data = e.data.slice(5);

  processRequest(e.data[0], data).then((result) =>
    postMessage(concatB(requestId, result))
  );
};
