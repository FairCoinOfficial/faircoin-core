/**
 * Binary encoding utilities for FairCoin protocol.
 * Base58Check, varint, integer serialization, and buffer helpers.
 */

import { sha256 } from "@noble/hashes/sha256";
import bs58 from "bs58";
import type { NetworkConfig } from "./network.js";

// ---------------------------------------------------------------------------
// Hex <-> Bytes
// ---------------------------------------------------------------------------

const HEX_CHARS = "0123456789abcdef";

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const hi = hex.charCodeAt(i * 2);
    const lo = hex.charCodeAt(i * 2 + 1);
    bytes[i] = (hexVal(hi) << 4) | hexVal(lo);
  }
  return bytes;
}

function hexVal(charCode: number): number {
  // 0-9
  if (charCode >= 48 && charCode <= 57) return charCode - 48;
  // a-f
  if (charCode >= 97 && charCode <= 102) return charCode - 87;
  // A-F
  if (charCode >= 65 && charCode <= 70) return charCode - 55;
  throw new Error(`Invalid hex character: ${String.fromCharCode(charCode)}`);
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_CHARS[bytes[i] >> 4];
    hex += HEX_CHARS[bytes[i] & 0x0f];
  }
  return hex;
}

/**
 * Byte-array equality: true only when both arrays have the same length and
 * identical bytes. NOT constant-time -- it is for comparing public values
 * (e.g. scriptPubKeys), never secret material.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Base58Check
// ---------------------------------------------------------------------------

function checksum(payload: Uint8Array): Uint8Array {
  return sha256(sha256(payload)).slice(0, 4);
}

export function base58CheckEncode(payload: Uint8Array): string {
  const cs = checksum(payload);
  const buf = new Uint8Array(payload.length + 4);
  buf.set(payload, 0);
  buf.set(cs, payload.length);
  return bs58.encode(buf);
}

export function base58CheckDecode(encoded: string): Uint8Array {
  const data = bs58.decode(encoded);
  if (data.length < 5) {
    throw new Error("Base58Check: input too short");
  }
  const payload = data.slice(0, data.length - 4);
  const cs = data.slice(data.length - 4);
  const expectedCs = checksum(payload);
  for (let i = 0; i < 4; i++) {
    if (cs[i] !== expectedCs[i]) {
      throw new Error("Base58Check: invalid checksum");
    }
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Address encoding
// ---------------------------------------------------------------------------

export function encodeAddress(hash160: Uint8Array, version: number): string {
  if (hash160.length !== 20) {
    throw new Error("hash160 must be 20 bytes");
  }
  const payload = new Uint8Array(21);
  payload[0] = version;
  payload.set(hash160, 1);
  return base58CheckEncode(payload);
}

export interface DecodedAddress {
  version: number;
  hash: Uint8Array;
}

export function decodeAddress(address: string): DecodedAddress {
  const payload = base58CheckDecode(address);
  if (payload.length !== 21) {
    throw new Error(
      `Invalid address payload length: expected 21, got ${payload.length}`,
    );
  }
  return {
    version: payload[0],
    hash: payload.slice(1),
  };
}

// ---------------------------------------------------------------------------
// WIF encoding
// ---------------------------------------------------------------------------

export function encodeWIF(
  privateKey: Uint8Array,
  compressed: boolean,
  network: NetworkConfig,
): string {
  if (privateKey.length !== 32) {
    throw new Error("Private key must be 32 bytes");
  }
  const payloadLen = compressed ? 34 : 33;
  const payload = new Uint8Array(payloadLen);
  payload[0] = network.wifPrefix;
  payload.set(privateKey, 1);
  if (compressed) {
    payload[33] = 0x01;
  }
  return base58CheckEncode(payload);
}

export interface DecodedWIF {
  privateKey: Uint8Array;
  compressed: boolean;
  networkPrefix: number;
}

export function decodeWIF(wif: string): DecodedWIF {
  const payload = base58CheckDecode(wif);
  if (payload.length !== 33 && payload.length !== 34) {
    throw new Error(
      `Invalid WIF payload length: expected 33 or 34, got ${payload.length}`,
    );
  }
  const networkPrefix = payload[0];
  const compressed = payload.length === 34;
  if (compressed && payload[33] !== 0x01) {
    throw new Error("Invalid compression flag in WIF");
  }
  return {
    privateKey: payload.slice(1, 33),
    compressed,
    networkPrefix,
  };
}

// ---------------------------------------------------------------------------
// VarInt
// ---------------------------------------------------------------------------

export function writeVarInt(n: number): Uint8Array {
  if (n < 0) {
    throw new Error("VarInt cannot be negative");
  }
  if (n < 0xfd) {
    return new Uint8Array([n]);
  }
  if (n <= 0xffff) {
    const buf = new Uint8Array(3);
    buf[0] = 0xfd;
    buf[1] = n & 0xff;
    buf[2] = (n >> 8) & 0xff;
    return buf;
  }
  if (n <= 0xffffffff) {
    const buf = new Uint8Array(5);
    buf[0] = 0xfe;
    buf[1] = n & 0xff;
    buf[2] = (n >> 8) & 0xff;
    buf[3] = (n >> 16) & 0xff;
    buf[4] = (n >> 24) & 0xff;
    return buf;
  }
  // For values > 32 bits, use BigInt to write correctly
  const buf = new Uint8Array(9);
  buf[0] = 0xff;
  const big = BigInt(n);
  for (let i = 0; i < 8; i++) {
    buf[1 + i] = Number((big >> BigInt(i * 8)) & 0xffn);
  }
  return buf;
}

export interface VarIntResult {
  value: number;
  bytesRead: number;
}

export function readVarInt(buf: Uint8Array, offset: number): VarIntResult {
  if (offset >= buf.length) {
    throw new Error("readVarInt: offset out of bounds");
  }
  const first = buf[offset];
  if (first < 0xfd) {
    return { value: first, bytesRead: 1 };
  }
  if (first === 0xfd) {
    ensureBytes(buf, offset, 3);
    return {
      value: buf[offset + 1] | (buf[offset + 2] << 8),
      bytesRead: 3,
    };
  }
  if (first === 0xfe) {
    ensureBytes(buf, offset, 5);
    return {
      value:
        (buf[offset + 1] |
          (buf[offset + 2] << 8) |
          (buf[offset + 3] << 16) |
          (buf[offset + 4] << 24)) >>>
        0,
      bytesRead: 5,
    };
  }
  // 0xff - 8 bytes
  ensureBytes(buf, offset, 9);
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value |= BigInt(buf[offset + 1 + i]) << BigInt(i * 8);
  }
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("readVarInt: value exceeds safe integer range");
  }
  return { value: Number(value), bytesRead: 9 };
}

function ensureBytes(
  buf: Uint8Array,
  offset: number,
  needed: number,
): void {
  if (offset + needed > buf.length) {
    throw new Error(
      `readVarInt: need ${needed} bytes at offset ${offset}, but buffer is ${buf.length} bytes`,
    );
  }
}

// ---------------------------------------------------------------------------
// Integer read/write helpers (little-endian)
// ---------------------------------------------------------------------------

export function writeUInt32LE(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = value & 0xff;
  buf[1] = (value >>> 8) & 0xff;
  buf[2] = (value >>> 16) & 0xff;
  buf[3] = (value >>> 24) & 0xff;
  return buf;
}

export function readUInt32LE(buf: Uint8Array, offset: number): number {
  if (offset + 4 > buf.length) {
    throw new Error("readUInt32LE: out of bounds");
  }
  return (
    (buf[offset] |
      (buf[offset + 1] << 8) |
      (buf[offset + 2] << 16) |
      (buf[offset + 3] << 24)) >>>
    0
  );
}

export function writeUInt64LE(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error("writeUInt64LE: value cannot be negative");
  }
  const buf = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    buf[i] = Number((value >> BigInt(i * 8)) & 0xffn);
  }
  return buf;
}

export function readUInt64LE(buf: Uint8Array, offset: number): bigint {
  if (offset + 8 > buf.length) {
    throw new Error("readUInt64LE: out of bounds");
  }
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value |= BigInt(buf[offset + i]) << BigInt(i * 8);
  }
  return value;
}

export function writeInt32LE(value: number): Uint8Array {
  // Works for signed int32 via unsigned reinterpretation
  return writeUInt32LE(value | 0);
}

export function readInt32LE(buf: Uint8Array, offset: number): number {
  if (offset + 4 > buf.length) {
    throw new Error("readInt32LE: out of bounds");
  }
  return (
    buf[offset] |
    (buf[offset + 1] << 8) |
    (buf[offset + 2] << 16) |
    (buf[offset + 3] << 24)
  );
}

// ---------------------------------------------------------------------------
// BufferWriter - incremental binary buffer builder
// ---------------------------------------------------------------------------

const INITIAL_CAPACITY = 256;

export class BufferWriter {
  private buffer: Uint8Array;
  private offset: number;

  constructor(initialCapacity: number = INITIAL_CAPACITY) {
    this.buffer = new Uint8Array(initialCapacity);
    this.offset = 0;
  }

  get length(): number {
    return this.offset;
  }

  private grow(needed: number): void {
    const required = this.offset + needed;
    if (required <= this.buffer.length) return;
    let newCap = this.buffer.length * 2;
    while (newCap < required) {
      newCap *= 2;
    }
    const newBuf = new Uint8Array(newCap);
    newBuf.set(this.buffer.subarray(0, this.offset), 0);
    this.buffer = newBuf;
  }

  writeBytes(data: Uint8Array): void {
    this.grow(data.length);
    this.buffer.set(data, this.offset);
    this.offset += data.length;
  }

  writeUInt8(value: number): void {
    this.grow(1);
    this.buffer[this.offset] = value & 0xff;
    this.offset += 1;
  }

  writeUInt16LE(value: number): void {
    this.grow(2);
    this.buffer[this.offset] = value & 0xff;
    this.buffer[this.offset + 1] = (value >> 8) & 0xff;
    this.offset += 2;
  }

  writeUInt32LE(value: number): void {
    this.grow(4);
    this.buffer[this.offset] = value & 0xff;
    this.buffer[this.offset + 1] = (value >>> 8) & 0xff;
    this.buffer[this.offset + 2] = (value >>> 16) & 0xff;
    this.buffer[this.offset + 3] = (value >>> 24) & 0xff;
    this.offset += 4;
  }

  writeInt32LE(value: number): void {
    this.writeUInt32LE(value | 0);
  }

  writeUInt64LE(value: bigint): void {
    this.grow(8);
    for (let i = 0; i < 8; i++) {
      this.buffer[this.offset + i] = Number(
        (value >> BigInt(i * 8)) & 0xffn,
      );
    }
    this.offset += 8;
  }

  writeVarInt(n: number): void {
    this.writeBytes(writeVarInt(n));
  }

  writeHash(hex: string): void {
    const bytes = hexToBytes(hex);
    if (bytes.length !== 32) {
      throw new Error(`Hash must be 32 bytes, got ${bytes.length}`);
    }
    // Hashes in Bitcoin protocol are stored in internal byte order (reversed)
    const reversed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      reversed[i] = bytes[31 - i];
    }
    this.writeBytes(reversed);
  }

  toBytes(): Uint8Array {
    return this.buffer.slice(0, this.offset);
  }
}

// ---------------------------------------------------------------------------
// BufferReader - incremental binary buffer parser
// ---------------------------------------------------------------------------

export class BufferReader {
  private readonly data: Uint8Array;
  private pos: number;

  constructor(data: Uint8Array) {
    this.data = data;
    this.pos = 0;
  }

  get offset(): number {
    return this.pos;
  }

  get remaining(): number {
    return this.data.length - this.pos;
  }

  private ensure(n: number): void {
    if (this.pos + n > this.data.length) {
      throw new Error(
        `BufferReader: need ${n} bytes at position ${this.pos}, but only ${this.remaining} remain`,
      );
    }
  }

  readBytes(n: number): Uint8Array {
    this.ensure(n);
    const slice = this.data.slice(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }

  readUInt8(): number {
    this.ensure(1);
    const val = this.data[this.pos];
    this.pos += 1;
    return val;
  }

  readUInt16LE(): number {
    this.ensure(2);
    const val = this.data[this.pos] | (this.data[this.pos + 1] << 8);
    this.pos += 2;
    return val;
  }

  readUInt32LE(): number {
    this.ensure(4);
    const val = readUInt32LE(this.data, this.pos);
    this.pos += 4;
    return val;
  }

  readInt32LE(): number {
    this.ensure(4);
    const val = readInt32LE(this.data, this.pos);
    this.pos += 4;
    return val;
  }

  readUInt64LE(): bigint {
    this.ensure(8);
    const val = readUInt64LE(this.data, this.pos);
    this.pos += 8;
    return val;
  }

  readVarInt(): number {
    const result = readVarInt(this.data, this.pos);
    this.pos += result.bytesRead;
    return result.value;
  }

  readHash(): string {
    const bytes = this.readBytes(32);
    // Reverse from internal byte order to display order
    const reversed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      reversed[i] = bytes[31 - i];
    }
    return bytesToHex(reversed);
  }
}
