'use strict';

const crypto = require('crypto');

const PLOT_FORMAT_VERSION = 4;
const PLOT_COMMIT_OPCODE = 1;
const PLOT_TX_MAGIC = Buffer.from('CCPC', 'ascii');
const PLOT_TX_MAGIC_HEX = '0x43435043';
const ZERO_32 = Buffer.alloc(32);
const SCOOP_SIZE = 32;
const SCOOPS_PER_NONCE = 8192;
const NONCE_BYTES = SCOOP_SIZE * SCOOPS_PER_NONCE;
const GIB = 1024n * 1024n * 1024n;
const MIN_PLOT_BYTES = GIB;
const MAX_PLOT_BYTES = 10240n * GIB;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const NONCE_DOMAIN = Buffer.from('CCPOC:PLOT:V4:NONCE\0', 'ascii');
const LEAF_DOMAIN = Buffer.from('CCPOC:PLOT:V4:LEAF\0', 'ascii');
const CHALLENGE_DOMAIN = Buffer.from('CCPOC:CHALLENGE:V4\0', 'ascii');

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function hashPair(left, right) {
  if (!Buffer.isBuffer(left) || left.length !== 32 || !Buffer.isBuffer(right) || right.length !== 32) {
    throw new TypeError('Merkle nodes must be 32-byte buffers');
  }
  return sha256(Buffer.concat([left, right]));
}

function _hex32(value, name) {
  if (typeof value !== 'string' || !/^(?:0x)?[0-9a-fA-F]{64}$/.test(value)) {
    throw new TypeError(name + ' must be exactly 32 bytes of hexadecimal');
  }
  const hex = value.replace(/^0x/i, '').toLowerCase();
  const bytes = Buffer.from(hex, 'hex');
  if (bytes.equals(ZERO_32)) throw new TypeError(name + ' cannot be all zeroes');
  return { hex, bytes };
}

function _validateCapacityBytes(value) {
  let bytes;
  try {
    if (typeof value === 'bigint') bytes = value;
    else if (typeof value === 'number' && Number.isSafeInteger(value)) bytes = BigInt(value);
    else if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)) bytes = BigInt(value);
    else throw new TypeError('capacity_bytes must be an exact integer');
  } catch (e) {
    throw new TypeError('capacity_bytes must be an exact integer');
  }
  if (bytes < MIN_PLOT_BYTES || bytes > MAX_PLOT_BYTES) {
    throw new RangeError('capacity_bytes must be between 1 GiB and 10 TiB');
  }
  if (bytes % GIB !== 0n) throw new RangeError('v4 plot capacity must be an integer number of GiB');
  if (bytes % BigInt(NONCE_BYTES) !== 0n) throw new RangeError('plot capacity must contain complete nonces');
  const count = bytes / BigInt(SCOOP_SIZE);
  if (count > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('plot has too many leaves');
  return { capacityBytes: bytes, sizeGb: Number(bytes / GIB), totalScoops: Number(count) };
}

function encodePlotCommitmentTxData(input) {
  if (!input || typeof input !== 'object') throw new TypeError('plot commitment input is required');
  const plotId = _hex32(input.plot_id || input.plotId, 'plot_id');
  const root = _hex32(input.merkle_root || input.merkleRoot, 'merkle_root');
  const cap = _validateCapacityBytes(input.capacity_bytes != null ? input.capacity_bytes : input.capacityBytes);
  const payload = Buffer.alloc(78);
  PLOT_TX_MAGIC.copy(payload, 0);
  payload.writeUInt8(PLOT_FORMAT_VERSION, 4);
  payload.writeUInt8(PLOT_COMMIT_OPCODE, 5);
  plotId.bytes.copy(payload, 6);
  root.bytes.copy(payload, 38);
  payload.writeBigUInt64BE(cap.capacityBytes, 70);
  return '0x' + payload.toString('hex');
}

function isPlotCommitmentTxData(data) {
  return typeof data === 'string' && data.slice(0, 10).toLowerCase() === PLOT_TX_MAGIC_HEX;
}

function parsePlotCommitmentTxData(data) {
  if (!isPlotCommitmentTxData(data)) return { recognized: false, ok: true };
  if (typeof data !== 'string' || !/^0x[0-9a-f]+$/.test(data)) {
    return { recognized: true, ok: false, motivo: 'plot commitment data must be canonical lowercase 0x hex' };
  }
  if (data.length !== 2 + 78 * 2) {
    return { recognized: true, ok: false, motivo: 'invalid plot commitment payload length' };
  }
  const bytes = Buffer.from(data.slice(2), 'hex');
  if (!bytes.subarray(0, 4).equals(PLOT_TX_MAGIC)) {
    return { recognized: true, ok: false, motivo: 'invalid plot commitment magic' };
  }
  if (bytes.readUInt8(4) !== PLOT_FORMAT_VERSION) {
    return { recognized: true, ok: false, motivo: 'unsupported plot format version' };
  }
  if (bytes.readUInt8(5) !== PLOT_COMMIT_OPCODE) {
    return { recognized: true, ok: false, motivo: 'unsupported plot commitment operation' };
  }
  const plotId = bytes.subarray(6, 38);
  const merkleRoot = bytes.subarray(38, 70);
  if (plotId.equals(ZERO_32) || merkleRoot.equals(ZERO_32)) {
    return { recognized: true, ok: false, motivo: 'plot_id and merkle_root cannot be zero' };
  }
  let cap;
  try {
    cap = _validateCapacityBytes(bytes.readBigUInt64BE(70));
  } catch (e) {
    return { recognized: true, ok: false, motivo: e.message };
  }
  return {
    recognized: true,
    ok: true,
    commitment: {
      format_version: PLOT_FORMAT_VERSION,
      plot_id: plotId.toString('hex'),
      merkle_root: merkleRoot.toString('hex'),
      capacity_bytes: cap.capacityBytes.toString(),
      size_gb: cap.sizeGb,
      total_scoops: cap.totalScoops,
    },
  };
}

function deriveTargetScoopIndex(challengeId) {
  if (typeof challengeId !== 'string' || !/^[0-9a-f]{64}$/.test(challengeId)) {
    throw new TypeError('challenge_id must be a canonical 32-byte lowercase hash');
  }
  const digest = sha256(Buffer.concat([CHALLENGE_DOMAIN, Buffer.from(challengeId, 'hex')]));
  // The modulus is 2^13, so the low 13 bits are exactly uniform.
  return digest.readUInt16BE(30) & (SCOOPS_PER_NONCE - 1);
}

function _chainIdBytes(chainId) {
  const value = String(chainId == null ? '' : chainId);
  if (!/^(?:0|[1-9][0-9]{0,37})$/.test(value)) throw new TypeError('chain_id must be canonical unsigned decimal');
  return Buffer.from(value, 'ascii');
}

function _addressBytes(address) {
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new TypeError('miner must be a 20-byte EVM address');
  }
  return Buffer.from(address.slice(2).toLowerCase(), 'hex');
}

function _nonceSeed(chainId, miner, plotId, nonceIndex) {
  const chainBytes = _chainIdBytes(chainId);
  const minerBytes = _addressBytes(miner);
  const id = _hex32(plotId, 'plot_id').bytes;
  if (typeof nonceIndex !== 'number' || !Number.isSafeInteger(nonceIndex) || nonceIndex < 0) {
    throw new RangeError('nonce_index must be a non-negative safe integer');
  }
  const nonce = Buffer.alloc(8);
  nonce.writeBigUInt64BE(BigInt(nonceIndex));
  const chainLength = Buffer.from([chainBytes.length]);
  return sha256(Buffer.concat([NONCE_DOMAIN, chainLength, chainBytes, minerBytes, id, nonce]));
}

function _slotBytes(slot) {
  if (typeof slot !== 'number' || !Number.isInteger(slot) || slot < 0 || slot >= SCOOPS_PER_NONCE) {
    throw new RangeError('scoop slot must be between 0 and ' + (SCOOPS_PER_NONCE - 1));
  }
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(slot);
  return bytes;
}

function deriveCanonicalPlotLeaf(input) {
  if (!input || typeof input !== 'object') throw new TypeError('leaf derivation input is required');
  const nonceSeed = _nonceSeed(input.chain_id != null ? input.chain_id : input.chainId,
    input.miner, input.plot_id || input.plotId, input.nonce_index != null ? input.nonce_index : input.nonceIndex);
  const targetSlot = input.scoop_index != null ? input.scoop_index : input.scoopIndex;
  const targetBytes = _slotBytes(targetSlot);
  let previous = null;
  for (let slot = 0; slot <= targetSlot; slot++) {
    const data = previous
      ? Buffer.concat([LEAF_DOMAIN, nonceSeed, _slotBytes(slot), previous])
      : Buffer.concat([LEAF_DOMAIN, nonceSeed, _slotBytes(slot)]);
    previous = sha256(data);
  }
  return previous;
}

function* iterateCanonicalPlotLeaves(input) {
  if (!input || typeof input !== 'object') throw new TypeError('plot generation input is required');
  const chainBytes = _chainIdBytes(input.chain_id != null ? input.chain_id : input.chainId);
  const minerBytes = _addressBytes(input.miner);
  const plotId = _hex32(input.plot_id || input.plotId, 'plot_id').bytes;
  const cap = _validateCapacityBytes(input.capacity_bytes != null ? input.capacity_bytes : input.capacityBytes);
  const nonceCount = cap.totalScoops / SCOOPS_PER_NONCE;
  for (let nonceIndex = 0; nonceIndex < nonceCount; nonceIndex++) {
    const nonce = Buffer.alloc(8);
    nonce.writeBigUInt64BE(BigInt(nonceIndex));
    const nonceSeed = sha256(Buffer.concat([
      NONCE_DOMAIN, Buffer.from([chainBytes.length]), chainBytes, minerBytes, plotId, nonce,
    ]));
    let previous = null;
    for (let slot = 0; slot < SCOOPS_PER_NONCE; slot++) {
      const slotBytes = _slotBytes(slot);
      previous = previous
        ? sha256(Buffer.concat([LEAF_DOMAIN, nonceSeed, slotBytes, previous]))
        : sha256(Buffer.concat([LEAF_DOMAIN, nonceSeed, slotBytes]));
      yield previous;
    }
  }
}

class StreamingMerkleAccumulator {
  constructor(proofIndex = null) {
    if (proofIndex !== null && (!Number.isSafeInteger(proofIndex) || proofIndex < 0)) {
      throw new RangeError('proofIndex must be null or a non-negative safe integer');
    }
    this.proofIndex = proofIndex;
    this.count = 0;
    this.levels = [];
    this.proof = [];
  }

  _recordSibling(left, right, level) {
    if (this.proofIndex === null) return;
    const hasTargetLeft = this.proofIndex >= left.start && this.proofIndex < left.end;
    const hasTargetRight = this.proofIndex >= right.start && this.proofIndex < right.end;
    if (hasTargetLeft) this.proof[level] = Buffer.from(right.hash);
    else if (hasTargetRight) this.proof[level] = Buffer.from(left.hash);
  }

  addLeaf(value) {
    if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) throw new TypeError('leaf must be bytes');
    const hash = Buffer.from(value);
    if (hash.length !== 32) throw new TypeError('leaf must be exactly 32 bytes');
    const index = this.count++;
    let node = { hash, start: index, end: index + 1, level: 0 };
    let level = 0;
    while (this.levels[level]) {
      const left = this.levels[level];
      this._recordSibling(left, node, level);
      node = {
        hash: hashPair(left.hash, node.hash),
        start: left.start,
        end: node.end,
        level: level + 1,
      };
      this.levels[level] = null;
      level++;
    }
    this.levels[level] = node;
  }

  finish() {
    if (this.count < 1) throw new RangeError('cannot compute a Merkle root for zero leaves');
    if (this.proofIndex !== null && this.proofIndex >= this.count) throw new RangeError('proofIndex is outside the leaf set');
    let accumulator = null;
    for (let level = 0; level < this.levels.length; level++) {
      const peak = this.levels[level];
      if (!peak) continue;
      if (!accumulator) {
        accumulator = peak;
        continue;
      }
      while (accumulator.level < level) {
        accumulator = {
          hash: hashPair(accumulator.hash, accumulator.hash),
          start: accumulator.start,
          end: accumulator.end,
          level: accumulator.level + 1,
        };
      }
      this._recordSibling(peak, accumulator, level);
      accumulator = {
        hash: hashPair(peak.hash, accumulator.hash),
        start: peak.start,
        end: accumulator.end,
        level: level + 1,
      };
    }
    const proof = this.proofIndex === null
      ? undefined
      : this.proof.filter((entry) => Buffer.isBuffer(entry)).map((entry) => Buffer.from(entry));
    return { root: Buffer.from(accumulator.hash), count: this.count, proof };
  }
}

module.exports = {
  PLOT_FORMAT_VERSION,
  PLOT_COMMIT_OPCODE,
  PLOT_TX_MAGIC_HEX,
  SCOOP_SIZE,
  SCOOPS_PER_NONCE,
  NONCE_BYTES,
  GIB,
  MIN_PLOT_BYTES,
  MAX_PLOT_BYTES,
  ZERO_ADDRESS,
  encodePlotCommitmentTxData,
  isPlotCommitmentTxData,
  parsePlotCommitmentTxData,
  deriveTargetScoopIndex,
  deriveCanonicalPlotLeaf,
  iterateCanonicalPlotLeaves,
  StreamingMerkleAccumulator,
  hashPair,
};
