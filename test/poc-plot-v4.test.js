'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
  SCOOP_SIZE,
  SCOOPS_PER_NONCE,
  NONCE_BYTES,
  ZERO_ADDRESS,
  encodePlotCommitmentTxData,
  parsePlotCommitmentTxData,
  deriveTargetScoopIndex,
  deriveCanonicalPlotLeaf,
  StreamingMerkleAccumulator,
  hashPair,
} = require('../src/consensus/poc-plot-v4');
const { verifyMerkleProofBuf } = require('../src/crypto-utils/crypto');

const miner = '0x' + '12'.repeat(20);
const plotId = '34'.repeat(32);
const root = '56'.repeat(32);

test('v4 layout is fixed to 8192 sequential 32-byte leaves per nonce', () => {
  assert.equal(SCOOP_SIZE, 32);
  assert.equal(SCOOPS_PER_NONCE, 8192);
  assert.equal(NONCE_BYTES, 262144);
  assert.equal(ZERO_ADDRESS, '0x0000000000000000000000000000000000000000');
});

test('plot registration transaction payload round-trips canonically', () => {
  const data = encodePlotCommitmentTxData({
    plot_id: plotId,
    merkle_root: root,
    capacity_bytes: 1024 ** 3,
  });
  assert.equal(data.length, 2 + 78 * 2);
  assert.equal(data, data.toLowerCase());
  const parsed = parsePlotCommitmentTxData(data);
  assert.equal(parsed.recognized, true);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.commitment.plot_id, plotId);
  assert.equal(parsed.commitment.merkle_root, root);
  assert.equal(parsed.commitment.capacity_bytes, String(1024 ** 3));
  assert.equal(parsed.commitment.size_gb, 1);
  assert.equal(parsed.commitment.total_scoops, 33554432);
});

test('malformed or non-canonical plot commitment transactions are rejected', () => {
  const valid = encodePlotCommitmentTxData({
    plot_id: plotId,
    merkle_root: root,
    capacity_bytes: 1024 ** 3,
  });
  assert.equal(parsePlotCommitmentTxData('0x1234').recognized, false);
  assert.equal(parsePlotCommitmentTxData('0x43435043').ok, false);
  assert.equal(parsePlotCommitmentTxData(valid.toUpperCase()).ok, false);
  assert.equal(parsePlotCommitmentTxData(valid.slice(0, -2)).ok, false);

  const badSize = Buffer.from(valid.slice(2), 'hex');
  badSize.writeBigUInt64BE(512n * 1024n * 1024n, 70);
  assert.equal(parsePlotCommitmentTxData('0x' + badSize.toString('hex')).ok, false);

  const badVersion = Buffer.from(valid.slice(2), 'hex');
  badVersion[4] = 3;
  assert.equal(parsePlotCommitmentTxData('0x' + badVersion.toString('hex')).ok, false);
});

test('challenge scoop is derived from the parent-bound challenge ID', () => {
  const a = deriveTargetScoopIndex('ab'.repeat(32));
  assert.equal(a, deriveTargetScoopIndex('ab'.repeat(32)));
  assert.ok(a >= 0 && a < SCOOPS_PER_NONCE);
  assert.notEqual(a, deriveTargetScoopIndex('cd'.repeat(32)));
  assert.throws(() => deriveTargetScoopIndex('not-a-hash'), /challenge_id/);
});

test('canonical leaf derivation is deterministic, scoped to owner, plot and chain', () => {
  const params = {
    chain_id: '1337',
    miner,
    plot_id: plotId,
    nonce_index: 9,
    scoop_index: 23,
  };
  const first = deriveCanonicalPlotLeaf(params);
  const second = deriveCanonicalPlotLeaf(params);
  assert.equal(first.length, 32);
  assert.deepEqual(first, second);
  assert.notDeepEqual(first, deriveCanonicalPlotLeaf({ ...params, nonce_index: 10 }));
  assert.notDeepEqual(first, deriveCanonicalPlotLeaf({ ...params, plot_id: '78'.repeat(32) }));
  assert.notDeepEqual(first, deriveCanonicalPlotLeaf({ ...params, miner: '0x' + '99'.repeat(20) }));
  assert.notDeepEqual(first, deriveCanonicalPlotLeaf({ ...params, chain_id: '1' }));
  assert.throws(() => deriveCanonicalPlotLeaf({ ...params, scoop_index: SCOOPS_PER_NONCE }), /scoop slot/);
});

function referenceRoot(values) {
  let nodes = values.map(Buffer.from);
  while (nodes.length > 1) {
    const next = [];
    for (let i = 0; i < nodes.length; i += 2) {
      next.push(hashPair(nodes[i], nodes[i + 1] || nodes[i]));
    }
    nodes = next;
  }
  return nodes[0];
}

function referenceProof(values, targetIndex) {
  let nodes = values.map(Buffer.from);
  let index = targetIndex;
  const proof = [];
  while (nodes.length > 1) {
    const sibling = index ^ 1;
    if (sibling < nodes.length) proof.push(Buffer.from(nodes[sibling]));
    const next = [];
    for (let i = 0; i < nodes.length; i += 2) {
      next.push(hashPair(nodes[i], nodes[i + 1] || nodes[i]));
    }
    nodes = next;
    index >>= 1;
  }
  return proof;
}

test('streaming Merkle accumulator matches duplicate-last root and proofs for odd/even trees', () => {
  for (let count = 1; count <= 17; count++) {
    const leaves = Array.from({ length: count }, (_, index) =>
      crypto.createHash('sha256').update('leaf-' + index).digest());
    const expectedRoot = referenceRoot(leaves);
    const plain = new StreamingMerkleAccumulator();
    for (const leaf of leaves) plain.addLeaf(leaf);
    assert.deepEqual(plain.finish().root, expectedRoot, 'root at count ' + count);

    for (let target = 0; target < count; target++) {
      const acc = new StreamingMerkleAccumulator(target);
      for (const leaf of leaves) acc.addLeaf(leaf);
      const result = acc.finish();
      assert.deepEqual(result.root, expectedRoot, 'proof root count=' + count + ' target=' + target);
      assert.deepEqual(result.proof, referenceProof(leaves, target), 'proof count=' + count + ' target=' + target);
      assert.equal(
        verifyMerkleProofBuf(leaves[target], target, count, result.proof.map(v => v.toString('hex')), expectedRoot),
        true,
        'verifier count=' + count + ' target=' + target
      );
    }
  }
});

test('streaming Merkle accumulator rejects empty trees and out-of-range proof indexes', () => {
  assert.throws(() => new StreamingMerkleAccumulator().finish(), /zero leaves/);
  const acc = new StreamingMerkleAccumulator(1);
  acc.addLeaf(Buffer.alloc(32, 1));
  assert.throws(() => acc.finish(), /outside/);
});
