'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { verifyMerkleProofBuf, expectedMerkleProofLen } = require('../src/crypto-utils/crypto');

function hashPair(left, right) {
  return crypto.createHash('sha256').update(Buffer.concat([left, right])).digest();
}

test('accepts a valid two-leaf Merkle proof', () => {
  const left = Buffer.alloc(32, 0x11);
  const right = Buffer.alloc(32, 0x22);
  const root = hashPair(left, right);
  assert.equal(expectedMerkleProofLen(0, 2), 1);
  assert.equal(verifyMerkleProofBuf(left, 0, 2, [right], root), true);
});

test('rejects missing, extra, and malformed Merkle siblings', () => {
  const left = Buffer.alloc(32, 0x11);
  const right = Buffer.alloc(32, 0x22);
  const root = hashPair(left, right);
  assert.equal(verifyMerkleProofBuf(left, 0, 2, [], root), false);
  assert.equal(verifyMerkleProofBuf(left, 0, 2, [right, right], root), false);
  assert.equal(verifyMerkleProofBuf(left, 0, 2, ['abcd'], root), false);
  assert.equal(verifyMerkleProofBuf(Buffer.alloc(31), 0, 2, [right], root), false);
});

test('validates the duplicate-last convention for odd-sized trees', () => {
  const first = Buffer.alloc(32, 0x01);
  const second = Buffer.alloc(32, 0x02);
  const third = Buffer.alloc(32, 0x03);
  const leftNode = hashPair(first, second);
  const duplicatedLast = hashPair(third, third);
  const root = hashPair(leftNode, duplicatedLast);
  assert.equal(expectedMerkleProofLen(2, 3), 1);
  assert.equal(verifyMerkleProofBuf(third, 2, 3, [leftNode], root), true);
});

test('rejects out-of-range indices and invalid tree sizes', () => {
  const leaf = Buffer.alloc(32, 0x11);
  const root = Buffer.alloc(32, 0x22);
  assert.equal(verifyMerkleProofBuf(leaf, -1, 1, [], root), false);
  assert.equal(verifyMerkleProofBuf(leaf, 1, 1, [], root), false);
  assert.equal(verifyMerkleProofBuf(leaf, 0, 0, [], root), false);
  assert.equal(verifyMerkleProofBuf(leaf, 0, 1, [leaf], leaf), false);
});
