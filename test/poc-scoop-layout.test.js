'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  SCOOP_SIZE,
  SCOOPS_PER_NONCE,
  MINING_SCOOP_MODULUS,
  plotScoopCount,
} = require('../src/crypto-utils/crypto');

test('PoC v4 sampling modulus matches the 32-byte leaf layout', () => {
  assert.equal(SCOOP_SIZE, 32);
  assert.equal(SCOOPS_PER_NONCE, 8192);
  assert.equal(MINING_SCOOP_MODULUS, SCOOPS_PER_NONCE);
});

test('a 1 GiB plot contains a whole number of CCPoC nonces', () => {
  const leaves = plotScoopCount(1);
  assert.equal(leaves, 33_554_432);
  assert.equal(leaves / SCOOPS_PER_NONCE, 4096);
});

test('each selected leaf slot maps to exactly one leaf in each complete nonce', () => {
  const nonceCount = 3;
  const leaves = nonceCount * SCOOPS_PER_NONCE;
  for (const target of [0, 1, 4095, 4096, SCOOPS_PER_NONCE - 1]) {
    const eligible = [];
    for (let index = 0; index < leaves; index++) {
      if (index % MINING_SCOOP_MODULUS === target) eligible.push(index);
    }
    assert.equal(eligible.length, nonceCount, `target slot ${target}`);
    for (let nonce = 0; nonce < nonceCount; nonce++) {
      assert.equal(eligible[nonce], nonce * SCOOPS_PER_NONCE + target);
    }
  }
});
