'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { validateImmutablePlotCommitment } = require('../src/crypto-utils/plot-capacity');

const rootA = 'a'.repeat(64);
const rootB = 'b'.repeat(64);
const existing = {
  merkle_root: rootA,
  size_gb: 1,
  total_scoops: 33554432,
};
const candidate = {
  merkle_root: rootA.toUpperCase(),
  size_gb: 1,
  total_scoops: 33554432,
};

test('allows first registration when no prior commitment exists', () => {
  assert.deepEqual(validateImmutablePlotCommitment(null, candidate), {
    ok: true,
    unchanged: false,
  });
});

test('allows an idempotent registration of the same root and capacity', () => {
  assert.deepEqual(validateImmutablePlotCommitment(existing, candidate), {
    ok: true,
    unchanged: true,
  });
});

test('rejects replacing a plot root under the same plot ID', () => {
  const result = validateImmutablePlotCommitment(existing, { ...candidate, merkle_root: rootB });
  assert.equal(result.ok, false);
  assert.match(result.motivo, /merkle_root cannot be replaced/);
});

test('rejects changing the declared capacity under the same plot ID', () => {
  const result = validateImmutablePlotCommitment(existing, { ...candidate, size_gb: 2 });
  assert.equal(result.ok, false);
  assert.match(result.motivo, /size_gb cannot be changed/);
});

test('rejects changing the canonical scoop count under the same plot ID', () => {
  const result = validateImmutablePlotCommitment(existing, { ...candidate, total_scoops: 67108864 });
  assert.equal(result.ok, false);
  assert.match(result.motivo, /total_scoops cannot be changed/);
});

test('refuses silent upgrades from legacy rows without a canonical root', () => {
  const result = validateImmutablePlotCommitment({ ...existing, merkle_root: '' }, candidate);
  assert.equal(result.ok, false);
  assert.match(result.motivo, /register a new plot_id/);
});
