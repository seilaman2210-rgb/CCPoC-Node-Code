'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { deriveSampleIndexes } = require('../src/crypto-utils/crypto');

test('sample selection is deterministic for the same challenge and plot ID', () => {
  const a = deriveSampleIndexes('seed', 1000, 64, 3, 'plot-1');
  const b = deriveSampleIndexes('seed', 1000, 64, 3, 'plot-1');
  assert.deepEqual(a, b);
});

test('partial samples are unique and always within the plot bounds', () => {
  for (const sampleCount of [1, 2, 17, 99]) {
    const indexes = deriveSampleIndexes('seed', 100, sampleCount, 1, 'plot');
    assert.equal(indexes.length, sampleCount);
    assert.equal(new Set(indexes).size, sampleCount);
    assert.ok(indexes.every(i => Number.isSafeInteger(i) && i >= 0 && i < 100));
  }
});

test('a full sample is a permutation of all leaf indexes', () => {
  const indexes = deriveSampleIndexes('seed', 32, 32, 1, 'plot');
  assert.equal(indexes.length, 32);
  assert.deepEqual([...indexes].sort((a, b) => a - b), Array.from({ length: 32 }, (_, i) => i));
});

test('zero requested samples returns an empty array', () => {
  assert.deepEqual(deriveSampleIndexes('seed', 100, 0, 1, 'plot'), []);
});

test('rejects invalid or unsafe plot/sample counts without looping forever', () => {
  assert.throws(() => deriveSampleIndexes('seed', 0, 1, 1, 'plot'), /totalScoops/);
  assert.throws(() => deriveSampleIndexes('seed', Number.MAX_SAFE_INTEGER + 1, 1, 1, 'plot'), /totalScoops/);
  assert.throws(() => deriveSampleIndexes('seed', 100, -1, 1, 'plot'), /sampleCount/);
  assert.throws(() => deriveSampleIndexes('seed', 100, 101, 1, 'plot'), /sampleCount/);
  assert.throws(() => deriveSampleIndexes('seed', 100, 1.5, 1, 'plot'), /sampleCount/);
  assert.throws(() => deriveSampleIndexes('seed', 2_000_000, 1_000_001, 1, 'plot'), /limit/);
});
