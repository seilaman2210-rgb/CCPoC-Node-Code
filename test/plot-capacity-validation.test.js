'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { validatePlotMetadata } = require('../src/consensus/plot-capacity-validation');

test('accepts a canonical size and scoop count', () => {
  assert.deepEqual(validatePlotMetadata(1, 10, 10), {
    ok: true, sizeGb: 1, totalScoops: 10,
  });
});

test('rejects capacity claims inconsistent with the scoop count', () => {
  assert.equal(validatePlotMetadata(10, 10, 20).ok, false);
  assert.equal(validatePlotMetadata(1, 10, 11).ok, false);
});

test('rejects invalid sizes, fractional counts, and unsafe integers', () => {
  assert.equal(validatePlotMetadata(0, 1, 1).ok, false);
  assert.equal(validatePlotMetadata(-1, 1, 1).ok, false);
  assert.equal(validatePlotMetadata(10241, 1, 1).ok, false);
  assert.equal(validatePlotMetadata(1, 1.5, 1).ok, false);
  assert.equal(validatePlotMetadata(1, '1.5', 1).ok, false);
  assert.equal(validatePlotMetadata(1, '9007199254740992', 1).ok, false);
});

test('rejects non-canonical integer strings', () => {
  assert.equal(validatePlotMetadata(1, '0010', 10).ok, false);
});
