'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { validatePlotCapacity } = require('../src/crypto-utils/plot-capacity');

test('validates the canonical scoop count for a 1 GiB plot', () => {
  assert.deepEqual(validatePlotCapacity(1, 33554432), {
    ok: true, sizeGb: 1, totalScoops: 33554432,
  });
});

test('rejects a plot claim with the wrong canonical scoop count', () => {
  assert.equal(validatePlotCapacity(1, 33554431).ok, false);
  assert.equal(validatePlotCapacity(1, '033554432').ok, false);
});
