'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { calculateEmissionThroughHeight } = require('../src/consensus/issuance');

test('calculates emission only for mined heights and excludes genesis', () => {
  const cfg = { initialReward: '10', halvingInterval: 3 };
  assert.equal(calculateEmissionThroughHeight(0, cfg), 0n);
  assert.equal(calculateEmissionThroughHeight(1, cfg), 10n);
  assert.equal(calculateEmissionThroughHeight(2, cfg), 20n);
});

test('applies halvings at the same heights as calculateMiningReward', () => {
  const cfg = { initialReward: '10', halvingInterval: 3 };
  assert.equal(calculateEmissionThroughHeight(3, cfg), 25n);
  assert.equal(calculateEmissionThroughHeight(6, cfg), 37n);
});

test('supports one-block halving intervals and rejects invalid heights', () => {
  assert.equal(calculateEmissionThroughHeight(3, { initialReward: '8', halvingInterval: 1 }), 7n);
  assert.throws(() => calculateEmissionThroughHeight(-1, {}), RangeError);
  assert.throws(() => calculateEmissionThroughHeight(1.5, {}), RangeError);
  assert.throws(() => calculateEmissionThroughHeight(1, { halvingInterval: 0.5 }), RangeError);
});
