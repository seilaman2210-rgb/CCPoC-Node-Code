'use strict';

const DEFAULT_INITIAL_REWARD = '1650000000000000000';
const DEFAULT_HALVING_INTERVAL = 6300000;

/**
 * Exact cumulative scheduled mining emission for block heights 1..lastHeight.
 * Reward is a deterministic function of height, so this avoids summing a
 * database column that may contain zeros or rewards from orphaned forks.
 */
function calculateEmissionThroughHeight(lastHeight, cfg = {}) {
  const maxHeight = Number(lastHeight);
  if (!Number.isSafeInteger(maxHeight) || maxHeight < 0) {
    throw new RangeError('lastHeight must be a non-negative safe integer');
  }
  if (maxHeight === 0) return 0n;

  const rawInterval = cfg.halvingInterval || DEFAULT_HALVING_INTERVAL;
  const interval = Number(rawInterval);
  if (!Number.isSafeInteger(interval) || interval <= 0) {
    throw new RangeError('halvingInterval must be a positive safe integer');
  }

  let reward;
  try {
    reward = BigInt(cfg.initialReward || DEFAULT_INITIAL_REWARD);
  } catch {
    throw new TypeError('initialReward must be an integer amount');
  }
  if (reward <= 0n) return 0n;

  // calculateMiningReward(height) applies halvings starting at height=interval.
  const initialHalvings = Math.floor(1 / interval);
  for (let i = 0; i < initialHalvings && reward > 0n; i++) reward /= 2n;

  let emitted = 0n;
  let nextHeight = 1;
  while (nextHeight <= maxHeight && reward > 0n) {
    const offset = nextHeight % interval;
    const blocksUntilHalving = offset === 0 ? interval : interval - offset;
    const count = Math.min(blocksUntilHalving, maxHeight - nextHeight + 1);
    emitted += BigInt(count) * reward;
    nextHeight += count;
    reward /= 2n;
  }

  return emitted;
}

module.exports = { calculateEmissionThroughHeight };
