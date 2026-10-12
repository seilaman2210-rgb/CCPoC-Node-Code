'use strict';

const DEFAULT_MAX_PLOT_GB = 10240;

/**
 * Validate a plot's declared capacity against the protocol's canonical
 * number of 32-byte scoop leaves. The expected count is passed by the caller
 * so the calculation remains centralized in crypto.js (plotScoopCount).
 */
function validatePlotMetadata(sizeGb, totalScoops, expectedTotalScoops, maxPlotGb = DEFAULT_MAX_PLOT_GB) {
  const size = typeof sizeGb === 'number' ? sizeGb
    : (typeof sizeGb === 'string' && sizeGb.trim() !== '' ? Number(sizeGb) : NaN);

  if (!Number.isFinite(size) || size <= 0 || size > maxPlotGb) {
    return { ok: false, motivo: `invalid size_gb (must be > 0 and <= ${maxPlotGb})` };
  }

  let count;
  if (typeof totalScoops === 'number') {
    count = totalScoops;
  } else if (typeof totalScoops === 'string' && /^\\d+$/.test(totalScoops)) {
    count = Number(totalScoops);
  } else {
    return { ok: false, motivo: 'total_scoops must be a positive integer' };
  }

  if (!Number.isSafeInteger(count) || count < 1) {
    return { ok: false, motivo: 'total_scoops must be a positive safe integer' };
  }
  if (!Number.isSafeInteger(expectedTotalScoops) || expectedTotalScoops < 1) {
    return { ok: false, motivo: 'expected total_scoops is invalid' };
  }
  if (count !== expectedTotalScoops) {
    return {
      ok: false,
      motivo: `total_scoops mismatch for size_gb=${String(size)}: expected ${expectedTotalScoops}, got ${count}`,
    };
  }

  return { ok: true, sizeGb: size, totalScoops: count };
}

module.exports = { validatePlotMetadata, DEFAULT_MAX_PLOT_GB };
