const { vrfProve, vrfVerify, plotRegisterMessage, signMessage, verifySignature, pubkeyToAddress, safeInt, plotScoopCount } = require('./crypto');
const { validatePlotMetadata } = require('../consensus/plot-capacity-validation');
const isMerkleRoot = (v) => typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v);

const MAX_PLOT_GB = 10240;

function validatePlotCapacity(sizeGb, totalScoops) {
  const size = typeof sizeGb === 'number' ? sizeGb
    : (typeof sizeGb === 'string' && sizeGb.trim() !== '' ? Number(sizeGb) : NaN);
  const expectedScoops = plotScoopCount(size);
  return validatePlotMetadata(size, totalScoops, expectedScoops, MAX_PLOT_GB);
}

/**
 * Treat a plot ID as an immutable commitment identifier. Replacing the root or
 * capacity under the same (plot_id, miner) silently changes what a past proof
 * claims to have used. Replotting must use a new plot_id.
 */
function validateImmutablePlotCommitment(existing, candidate) {
  if (!existing) return { ok: true, unchanged: false };

  const existingRoot = String(existing.merkle_root || '').toLowerCase();
  const candidateRoot = String(candidate && candidate.merkle_root || '').toLowerCase();
  if (!isMerkleRoot(existingRoot)) {
    return { ok: false, motivo: 'existing plot commitment has no canonical root; register a new plot_id' };
  }
  if (!isMerkleRoot(candidateRoot) || existingRoot !== candidateRoot) {
    return { ok: false, motivo: 'plot_id is immutable: merkle_root cannot be replaced; register a new plot_id' };
  }

  const existingSize = Number(existing.size_gb);
  const candidateSize = Number(candidate && candidate.size_gb);
  if (!Number.isFinite(existingSize) || !Number.isFinite(candidateSize) || existingSize !== candidateSize) {
    return { ok: false, motivo: 'plot_id is immutable: size_gb cannot be changed; register a new plot_id' };
  }

  const parseCount = (value) => {
    if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0 ? value : null;
    if (typeof value === 'string' && /^[1-9][0-9]*$/.test(value)) {
      const n = Number(value);
      return Number.isSafeInteger(n) ? n : null;
    }
    return null;
  };
  const existingCount = parseCount(existing.total_scoops);
  const candidateCount = parseCount(candidate && candidate.total_scoops);
  if (existingCount === null || candidateCount === null || existingCount !== candidateCount) {
    return { ok: false, motivo: 'plot_id is immutable: total_scoops cannot be changed; register a new plot_id' };
  }

  return { ok: true, unchanged: true };
}

function makeLocalAnnouncement(plot, cfg, vrfOverrides = null) {
  const miner = String(plot.miner || '').toLowerCase();
  const merkleRoot = String(plot.merkle_root || '');
  const publicKey = String(plot.public_key || cfg.minerPublicKey || '');
  if (!publicKey) return null;
  try {
    const { pubkeyToAddress } = require('./crypto');
    if (pubkeyToAddress(publicKey).toLowerCase() !== miner) return null;
  } catch { return null; }
  const privateKey = String(plot.private_key !== undefined ? plot.private_key : (cfg.minerPrivateKey || ''));
  const sizeGb = plot.size_gb;
  const totalScoops = safeInt(plot.total_scoops, 0) || 0;

  let vrfPublicKey = plot.vrf_public_key || '';
  let vrfOutput = plot.vrf_output || '';
  let vrfProof = plot.vrf_proof || '';
  if (vrfOverrides && vrfOverrides.public_key) {
    vrfPublicKey = vrfOverrides.public_key;
    vrfOutput = vrfOverrides.output;
    vrfProof = vrfOverrides.proof;
  } else if (privateKey && merkleRoot && !vrfPublicKey) {
    try {
      const vrf = vrfProve(privateKey, plot.plot_id, merkleRoot);
      vrfPublicKey = vrf.public_key;
      vrfOutput = vrf.output;
      vrfProof = vrf.proof;
    } catch { /* leave empty, will be skipped by verifiers */ }
  }

  const ann = {
    miner,
    plot_id: String(plot.plot_id || ''),
    merkle_root: merkleRoot,
    size_gb: sizeGb,
    total_scoops: totalScoops,
    vrf_public_key: vrfPublicKey,
    vrf_output: vrfOutput,
    vrf_proof: vrfProof,
    public_key: publicKey,
    node_url: cfg.nodeUrl || '',
  };
  if (plot.signature) {
    ann.signature = String(plot.signature);
  } else if (publicKey) {
    try {
      ann.signature = signMessage(plotRegisterMessage(miner, ann.plot_id, merkleRoot, String(sizeGb), String(totalScoops)), privateKey || '');
    } catch { ann.signature = ''; }
  }
  return ann;
}

function verifyAnnouncement(ann, opts = {}) {
  const requireVrf = opts.requireVrf !== false;
  const requireSig = opts.requireSig !== false;
  if (!ann || typeof ann !== 'object') return { ok: false, motivo: 'invalid announcement' };
  if (!ann.plot_id || !ann.miner) return { ok: false, motivo: 'plot_id and miner required' };
  if (!isMerkleRoot(ann.merkle_root)) return { ok: false, motivo: 'invalid merkle_root' };
  const miner = String(ann.miner).toLowerCase();
  const publicKey = String(ann.public_key || '');
  const merkleRoot = String(ann.merkle_root);
  const capacity = validatePlotCapacity(ann.size_gb, ann.total_scoops);
  if (!capacity.ok) return capacity;
  const sizeGb = capacity.sizeGb;

  if (requireSig) {
    if (!publicKey) return { ok: false, motivo: 'public_key required for signature check' };
    try {
      if (pubkeyToAddress(publicKey).toLowerCase() !== miner) return { ok: false, motivo: 'address does not match public key' };
    } catch { return { ok: false, motivo: 'invalid miner public key' }; }
    if (!ann.signature) return { ok: false, motivo: 'missing capacity signature' };
    const msg = plotRegisterMessage(miner, String(ann.plot_id), merkleRoot, String(sizeGb), String(safeInt(ann.total_scoops, 0) || 0));
    if (!verifySignature(msg, ann.signature, publicKey)) return { ok: false, motivo: 'invalid capacity signature' };
  }

  if (requireVrf) {
    if (!ann.vrf_public_key || !ann.vrf_output || !ann.vrf_proof) return { ok: false, motivo: 'missing VRF commitment' };
    const ok = vrfVerify(String(ann.vrf_public_key), merkleRoot, String(ann.vrf_output), ann.vrf_proof);
    if (!ok) return { ok: false, motivo: 'VRF capacity proof failed' };
  }

  return { ok: true };
}

module.exports = { makeLocalAnnouncement, verifyAnnouncement, validatePlotCapacity, validateImmutablePlotCommitment, isMerkleRoot, MAX_PLOT_GB };
