'use strict';

const fs = require('fs');
const path = require('path');
const {
  verifyMerkleProofBuf,
  computeDeadline,
  sha256hex,
  proofMessage,
  signMessage,
  privateKeyToAddress,
  secpPublicKeyFromPrivate,
} = require('../src/crypto-utils/crypto');
const {
  PLOT_FORMAT_VERSION,
  SCOOP_SIZE,
  SCOOPS_PER_NONCE,
  ZERO_ADDRESS,
  deriveCanonicalPlotLeaf,
  deriveTargetScoopIndex,
  derivePlotCapacitySampleIndexes,
  CAPACITY_SAMPLE_COUNT,
} = require('../src/consensus/poc-plot-v4');

function readExactSync(fd, buffer, position) {
  let offset = 0;
  while (offset < buffer.length) {
    const read = fs.readSync(fd, buffer, offset, buffer.length - offset, position + offset);
    if (read <= 0) throw new Error('unexpected end of plot/Merkle index file');
    offset += read;
  }
}

function readLeafAndProof(index, totalScoops, plotFd, treeFd, levels) {
  const leaf = Buffer.alloc(SCOOP_SIZE);
  readExactSync(plotFd, leaf, index * SCOOP_SIZE);
  const merkleProof = [];
  let currentIndex = index;
  let count = totalScoops;
  let layer = 0;
  while (count > 1) {
    const oddLast = count % 2 === 1 && currentIndex === count - 1;
    if (!oddLast) {
      const siblingIndex = currentIndex ^ 1;
      const sibling = Buffer.alloc(SCOOP_SIZE);
      if (layer === 0) {
        readExactSync(plotFd, sibling, siblingIndex * SCOOP_SIZE);
      } else {
        const treeLevel = levels[layer - 1];
        if (!treeLevel || Number(treeLevel.count) !== count) {
          throw new Error('Merkle index metadata has inconsistent level counts');
        }
        readExactSync(treeFd, sibling, Number(treeLevel.offset_bytes) + siblingIndex * SCOOP_SIZE);
      }
      merkleProof.push(sibling.toString('hex'));
    }
    currentIndex = Math.floor(currentIndex / 2);
    count = Math.ceil(count / 2);
    layer++;
  }
  return { leaf, merkleProof };
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 5) {
    console.error('Usage: CCPoC_PRIVATE_KEY=<hex> node scripts/prove-poc-v4-leaf.js <metadata.json> <challenge_id> <challenge_seed> <base_target> <scoop_index>');
    process.exitCode = 2;
    return;
  }

  const metadataPath = path.resolve(args[0]);
  const challengeId = String(args[1]).replace(/^0x/i, '').toLowerCase();
  const challengeSeed = String(args[2]);
  const baseTarget = String(args[3]);
  const indexText = String(args[4]);
  if (!/^[0-9a-f]{64}$/.test(challengeId)) throw new Error('challenge_id must be 32-byte lowercase hex');
  if (!/^[0-9]+$/.test(indexText)) throw new Error('scoop_index must be a non-negative integer');
  if (!/^[0-9]+$/.test(baseTarget) || BigInt(baseTarget) <= 0n) throw new Error('base_target must be a positive decimal integer');

  const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  if (metadata.format_version !== PLOT_FORMAT_VERSION) throw new Error('plot metadata has an unsupported format version');
  if (!Array.isArray(metadata.merkle_index_levels) || !metadata.merkle_index_levels.length) {
    throw new Error('metadata is missing the streamed Merkle index');
  }

  const totalScoops = Number(metadata.total_scoops);
  const scoopIndex = Number(indexText);
  if (!Number.isSafeInteger(totalScoops) || totalScoops < 1) throw new Error('invalid total_scoops in metadata');
  if (!Number.isSafeInteger(scoopIndex) || scoopIndex < 0 || scoopIndex >= totalScoops) throw new Error('scoop_index is outside the plot');
  const targetSlot = deriveTargetScoopIndex(challengeId);
  if (scoopIndex % SCOOPS_PER_NONCE !== targetSlot) {
    throw new Error('scoop_index must target slot ' + targetSlot + ' for this challenge ID');
  }

  const plotPath = path.isAbsolute(metadata.plot_file)
    ? metadata.plot_file
    : path.resolve(path.dirname(metadataPath), metadata.plot_file);
  const treePath = path.isAbsolute(metadata.merkle_index_file)
    ? metadata.merkle_index_file
    : path.resolve(path.dirname(metadataPath), metadata.merkle_index_file);

  const plotFd = fs.openSync(plotPath, 'r');
  const treeFd = fs.openSync(treePath, 'r');
  let leaf;
  let merkleProof;
  let capacitySamples;
  try {
    const targetProof = readLeafAndProof(scoopIndex, totalScoops, plotFd, treeFd, metadata.merkle_index_levels);
    leaf = targetProof.leaf;
    merkleProof = targetProof.merkleProof;

    const canonicalLeaf = deriveCanonicalPlotLeaf({
      chain_id: String(metadata.chain_id),
      miner: String(metadata.miner).toLowerCase(),
      plot_id: String(metadata.plot_id),
      nonce_index: Math.floor(scoopIndex / SCOOPS_PER_NONCE),
      scoop_index: scoopIndex % SCOOPS_PER_NONCE,
    });
    if (!canonicalLeaf.equals(leaf)) throw new Error('selected stored leaf does not match canonical v4 generation');
    if (!verifyMerkleProofBuf(leaf, scoopIndex, totalScoops, merkleProof, metadata.merkle_root)) {
      throw new Error('generated Merkle proof does not match the on-chain root');
    }

    const sampleIndexes = derivePlotCapacitySampleIndexes(challengeId, totalScoops, metadata.plot_id, scoopIndex);
    capacitySamples = sampleIndexes.map(sampleIndex => {
      const sampleProof = readLeafAndProof(sampleIndex, totalScoops, plotFd, treeFd, metadata.merkle_index_levels);
      const canonicalSample = deriveCanonicalPlotLeaf({
        chain_id: String(metadata.chain_id),
        miner: String(metadata.miner).toLowerCase(),
        plot_id: String(metadata.plot_id),
        nonce_index: Math.floor(sampleIndex / SCOOPS_PER_NONCE),
        scoop_index: sampleIndex % SCOOPS_PER_NONCE,
      });
      if (!canonicalSample.equals(sampleProof.leaf)) {
        throw new Error('capacity sample at index ' + sampleIndex + ' is not canonical');
      }
      if (!verifyMerkleProofBuf(sampleProof.leaf, sampleIndex, totalScoops, sampleProof.merkleProof, metadata.merkle_root)) {
        throw new Error('capacity sample at index ' + sampleIndex + ' does not match the committed Merkle root');
      }
      return {
        scoop_index: sampleIndex,
        scoop_data: sampleProof.leaf.toString('hex'),
        merkle_proof: sampleProof.merkleProof,
      };
    });
  } finally {
    fs.closeSync(plotFd);
    fs.closeSync(treeFd);
  }

  if (!Array.isArray(capacitySamples) || capacitySamples.length !== CAPACITY_SAMPLE_COUNT) {
    throw new Error('failed to construct all canonical capacity samples');
  }

  const deadline = computeDeadline(leafHex, challengeSeed, baseTarget);
  const privateKey = String(process.env.CCPOC_PRIVATE_KEY || '').replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error('set CCPOC_PRIVATE_KEY to the miner key (do not put it in metadata or source code)');
  }
  const recoveredAddress = privateKeyToAddress(privateKey).toLowerCase();
  if (recoveredAddress !== String(metadata.miner).toLowerCase()) {
    throw new Error('CCPOC_PRIVATE_KEY does not belong to the plot owner in metadata');
  }
  const signature = signMessage(proofMessage(challengeId, recoveredAddress, deadline, metadata.plot_id), privateKey);
  const proofPacket = {
    format_version: PLOT_FORMAT_VERSION,
    challenge_id: challengeId,
    challenge_seed: challengeSeed,
    base_target: baseTarget,
    miner: recoveredAddress,
    public_key: secpPublicKeyFromPrivate(privateKey).toString('base64'),
    plot_id: metadata.plot_id,
    merkle_root: metadata.merkle_root,
    total_scoops: totalScoops,
    scoop_index: scoopIndex,
    scoop_data: leafHex,
    merkle_proof: merkleProof,
    capacity_samples: capacitySamples,
    deadline,
    proof_digest: sha256hex(Buffer.concat([leaf, Buffer.from(String(deadline))])),
    proof_signature: signature,
  };

  console.log(JSON.stringify({
    ok: true,
    to_addr: ZERO_ADDRESS,
    proof_packet: proofPacket,
    note: 'Submit this proof packet to the challenge API. The root must already be committed in a block at least one full block before the challenge parent.',
  }, null, 2));
}

try {
  main();
} catch (error) {
  console.error('PoC v4 proof generation failed:', error.message);
  process.exitCode = 1;
}
