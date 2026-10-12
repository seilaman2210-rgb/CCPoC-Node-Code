'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const {
  privateKeyToAddress,
  verifySignature,
  proofMessage,
} = require('../src/crypto-utils/crypto');
const {
  deriveTargetScoopIndex,
  derivePlotCapacitySampleIndexes,
  verifyMerkleProofBuf,
  CAPACITY_SAMPLE_COUNT,
} = (() => {
  const poc = require('../src/consensus/poc-plot-v4');
  const crypto = require('../src/crypto-utils/crypto');
  return { ...poc, verifyMerkleProofBuf: crypto.verifyMerkleProofBuf };
})();

test('canonical v4 plot generator and proof builder interoperate end-to-end on one nonce', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ccpoc-v4-e2e-'));
  try {
    const privateKey = '0'.repeat(63) + '1';
    const miner = privateKeyToAddress(privateKey).toLowerCase();
    const chainId = '1337';
    const plotId = '34'.repeat(32);
    const plotPath = path.join(dir, 'plot-v4.bin');
    const metadataPath = plotPath + '.json';
    const challengeId = 'ab'.repeat(32);
    const challengeSeed = 'cd'.repeat(32);
    const baseTarget = '1000000000000000';

    const generationOutput = execFileSync(process.execPath, [
      path.resolve('scripts/generate-poc-v4-plot.js'),
      chainId,
      miner,
      '262144',
      plotPath,
      plotId,
    ], { encoding: 'utf8' });
    const generated = JSON.parse(generationOutput);
    assert.equal(generated.ok, true);
    assert.equal(generated.capacity_bytes, '262144');
    assert.equal(fs.statSync(plotPath).size, 262144);
    assert.ok(fs.statSync(generated.merkle_index_file).size > 0);

    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    const targetSlot = deriveTargetScoopIndex(challengeId);
    const proofOutput = execFileSync(process.execPath, [
      path.resolve('scripts/prove-poc-v4-leaf.js'),
      metadataPath,
      challengeId,
      challengeSeed,
      baseTarget,
      String(targetSlot),
    ], {
      encoding: 'utf8',
      env: { ...process.env, CCPOC_PRIVATE_KEY: privateKey },
    });
    const result = JSON.parse(proofOutput);
    assert.equal(result.ok, true);
    const packet = result.proof_packet;
    assert.equal(packet.plot_id, plotId);
    assert.equal(packet.miner, miner);
    assert.equal(packet.scoop_index, targetSlot);
    assert.equal(packet.merkle_root, generated.merkle_root);
    assert.equal(packet.capacity_samples.length, CAPACITY_SAMPLE_COUNT);

    const expectedSamples = derivePlotCapacitySampleIndexes(challengeId, packet.total_scoops, plotId, targetSlot);
    assert.deepEqual(packet.capacity_samples.map(sample => sample.scoop_index), expectedSamples);
    assert.equal(
      verifyMerkleProofBuf(
        Buffer.from(packet.scoop_data, 'hex'),
        packet.scoop_index,
        packet.total_scoops,
        packet.merkle_proof,
        packet.merkle_root
      ),
      true
    );
    for (const sample of packet.capacity_samples) {
      assert.equal(
        verifyMerkleProofBuf(
          Buffer.from(sample.scoop_data, 'hex'),
          sample.scoop_index,
          packet.total_scoops,
          sample.merkle_proof,
          packet.merkle_root
        ),
        true
      );
    }
    assert.equal(
      verifySignature(
        proofMessage(challengeId, miner, packet.deadline, plotId),
        packet.proof_signature,
        packet.public_key
      ),
      true
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
