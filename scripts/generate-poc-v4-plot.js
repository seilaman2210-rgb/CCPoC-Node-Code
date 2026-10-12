'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  PLOT_FORMAT_VERSION,
  SCOOP_SIZE,
  SCOOPS_PER_NONCE,
  NONCE_BYTES,
  GIB,
  MIN_PLOT_BYTES,
  MAX_PLOT_BYTES,
  ZERO_ADDRESS,
  iterateCanonicalPlotLeaves,
  StreamingMerkleAccumulator,
  hashPair,
  encodePlotCommitmentTxData,
} = require('../src/consensus/poc-plot-v4');

const WRITE_CHUNK_BYTES = 1024 * 1024;
const TREE_BATCH_NODES = 32768;

function writeAllSync(fd, buffer, position) {
  let offset = 0;
  while (offset < buffer.length) {
    const written = fs.writeSync(fd, buffer, offset, buffer.length - offset, position + offset);
    if (written <= 0) throw new Error('short write while creating plot');
    offset += written;
  }
}

function readExactSync(fd, buffer, position) {
  let offset = 0;
  while (offset < buffer.length) {
    const read = fs.readSync(fd, buffer, offset, buffer.length - offset, position + offset);
    if (read <= 0) throw new Error('unexpected end of plot/tree file');
    offset += read;
  }
}

function buildMerkleIndex(plotPath, treePath, totalLeaves) {
  const plotFd = fs.openSync(plotPath, 'r');
  const treeFd = fs.openSync(treePath, 'wx');
  const levels = [];
  let sourceFd = plotFd;
  let sourceOffset = 0;
  let sourceCount = totalLeaves;
  let treeOffset = 0;
  let level = 1;

  try {
    while (sourceCount > 1) {
      const nextCount = Math.ceil(sourceCount / 2);
      const levelOffset = treeOffset;
      levels.push({
        level,
        count: nextCount,
        offset_bytes: String(levelOffset),
      });

      for (let start = 0; start < sourceCount; start += TREE_BATCH_NODES) {
        const inputCount = Math.min(TREE_BATCH_NODES, sourceCount - start);
        const input = Buffer.allocUnsafe(inputCount * SCOOP_SIZE);
        readExactSync(sourceFd, input, sourceOffset + start * SCOOP_SIZE);
        const outputCount = Math.ceil(inputCount / 2);
        const output = Buffer.allocUnsafe(outputCount * SCOOP_SIZE);

        for (let i = 0, out = 0; i < inputCount; i += 2, out++) {
          const left = input.subarray(i * SCOOP_SIZE, (i + 1) * SCOOP_SIZE);
          const right = i + 1 < inputCount
            ? input.subarray((i + 1) * SCOOP_SIZE, (i + 2) * SCOOP_SIZE)
            : left;
          hashPair(left, right).copy(output, out * SCOOP_SIZE);
        }
        writeAllSync(treeFd, output, treeOffset);
        treeOffset += output.length;
      }

      sourceFd = treeFd;
      sourceOffset = levelOffset;
      sourceCount = nextCount;
      level++;
    }

    fs.fsyncSync(treeFd);
    const root = Buffer.alloc(SCOOP_SIZE);
    const last = levels[levels.length - 1];
    readExactSync(treeFd, root, Number(last.offset_bytes));
    return { root, levels, treeBytes: treeOffset };
  } finally {
    fs.closeSync(plotFd);
    fs.closeSync(treeFd);
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 4 || args.length > 5) {
    console.error('Usage: node scripts/generate-poc-v4-plot.js <chain_id> <miner_address> <capacity_bytes> <plot_file> [plot_id_hex]');
    process.exitCode = 2;
    return;
  }

  const chainId = String(args[0]);
  const miner = String(args[1]).toLowerCase();
  const capacityText = String(args[2]);
  const plotPath = path.resolve(args[3]);
  const plotId = args[4]
    ? String(args[4]).replace(/^0x/i, '').toLowerCase()
    : crypto.randomBytes(32).toString('hex');

  if (!/^(?:0|[1-9][0-9]*)$/.test(capacityText)) throw new Error('capacity_bytes must be canonical unsigned decimal');
  const capacityBytes = BigInt(capacityText);
  if (capacityBytes < MIN_PLOT_BYTES || capacityBytes > MAX_PLOT_BYTES) {
    throw new RangeError('capacity_bytes must be at least one nonce and no larger than 10 TiB');
  }
  if (capacityBytes % BigInt(NONCE_BYTES) !== 0n) {
    throw new RangeError('capacity_bytes must be a multiple of ' + NONCE_BYTES + ' bytes (one complete nonce)');
  }

  // Validate chain/address/plot identity before creating any large files.
  const leafIterator = iterateCanonicalPlotLeaves({
    chain_id: chainId,
    miner,
    plot_id: plotId,
    capacity_bytes: capacityBytes.toString(),
  });
  const totalLeavesBig = capacityBytes / BigInt(SCOOP_SIZE);
  if (totalLeavesBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('plot has too many leaves for this implementation');
  const totalLeaves = Number(totalLeavesBig);

  fs.mkdirSync(path.dirname(plotPath), { recursive: true });
  const plotFd = fs.openSync(plotPath, 'wx');
  const accumulator = new StreamingMerkleAccumulator();
  let chunk = Buffer.allocUnsafe(WRITE_CHUNK_BYTES);
  let chunkOffset = 0;
  let writtenBytes = 0;

  try {
    for (const leaf of leafIterator) {
      accumulator.addLeaf(leaf);
      leaf.copy(chunk, chunkOffset);
      chunkOffset += SCOOP_SIZE;
      if (chunkOffset === chunk.length) {
        writeAllSync(plotFd, chunk, writtenBytes);
        writtenBytes += chunkOffset;
        chunkOffset = 0;
      }
    }
    if (chunkOffset > 0) {
      writeAllSync(plotFd, chunk.subarray(0, chunkOffset), writtenBytes);
      writtenBytes += chunkOffset;
    }
    fs.fsyncSync(plotFd);
  } catch (e) {
    fs.closeSync(plotFd);
    try { fs.unlinkSync(plotPath); } catch {}
    throw e;
  }
  fs.closeSync(plotFd);

  if (BigInt(writtenBytes) !== capacityBytes) {
    throw new Error('generated plot length does not match capacity_bytes');
  }

  const accumulated = accumulator.finish();
  const treePath = plotPath + '.mtree';
  const indexed = buildMerkleIndex(plotPath, treePath, totalLeaves);
  if (!indexed.root.equals(accumulated.root)) {
    try { fs.unlinkSync(treePath); } catch {}
    throw new Error('streaming Merkle root and disk index root differ');
  }

  const capacityBytesString = capacityBytes.toString();
  const rootHex = indexed.root.toString('hex');
  const registerData = encodePlotCommitmentTxData({
    plot_id: plotId,
    merkle_root: rootHex,
    capacity_bytes: capacityBytesString,
  });
  const metadataPath = plotPath + '.json';
  const metadata = {
    format_version: PLOT_FORMAT_VERSION,
    chain_id: chainId,
    miner,
    plot_id: plotId,
    merkle_root: rootHex,
    capacity_bytes: capacityBytesString,
    capacity_gb: Number(capacityBytes) / Number(GIB),
    total_scoops: totalLeaves,
    scoop_size_bytes: SCOOP_SIZE,
    scoops_per_nonce: SCOOPS_PER_NONCE,
    nonce_bytes: NONCE_BYTES,
    plot_file: plotPath,
    merkle_index_file: treePath,
    merkle_index_levels: indexed.levels,
    merkle_index_bytes: String(indexed.treeBytes),
    registration_transaction: {
      to_addr: ZERO_ADDRESS,
      value: '0',
      data: registerData,
    },
  };
  fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2) + '\n', { flag: 'wx' });

  console.log(JSON.stringify({
    ok: true,
    format_version: PLOT_FORMAT_VERSION,
    plot_id: plotId,
    merkle_root: rootHex,
    capacity_bytes: capacityBytesString,
    capacity_gb: metadata.capacity_gb,
    total_scoops: totalLeaves,
    plot_file: plotPath,
    merkle_index_file: treePath,
    metadata_file: metadataPath,
    registration_transaction: metadata.registration_transaction,
    warning: 'The transaction payload is not submitted automatically. Sign and broadcast a normal transaction to anchor this root on-chain.',
  }, null, 2));
}

try {
  main();
} catch (error) {
  console.error('PoC v4 plot generation failed:', error.message);
  process.exitCode = 1;
}
