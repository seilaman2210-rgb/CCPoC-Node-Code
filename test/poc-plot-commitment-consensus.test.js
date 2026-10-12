'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { Chain } = require('../src/Blockchain/chain');
const {
  ZERO_ADDRESS,
  NONCE_BYTES,
  encodePlotCommitmentTxData,
} = require('../src/consensus/poc-plot-v4');

function setupChainFixture() {
  const db = new Database(':memory:');
  db.exec(\`
    CREATE TABLE blocks (
      hash TEXT PRIMARY KEY,
      parent_hash TEXT,
      height INTEGER NOT NULL
    );
    CREATE TABLE plot_commitment_events (
      block_hash TEXT NOT NULL,
      block_height INTEGER NOT NULL,
      tx_index INTEGER NOT NULL,
      plot_id TEXT NOT NULL,
      miner TEXT NOT NULL,
      merkle_root TEXT NOT NULL,
      capacity_bytes TEXT NOT NULL,
      size_gb REAL NOT NULL,
      total_scoops INTEGER NOT NULL,
      format_version INTEGER NOT NULL,
      PRIMARY KEY (block_hash, tx_index)
    );
  \`);

  const genesis = '01'.repeat(32);
  const main1 = '02'.repeat(32);
  const fork1 = '03'.repeat(32);
  db.prepare('INSERT INTO blocks(hash,parent_hash,height) VALUES(?,?,?)').run(genesis, '00'.repeat(32), 0);
  db.prepare('INSERT INTO blocks(hash,parent_hash,height) VALUES(?,?,?)').run(main1, genesis, 1);
  db.prepare('INSERT INTO blocks(hash,parent_hash,height) VALUES(?,?,?)').run(fork1, genesis, 1);

  const chain = Object.create(Chain.prototype);
  chain.db = db;
  chain.cfg = { chainId: '1337' };
  chain.bestHash = main1;
  chain.height = 1;
  return { db, chain, genesis, main1, fork1 };
}

const plotId = '34'.repeat(32);
const root = '56'.repeat(32);
const miner = '0x' + '12'.repeat(20);

function makeCommitTx(overrides = {}) {
  return {
    from_addr: miner,
    to_addr: ZERO_ADDRESS,
    value: '0',
    fee: '1',
    nonce: 0,
    chain_id: '1337',
    data: encodePlotCommitmentTxData({
      plot_id: plotId,
      merkle_root: root,
      capacity_bytes: String(NONCE_BYTES),
    }),
    ...overrides,
  };
}

function insertCommit(db, blockHash, height, id = plotId, owner = miner) {
  db.prepare(\`
    INSERT INTO plot_commitment_events
      (block_hash, block_height, tx_index, plot_id, miner, merkle_root,
       capacity_bytes, size_gb, total_scoops, format_version)
    VALUES (?,?,?,?,?,?,?,?,?,?)
  \`).run(blockHash, height, 0, id, owner, root,
    String(NONCE_BYTES), NONCE_BYTES / (1024 ** 3), NONCE_BYTES / 32, 4);
}

test('plot commitment transaction is accepted only with canonical destination/value/chain fields', () => {
  const f = setupChainFixture();
  try {
    const result = Chain.prototype._validatePlotCommitmentTxs.call(f.chain, [makeCommitTx()], f.genesis, 1);
    assert.equal(result.ok, true);
    assert.equal(result.commitments.length, 1);
    assert.equal(result.commitments[0].plot_id, plotId);
    assert.equal(result.commitments[0].format_version, 4);
    assert.equal(result.commitments[0].total_scoops, 8192);

    assert.equal(Chain.prototype._validatePlotCommitmentTxs.call(
      f.chain, [makeCommitTx({ to_addr: miner })], f.genesis, 1
    ).ok, false);
    assert.equal(Chain.prototype._validatePlotCommitmentTxs.call(
      f.chain, [makeCommitTx({ value: '1' })], f.genesis, 1
    ).ok, false);
    assert.equal(Chain.prototype._validatePlotCommitmentTxs.call(
      f.chain, [makeCommitTx({ chain_id: '1' })], f.genesis, 1
    ).ok, false);
  } finally {
    f.db.close();
  }
});

test('malformed marked plot commitment data is rejected instead of treated as ordinary contract data', () => {
  const f = setupChainFixture();
  try {
    const tx = makeCommitTx({ data: '0x434350430400' });
    const result = Chain.prototype._validatePlotCommitmentTxs.call(f.chain, [tx], f.genesis, 1);
    assert.equal(result.ok, false);
    assert.match(result.motivo, /payload length/);
  } finally {
    f.db.close();
  }
});

test('a committed plot ID cannot be registered twice on the same ancestry', () => {
  const f = setupChainFixture();
  try {
    insertCommit(f.db, f.main1, 1);
    const result = Chain.prototype._validatePlotCommitmentTxs.call(f.chain, [makeCommitTx()], f.main1, 2);
    assert.equal(result.ok, false);
    assert.match(result.motivo, /already committed/);
  } finally {
    f.db.close();
  }
});

test('plot commitments are resolved against the requested parent ancestry, not local/global cache state', () => {
  const f = setupChainFixture();
  try {
    insertCommit(f.db, f.main1, 1);
    const onMain = Chain.prototype.getPlotCommitment.call(f.chain, plotId, f.main1, 1);
    const onFork = Chain.prototype.getPlotCommitment.call(f.chain, plotId, f.fork1, 1);
    const immature = Chain.prototype.getPlotCommitment.call(f.chain, plotId, f.main1, 0);
    assert.ok(onMain);
    assert.equal(onMain.miner, miner);
    assert.equal(onFork, null);
    assert.equal(immature, null);
    const active = Chain.prototype.getActivePlotCommitments.call(f.chain, f.main1, 1);
    assert.equal(active.length, 1);
    assert.equal(Chain.prototype.getActivePlotCommitments.call(f.chain, f.fork1, 1).length, 0);
  } finally {
    f.db.close();
  }
});

test('one block cannot contain two plot commitments with the same identifier', () => {
  const f = setupChainFixture();
  try {
    const a = makeCommitTx();
    const b = makeCommitTx({ data: encodePlotCommitmentTxData({
      plot_id: plotId,
      merkle_root: '78'.repeat(32),
      capacity_bytes: String(NONCE_BYTES),
    }) });
    const result = Chain.prototype._validatePlotCommitmentTxs.call(f.chain, [a, b], f.genesis, 1);
    assert.equal(result.ok, false);
    assert.match(result.motivo, /more than once/);
  } finally {
    f.db.close();
  }
});
