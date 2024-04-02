use anyhow::{Context, Result};
use bitcoin::consensus::{deserialize, serialize, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, OutPoint, Txid};
use bitcoin_slices::{bsl, Visit, Visitor};
use rayon::prelude::*;
use silentpayments::utils::receiving::recipient_calculate_tweak_data;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};

use crate::{
    chain::{Chain, NewHeader},
    daemon::Daemon,
    db::{DBStore, Row, WriteBatch},
    metrics::{self, Gauge, Histogram, Metrics},
    signals::ExitFlag,
    types::{
        bsl_txid, HashPrefixRow, HeaderRow, ScriptHash, ScriptHashRow, SerBlock, SpendingPrefixRow,
        TxidRow,
    },
};

#[derive(Clone)]
struct Stats {
    update_duration: Histogram,
    update_size: Histogram,
    height: Gauge,
    db_properties: Gauge,
}

impl Stats {
    fn new(metrics: &Metrics) -> Self {
        Self {
            update_duration: metrics.histogram_vec(
                "index_update_duration",
                "Index update duration (in seconds)",
                "step",
                metrics::default_duration_buckets(),
            ),
            update_size: metrics.histogram_vec(
                "index_update_size",
                "Index update size (in bytes)",
                "step",
                metrics::default_size_buckets(),
            ),
            height: metrics.gauge("index_height", "Indexed block height", "type"),
            db_properties: metrics.gauge("index_db_properties", "Index DB properties", "name"),
        }
    }

    fn observe_duration<T>(&self, label: &str, f: impl FnOnce() -> T) -> T {
        self.update_duration.observe_duration(label, f)
    }

    fn observe_size(&self, label: &str, rows: &[Row]) {
        self.update_size.observe(label, db_rows_size(rows) as f64);
    }

    fn observe_batch(&self, batch: &WriteBatch) {
        self.observe_size("write_funding_rows", &batch.funding_rows);
        self.observe_size("write_spending_rows", &batch.spending_rows);
        self.observe_size("write_txid_rows", &batch.txid_rows);
        self.observe_size("write_header_rows", &batch.header_rows);
        debug!(
            "writing {} funding and {} spending rows from {} transactions, {} blocks",
            batch.funding_rows.len(),
            batch.spending_rows.len(),
            batch.txid_rows.len(),
            batch.header_rows.len()
        );
    }

    fn observe_chain(&self, chain: &Chain) {
        self.height.set("tip", chain.height() as f64);
    }

    fn observe_db(&self, store: &DBStore) {
        for (cf, name, value) in store.get_properties() {
            self.db_properties
                .set(&format!("{}:{}", name, cf), value as f64);
        }
    }
}

/// Confirmed transactions' address index
pub struct Index {
    store: DBStore,
    batch_size: usize,
    lookup_limit: Option<usize>,
    chain: Chain,
    stats: Stats,
    is_ready: bool,
    flush_needed: bool,
}

impl Index {
    pub(crate) fn load(
        store: DBStore,
        mut chain: Chain,
        metrics: &Metrics,
        batch_size: usize,
        lookup_limit: Option<usize>,
        reindex_last_blocks: usize,
    ) -> Result<Self> {
        if let Some(row) = store.get_tip() {
            match deserialize(&row) {
                Ok(tip) => {
                    let headers = store
                        .read_headers()
                        .into_iter()
                        .map(|row| HeaderRow::from_db_row(&row).header)
                        .collect();
                    chain.load(headers, tip);
                    chain.drop_last_headers(reindex_last_blocks);
                }
                Err(_) => {}
            }
        };
        let stats = Stats::new(metrics);
        stats.observe_chain(&chain);
        stats.observe_db(&store);
        Ok(Index {
            store,
            batch_size,
            lookup_limit,
            chain,
            stats,
            is_ready: false,
            flush_needed: false,
        })
    }

    pub(crate) fn chain(&self) -> &Chain {
        &self.chain
    }

    pub(crate) fn limit_result<T>(&self, entries: impl Iterator<Item = T>) -> Result<Vec<T>> {
        let mut entries = entries.fuse();
        let result: Vec<T> = match self.lookup_limit {
            Some(lookup_limit) => entries.by_ref().take(lookup_limit).collect(),
            None => entries.by_ref().collect(),
        };
        if entries.next().is_some() {
            bail!(">{} index entries, query may take too long", result.len())
        }
        Ok(result)
    }

    pub(crate) fn filter_by_txid(&self, txid: Txid) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_txid(TxidRow::scan_prefix(txid))
            .map(|row| HashPrefixRow::from_db_row(&row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    pub(crate) fn filter_by_funding(
        &self,
        scripthash: ScriptHash,
    ) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_funding(ScriptHashRow::scan_prefix(scripthash))
            .map(|row| HashPrefixRow::from_db_row(&row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    pub(crate) fn filter_by_spending(
        &self,
        outpoint: OutPoint,
    ) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_spending(SpendingPrefixRow::scan_prefix(outpoint))
            .map(|row| HashPrefixRow::from_db_row(&row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    pub(crate) fn silent_payments_sync(
        &mut self,
        daemon: &Daemon,
        exit_flag: &ExitFlag,
        sp_begin_height: Option<usize>,
        sp_min_dust: Option<usize>,
        sp_skip_height: Option<usize>,
    ) -> Result<bool> {
        let mut start = sp_skip_height.unwrap_or(0);
        let initial_height = sp_begin_height.unwrap_or(70_000);

        self.flush_needed = true;

        if start == 0 {
            if let Some(row) = self.store.last_sp() {
                match deserialize::<BlockHash>(&row) {
                    Ok(blockhash) => {
                        start = self
                            .chain
                            .get_block_height(&blockhash)
                            .unwrap_or(initial_height - 1)
                            + 1;
                    }
                    Err(_) => {
                        start = self
                            .store
                            .read_last_tweak()
                            .into_iter()
                            .filter_map(|(blockhash, _)| {
                                Some(match deserialize::<BlockHash>(&blockhash) {
                                    Ok(blockhash) => {
                                        self.chain
                                            .get_block_height(&blockhash)
                                            .unwrap_or(initial_height - 1)
                                            + 1
                                    }
                                    Err(_) => initial_height,
                                })
                            })
                            .collect::<Vec<_>>()[0];
                    }
                };
            } else {
                start = initial_height;
            }
        }

        let new_header = self
            .chain
            .get_block_header(start)
            .and_then(|header| Some(NewHeader::from((*header, start))));

        if let Some(new_header) = new_header {
            info!("Looking for sp tweaks in block: {}", start);

            exit_flag
                .poll()
                .with_context(|| format!("indexing interrupted at height: {}", start))?;

            let min_dust = sp_min_dust
                .and_then(|dust| u64::try_from(dust).ok())
                .unwrap_or(0);

            self.sync_blocks(daemon, &[new_header], true, min_dust, !self.flush_needed)?;
        } else {
            if self.flush_needed {
                self.store.flush(); // full compaction is performed on the first flush call
                self.flush_needed = false;
            }
            if !self.is_ready {
                info!("Finished Looking for sp tweaks");
            }
            self.is_ready = true;
            return Ok(true); // no more blocks to index (done for now)
        }

        Ok(false) // sync is not done
    }

    pub(crate) fn get_tweaks(&self, height: usize, count: usize) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        let _: Vec<_> = self
            .store
            .read_tweaks(height as u64, count as u64)
            .into_iter()
            .filter_map(|(block_height_vec, data)| {
                if !data.is_empty() {
                    let mut chunk = 0;

                    while data.len() > chunk {
                        let mut obj = serde_json::Map::new();

                        let mut txid = [0u8; 32];
                        txid.copy_from_slice(&data[chunk..chunk + 32]);
                        chunk += 32;
                        txid.reverse();

                        let mut tweak = [0u8; 33];
                        tweak.copy_from_slice(&data[chunk..chunk + 33]);
                        chunk += 33;
                        obj.insert(
                            "tweak".to_string(),
                            serde_json::Value::String(tweak.as_hex().to_string()),
                        );

                        let mut output_pubkeys_len = [0u8; 8];
                        output_pubkeys_len.copy_from_slice(&data[chunk..chunk + 8]);
                        chunk += 8;

                        let chunk_size = 46;

                        data[chunk..]
                            .chunks(u64::from_be_bytes(output_pubkeys_len) as usize)
                            .next()?
                            .chunks(chunk_size)
                            .for_each(|pubkey| {
                                let mut pubkey_chunk = 0;

                                let mut vout = [0u8; 4];
                                vout.copy_from_slice(&pubkey[..4]);
                                pubkey_chunk += 4;

                                let mut amount = [0u8; 8];
                                amount.copy_from_slice(&pubkey[pubkey_chunk..pubkey_chunk + 8]);
                                pubkey_chunk += 8;

                                let pubkey_hex = serde_json::Value::String(
                                    pubkey[pubkey_chunk + 2..].as_hex().to_string(),
                                );
                                pubkey_chunk += 34;
                                chunk += pubkey_chunk;

                                if let Some(value) = obj.get_mut("output_pubkeys") {
                                    if let Some(vout_map) = value.as_object_mut() {
                                        vout_map.insert(
                                            u32::from_be_bytes(vout).to_string(),
                                            serde_json::json!({
                                                "pubkey": pubkey_hex,
                                                "amount": u64::from_be_bytes(amount).to_string()
                                            }),
                                        );
                                    };
                                } else {
                                    let mut vout_map = serde_json::Map::new();
                                    vout_map.insert(
                                        u32::from_be_bytes(vout).to_string(),
                                        serde_json::json!({
                                            "pubkey": pubkey_hex,
                                            "amount": u64::from_be_bytes(amount).to_string()
                                        }),
                                    );

                                    obj.insert(
                                        "output_pubkeys".to_string(),
                                        serde_json::Value::Object(vout_map),
                                    );
                                }
                            });

                        let mut height_value = [0u8; 8];
                        height_value.copy_from_slice(&block_height_vec);
                        let height = u64::from_be_bytes(height_value);

                        if let Some(value) = map.get_mut(&height.to_string()) {
                            if let Some(value_map) = value.as_object_mut() {
                                value_map.insert(
                                    Txid::from_byte_array(txid).to_string(),
                                    serde_json::Value::Object(obj),
                                );
                            }
                        } else {
                            let mut new_map = serde_json::Map::new();
                            new_map.insert(
                                Txid::from_byte_array(txid).to_string(),
                                serde_json::Value::Object(obj),
                            );
                            map.insert(height.to_string(), serde_json::Value::Object(new_map));
                        }
                    }

                    Some(())
                } else {
                    None
                }
            })
            .collect();

        serde_json::Value::Object(map)
    }

    // Return `Ok(true)` when the chain is fully synced and the index is compacted.
    pub(crate) fn sync(&mut self, daemon: &Daemon, exit_flag: &ExitFlag) -> Result<bool> {
        self.flush_needed = true;
        let new_headers = self
            .stats
            .observe_duration("headers", || daemon.get_new_headers(&self.chain))?;
        match (new_headers.first(), new_headers.last()) {
            (Some(first), Some(last)) => {
                let count = new_headers.len();
                info!(
                    "indexing {} blocks: [{}..{}]",
                    count,
                    first.height(),
                    last.height()
                );
            }
            _ => {
                return Ok(true); // no more blocks to index (done for now)
            }
        }
        for chunk in new_headers.chunks(self.batch_size) {
            exit_flag.poll().with_context(|| {
                format!(
                    "indexing interrupted at height: {}",
                    chunk.first().unwrap().height()
                )
            })?;
            self.sync_blocks(daemon, chunk, false, 0, !self.flush_needed)?;
        }
        self.chain.update(new_headers);
        self.stats.observe_chain(&self.chain);
        Ok(false) // sync is not done
    }

    fn sync_blocks(
        &mut self,
        daemon: &Daemon,
        chunk: &[NewHeader],
        sp: bool,
        min_dust: u64,
        initial_sync_done: bool,
    ) -> Result<()> {
        let blockhashes: Vec<BlockHash> = chunk.iter().map(|h| h.hash()).collect();
        let mut heights = chunk.iter().map(|h| h.height());

        let mut batch = WriteBatch::default();

        if !sp {
            let scan_block = |blockhash, block| {
                if let Some(height) = heights.next() {
                    self.stats.observe_duration("block", || {
                        index_single_block(
                            self,
                            blockhash,
                            block,
                            height,
                            &mut batch,
                            initial_sync_done,
                        );
                    });
                    self.stats.height.set("tip", height as f64);
                };
            };

            daemon.for_blocks(blockhashes, scan_block)?;
        } else {
            let scan_block_for_sp = |blockhash, block| {
                if let Some(height) = heights.next() {
                    scan_single_block_for_silent_payments(
                        daemon, height, blockhash, block, &mut batch, min_dust,
                    );
                };
            };

            daemon.for_blocks(blockhashes, scan_block_for_sp)?;
        }

        batch.sort();
        self.stats.observe_batch(&batch);
        self.stats
            .observe_duration("write", || self.store.write(&batch));
        self.stats.observe_db(&self.store);
        Ok(())
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.is_ready
    }
}

fn db_rows_size(rows: &[Row]) -> usize {
    rows.iter().map(|key| key.len()).sum()
}

fn index_single_block(
    index: &Index,
    block_hash: BlockHash,
    block: SerBlock,
    height: usize,
    batch: &mut WriteBatch,
    initial_sync_done: bool,
) {
    struct IndexBlockVisitor<'a> {
        index: &'a Index,
        batch: &'a mut WriteBatch,
        height: usize,
        initial_sync_done: bool,
    }

    impl<'a> Visitor for IndexBlockVisitor<'a> {
        fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
            let txid = bsl_txid(tx);
            self.batch
                .txid_rows
                .push(TxidRow::row(txid, self.height).to_db_row());

            ControlFlow::Continue(())
        }

        fn visit_tx_out(&mut self, _vout: usize, tx_out: &bsl::TxOut) -> ControlFlow<()> {
            let script = bitcoin::Script::from_bytes(tx_out.script_pubkey());
            // skip indexing unspendable outputs
            if !script.is_provably_unspendable() {
                let row = ScriptHashRow::row(ScriptHash::new(script), self.height);
                self.batch.funding_rows.push(row.to_db_row());
            }
            ControlFlow::Continue(())
        }

        fn visit_tx_in(&mut self, _vin: usize, tx_in: &bsl::TxIn) -> ControlFlow<()> {
            let prevout: OutPoint = tx_in.prevout().into();

            // skip indexing coinbase transactions' input
            if prevout.is_null() {
                return ControlFlow::Continue(());
            }

            let row = SpendingPrefixRow::row(prevout, self.height);
            self.batch.spending_rows.push(row.to_db_row());

            // if self.initial_sync_done {
            if true {
                return ControlFlow::Continue(());
            }

            let prev_tx_script_pubkey = &self
                .index
                .store
                .read_outpoint_script(SpendingPrefixRow::scan_prefix(prevout));

            if prev_tx_script_pubkey.is_empty() {
                return ControlFlow::Continue(());
            }

            let prev_tx_script_pubkey = &prev_tx_script_pubkey[0];

            let prevout_script_pubkey =
                bitcoin::Script::from_bytes(&prev_tx_script_pubkey).to_owned();

            if prevout_script_pubkey.is_empty() || !prevout_script_pubkey.is_p2tr() {
                return ControlFlow::Continue(());
            }

            let prev_txid = Txid::from_slice(&prevout.txid[..]).unwrap();
            let prev_block_hash = self.index.filter_by_txid(prev_txid).next();
            let prev_block_height = prev_block_hash.and_then(|block_hash| {
                self.index
                    .chain
                    .get_block_height(&block_hash)
                    .and_then(|height| u64::try_from(height).ok().and_then(|height| Some(height)))
            });
            let prev_get_tweaks = prev_block_height
                .and_then(|height| Some(self.index.store.read_tweaks(height, 1).into_iter()));

            if prev_get_tweaks.is_none() {
                return ControlFlow::Continue(());
            }

            let mut should_update_entry = false;
            let mut value = prev_block_height.unwrap().to_be_bytes().to_vec();

            let _: Vec<_> = prev_get_tweaks
                .unwrap()
                .filter_map(|(_block_height_vec, data)| {
                    if !data.is_empty() {
                        let mut chunk = 0;

                        while data.len() > chunk {
                            let mut txid = [0u8; 32];
                            if data.len() < chunk + 32 {
                                return None;
                            }
                            txid.copy_from_slice(&data[chunk..chunk + 32]);
                            chunk += 32;

                            value.extend(txid);

                            let mut tweak = [0u8; 33];
                            tweak.copy_from_slice(&data[chunk..chunk + 33]);
                            chunk += 33;
                            value.extend(&tweak.to_vec());

                            let mut output_pubkeys_len = [0u8; 8];
                            output_pubkeys_len.copy_from_slice(&data[chunk..chunk + 8]);
                            chunk += 8;

                            let chunk_size = 46;

                            let mut output_pubkeys: Vec<u8> = Vec::new();

                            data[chunk..]
                                .chunks(u64::from_be_bytes(output_pubkeys_len) as usize)
                                .next()?
                                .chunks(chunk_size)
                                .for_each(|pubkey| {
                                    let mut pubkey_chunk = 0;

                                    let mut vout = [0u8; 4];
                                    if pubkey.len() < 4 {
                                        return;
                                    }
                                    vout.copy_from_slice(&pubkey[..4]);
                                    pubkey_chunk += 4;

                                    let mut amount = [0u8; 8];
                                    amount.copy_from_slice(&pubkey[pubkey_chunk..pubkey_chunk + 8]);
                                    pubkey_chunk += 8;

                                    let pubkey_hex = &pubkey[pubkey_chunk + 2..];
                                    pubkey_chunk += 34;
                                    chunk += pubkey_chunk;

                                    let output_pubkey = {
                                        if u32::from_be_bytes(vout).to_string()
                                            == prevout.vout.to_string()
                                            && prevout_script_pubkey
                                                .to_hex_string()
                                                .rfind(pubkey_hex.as_hex().to_string().as_str())
                                                == Some(4)
                                        {
                                            should_update_entry = true;
                                            None
                                        } else {
                                            Some(pubkey.to_vec())
                                        }
                                    };

                                    if let Some(output_pubkey) = output_pubkey {
                                        output_pubkeys.extend(output_pubkey);
                                    }
                                });

                            let should_skip = {
                                if should_update_entry {
                                    output_pubkeys.is_empty()
                                } else {
                                    false
                                }
                            };

                            if !should_skip {
                                value.extend(output_pubkeys.len().to_be_bytes());
                                value.extend(output_pubkeys);
                            }
                        }

                        Some(())
                    } else {
                        None
                    }
                })
                .collect();

            if should_update_entry == true {
                self.batch.tweak_rows.push(value.into_boxed_slice());
            };
            ControlFlow::Continue(())
        }

        fn visit_block_header(&mut self, header: &bsl::BlockHeader) -> ControlFlow<()> {
            match bitcoin::block::Header::consensus_decode(&mut header.as_ref()) {
                Ok(header) => {
                    self.batch
                        .header_rows
                        .push(HeaderRow::new(header).to_db_row());
                }
                Err(_) => {}
            };
            ControlFlow::Continue(())
        }
    }

    let mut index_block = IndexBlockVisitor {
        index,
        batch,
        height,
        initial_sync_done,
    };
    match bsl::Block::visit(&block, &mut index_block) {
        Ok(_) => {}
        Err(_) => {}
    };
    batch.tip_row = serialize(&block_hash).into_boxed_slice();
}

fn scan_single_block_for_silent_payments(
    daemon: &Daemon,
    block_height: usize,
    block_hash: BlockHash,
    block: SerBlock,
    batch: &mut WriteBatch,
    min_dust: u64,
) {
    struct IndexBlockVisitor<'a> {
        daemon: &'a Daemon,
        min_dust: u64,
        value: &'a mut Vec<u8>,
        tx_index: usize,
    }

    impl<'a> Visitor for IndexBlockVisitor<'a> {
        fn visit_transaction(&mut self, tx: &bsl::Transaction) -> core::ops::ControlFlow<()> {
            info!("tx_index: {}", self.tx_index);
            self.tx_index += 1;
            let parsed_tx = match deserialize::<bitcoin::Transaction>(tx.as_ref()) {
                Ok(parsed_tx) => parsed_tx,
                Err(_) => return ControlFlow::Continue(()),
            };

            if parsed_tx.is_coinbase() {
                return ControlFlow::Continue(());
            };

            let txid = bsl_txid(tx);
            info!("txid: {}", txid);

            let output_pubkeys = Arc::new(Mutex::new(Vec::with_capacity(parsed_tx.output.len())));

            let i = Mutex::new(0);
            parsed_tx.output.clone().into_par_iter().for_each(|o| {
                let amount = o.value.to_sat();
                if o.script_pubkey.is_p2tr() && amount >= self.min_dust {
                    let is_unspent = self
                        .daemon
                        .get_tx_out(&txid, *i.lock().unwrap())
                        .ok()
                        .and_then(|result| result);

                    if !is_unspent.is_none() {
                        output_pubkeys
                            .lock()
                            .unwrap()
                            .extend(i.lock().unwrap().to_be_bytes());
                        output_pubkeys.lock().unwrap().extend(amount.to_be_bytes());
                        output_pubkeys
                            .lock()
                            .unwrap()
                            .extend(o.script_pubkey.to_bytes());
                    }
                }
                *i.lock().unwrap() += 1;
            });

            if output_pubkeys.lock().unwrap().is_empty() {
                return ControlFlow::Continue(());
            }

            let pubkeys = Arc::new(Mutex::new(Vec::with_capacity(parsed_tx.input.len())));
            let outpoints = Arc::new(Mutex::new(Vec::with_capacity(parsed_tx.input.len())));

            info!("Itering");
            parsed_tx.input.clone().into_par_iter().for_each(|i| {
                let prev_txid = i.previous_output.txid;
                let prev_vout = i.previous_output.vout;

                let prev_tx: bitcoin::Transaction = self
                    .daemon
                    .get_transaction(&prev_txid, None)
                    .expect("Spending non existent UTXO");
                let index: usize = prev_vout.try_into().expect("Unexpectedly high vout");
                let prevout: &bitcoin::TxOut = prev_tx
                    .output
                    .get(index)
                    .expect("Spending a non existent UTXO");
                match crate::sp::get_pubkey_from_input(&crate::sp::VinData {
                    script_sig: i.script_sig.to_bytes(),
                    txinwitness: i.witness.to_vec(),
                    script_pub_key: prevout.script_pubkey.to_bytes(),
                }) {
                    Ok(Some(pubkey)) => {
                        outpoints
                            .lock()
                            .unwrap()
                            .push((prev_txid.to_string(), prev_vout));
                        pubkeys.lock().unwrap().push(pubkey)
                    }
                    Ok(None) => (),
                    Err(_) => {}
                }
            });

            let binding = pubkeys.lock().unwrap();
            let pubkeys_ref: Vec<&PublicKey> = binding.iter().collect();

            if !pubkeys_ref.is_empty() {
                info!("Tweaking");
                if let Some(tweak) =
                    recipient_calculate_tweak_data(&pubkeys_ref, &outpoints.lock().unwrap()).ok()
                {
                    let mut txid_value = [0u8; 32];
                    txid_value.copy_from_slice(&txid[..]);
                    txid_value.reverse();

                    self.value.extend(txid_value);
                    self.value.extend(&Vec::from_iter(tweak.serialize()));

                    let outputs = output_pubkeys.lock().unwrap().clone();
                    self.value.extend(outputs.len().to_be_bytes());
                    self.value.extend(outputs);
                }
            }

            info!("Complete");
            ControlFlow::Continue(())
        }
    }

    let mut value = block_height.to_be_bytes().to_vec();
    let tx_index = 0;

    let mut index_block = IndexBlockVisitor {
        daemon,
        value: &mut value,
        min_dust,
        tx_index,
    };
    match bsl::Block::visit(&block, &mut index_block) {
        Ok(_) => {}
        Err(_) => {}
    };

    batch.tweak_rows.push(value.into_boxed_slice());
    batch.sp_tip_row = serialize(&block_hash).into_boxed_slice();
}
