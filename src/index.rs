use anyhow::{Context, Result};
use bitcoin::consensus::{deserialize, serialize, Decodable};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, OutPoint, Txid};
use bitcoin_slices::{bsl, Visit, Visitor};
use rayon::prelude::*;
use silentpayments::utils::receiving::recipient_calculate_tweak_data;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};

use crate::sp::{TweakBlockData, TweakData, VoutData};
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
    initial_sync_done: bool,
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
            initial_sync_done: false,
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
        let start: usize;
        let initial_height = sp_begin_height.unwrap_or(70_000);

        if let Some(sp_skip_height) = sp_skip_height {
            start = sp_skip_height;
        } else {
            if let Some(row) = self.store.last_sp() {
                let blockhash = deserialize::<BlockHash>(&row).ok().and_then(|blockhash| {
                    Some(
                        self.chain
                            .get_block_height(&blockhash)
                            .unwrap_or(initial_height - 1)
                            + 1,
                    )
                });

                if let Some(blockhash) = blockhash {
                    start = blockhash;
                } else {
                    start = self
                        .store
                        .read_last_tweak()
                        .into_iter()
                        .filter_map(|(blockhash, _)| {
                            Some(
                                deserialize::<BlockHash>(&blockhash)
                                    .ok()
                                    .and_then(|blockhash| {
                                        Some(
                                            self.chain
                                                .get_block_height(&blockhash)
                                                .unwrap_or(initial_height - 1)
                                                + 1,
                                        )
                                    })
                                    .unwrap_or(initial_height),
                            )
                        })
                        .collect::<Vec<_>>()[0];
                }
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
                .unwrap_or(546);

            self.sync_blocks(daemon, &[new_header], true, min_dust)?;
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

        self.flush_needed = true;
        Ok(false) // sync is not done
    }

    pub(crate) fn get_tweaks(&self, height: usize, count: usize) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        let _: Vec<_> = self
            .store
            .read_tweaks(height as u64, count as u64)
            .into_iter()
            .filter_map(|(key, data)| {
                if !data.is_empty() {
                    let tweak_block_data =
                        TweakBlockData::from_boxed_slice(key.clone(), data.clone());
                    let mut block_response_map = serde_json::Map::new();

                    for tweak_data in tweak_block_data.tx_data {
                        let mut tx_response_map = serde_json::Map::new();

                        tx_response_map.insert(
                            "tweak".to_string(),
                            serde_json::Value::String(tweak_data.tweak.to_string()),
                        );
                        tx_response_map.insert(
                            "output_pubkeys".to_string(),
                            serde_json::Value::Object(serde_json::Map::new()),
                        );

                        if let Some(vout_map) = tx_response_map.get_mut("output_pubkeys") {
                            if let Some(vout_map) = vout_map.as_object_mut() {
                                for vout in tweak_data.vout_data {
                                    vout_map.insert(
                                        vout.vout.to_string(),
                                        serde_json::Value::Array(vec![
                                            serde_json::Value::String(
                                                vout.script_pub_key
                                                    .to_hex_string()
                                                    .replace("5120", ""),
                                            ),
                                            serde_json::Value::Number(vout.amount.into()),
                                        ]),
                                    );
                                }
                            }
                        }

                        block_response_map.insert(
                            tweak_data.txid.to_string(),
                            serde_json::Value::Object(tx_response_map),
                        );
                    }

                    map.insert(
                        height.to_string(),
                        serde_json::Value::Object(block_response_map),
                    );

                    Some(())
                } else {
                    None
                }
            })
            .collect();

        serde_json::Value::Object(map)
    }

    // Return `Ok(true)` when the chain is fully synced and the index is compacted.
    pub(crate) fn sync(
        &mut self,
        daemon: &Daemon,
        exit_flag: &ExitFlag,
        sp_min_dust: Option<usize>,
    ) -> Result<bool> {
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
                if !self.initial_sync_done {
                    self.initial_sync_done = true;
                }
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
            let min_dust = sp_min_dust
                .and_then(|dust| u64::try_from(dust).ok())
                .unwrap_or(0);

            self.sync_blocks(daemon, chunk, false, min_dust)?;
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
    ) -> Result<()> {
        let blockhashes: Vec<BlockHash> = chunk.iter().map(|h| h.hash()).collect();
        let mut heights = chunk.iter().map(|h| h.height());
        let mut batch = WriteBatch::default();

        if !sp {
            let scan_block = |blockhash, block| {
                if let Some(height) = heights.next() {
                    self.stats.observe_duration("block", || {
                        index_single_block(
                            self, daemon, blockhash, block, height, &mut batch, min_dust,
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
    daemon: &Daemon,
    block_hash: BlockHash,
    block: SerBlock,
    height: usize,
    batch: &mut WriteBatch,
    min_dust: u64,
) {
    struct IndexBlockVisitor<'a> {
        index: &'a Index,
        daemon: &'a Daemon,
        batch: &'a mut WriteBatch,
        height: usize,
        min_dust: u64,
    }

    impl<'a> Visitor for IndexBlockVisitor<'a> {
        fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
            let txid = bsl_txid(tx);
            self.batch
                .txid_rows
                .push(TxidRow::row(txid, self.height).to_db_row());

            if !self.index.initial_sync_done {
                return ControlFlow::Continue(());
            }

            let parsed_tx = match deserialize::<bitcoin::Transaction>(tx.as_ref()) {
                Ok(parsed_tx) => parsed_tx,
                Err(_) => return ControlFlow::Continue(()),
            };

            if parsed_tx.is_coinbase() {
                return ControlFlow::Continue(());
            };

            for i in parsed_tx.input.iter() {
                let prev_txid = i.previous_output.txid;
                let prev_vout = i.previous_output.vout;

                let prev_tx = self.daemon.get_transaction(&prev_txid, None).ok();
                let prevout: Option<bitcoin::TxOut> = prev_tx.and_then(|prev_tx| {
                    let index: Option<usize> = prev_vout.try_into().ok();
                    index.and_then(move |index| prev_tx.output.get(index).cloned())
                });

                if let None = prevout {
                    continue;
                }

                let prevout = prevout.unwrap();

                if !prevout.script_pubkey.is_p2tr() || prevout.value.to_sat() < self.min_dust {
                    continue;
                }

                let prev_block_hash: Option<String> = self
                    .daemon
                    .get_transaction_info(&prev_txid, None)
                    .ok()
                    .and_then(|info| {
                        info.get("blockhash")
                            .and_then(|hash| hash.as_str())
                            .map(|s| s.to_string())
                    });
                let prev_block_height = prev_block_hash.and_then(|hash| {
                    self.daemon
                        .get_block(hash)
                        .ok()
                        .and_then(|info| info.get("height").and_then(|height| height.as_u64()))
                });
                let prev_get_tweaks = prev_block_height
                    .and_then(|height| Some(self.index.store.read_tweaks(height, 1).into_iter()));

                if prev_get_tweaks.is_none() {
                    continue;
                }

                let _: Vec<_> = prev_get_tweaks
                    .unwrap()
                    .filter_map(|(key, data)| {
                        if !data.is_empty() {
                            let mut tweak_block_data =
                                TweakBlockData::from_boxed_slice(key.clone(), data.clone());

                            let mut update_entry = false;

                            tweak_block_data.tx_data.retain(|tweak_data| {
                                let mut new_vout_data = vec![];

                                tweak_data.vout_data.iter().for_each(|vout| {
                                    if vout.vout.to_string() == prev_vout.to_string()
                                        && prevout.script_pubkey.to_hex_string()
                                            == vout.script_pub_key.to_hex_string()
                                    {
                                        // Found an output being used in this tx as input, should
                                        // update tweak db
                                        update_entry = true;
                                    } else {
                                        new_vout_data.push(vout.clone().to_owned());
                                    }
                                });

                                if new_vout_data.len() > 0 {
                                    true
                                } else {
                                    false
                                }
                            });

                            if update_entry {
                                self.batch
                                    .tweak_rows
                                    .push(tweak_block_data.clone().into_boxed_slice());
                            }

                            Some(())
                        } else {
                            None
                        }
                    })
                    .collect();
            }

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
        daemon,
        batch,
        height,
        min_dust,
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
        tweak_block_data: &'a mut TweakBlockData,
    }

    impl<'a> Visitor for IndexBlockVisitor<'a> {
        fn visit_transaction(&mut self, tx: &bsl::Transaction) -> core::ops::ControlFlow<()> {
            let parsed_tx = match deserialize::<bitcoin::Transaction>(tx.as_ref()) {
                Ok(parsed_tx) => parsed_tx,
                Err(_) => return ControlFlow::Continue(()),
            };

            if parsed_tx.is_coinbase() {
                return ControlFlow::Continue(());
            };

            let txid = bsl_txid(tx);
            let output_pubkeys: Arc<Mutex<Vec<VoutData>>> =
                Arc::new(Mutex::new(Vec::with_capacity(parsed_tx.output.len())));

            let i = Mutex::new(0);
            parsed_tx.output.clone().into_par_iter().for_each(|o| {
                let amount = o.value.to_sat();
                if o.script_pubkey.is_p2tr() && amount >= self.min_dust {
                    let unspent_response = self
                        .daemon
                        .get_tx_out(&txid, *i.lock().unwrap())
                        .ok()
                        .and_then(|result| result);
                    let is_unspent = !unspent_response.is_none();

                    if is_unspent {
                        output_pubkeys.lock().unwrap().push(VoutData {
                            vout: *i.lock().unwrap(),
                            amount,
                            script_pub_key: o.script_pubkey,
                        });
                    }
                }
                *i.lock().unwrap() += 1;
            });

            if output_pubkeys.lock().unwrap().is_empty() {
                return ControlFlow::Continue(());
            }

            let pubkeys = Arc::new(Mutex::new(Vec::with_capacity(parsed_tx.input.len())));
            let outpoints = Arc::new(Mutex::new(Vec::with_capacity(parsed_tx.input.len())));

            parsed_tx.input.clone().into_par_iter().for_each(|i| {
                let prev_txid = i.previous_output.txid;
                let prev_vout = i.previous_output.vout;

                let prev_tx = self.daemon.get_transaction(&prev_txid, None).ok();
                let prevout: Option<bitcoin::TxOut> = prev_tx.and_then(|prev_tx| {
                    let index: Option<usize> = prev_vout.try_into().ok();
                    index.and_then(move |index| prev_tx.output.get(index).cloned())
                });

                if let Some(prevout) = prevout {
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
                }
            });

            let binding = pubkeys.lock().unwrap();
            let pubkeys_ref: Vec<&PublicKey> = binding.iter().collect();

            if !pubkeys_ref.is_empty() {
                if let Some(tweak) =
                    recipient_calculate_tweak_data(&pubkeys_ref, &outpoints.lock().unwrap()).ok()
                {
                    self.tweak_block_data.tx_data.push(TweakData {
                        txid,
                        tweak,
                        vout_data: output_pubkeys.lock().unwrap().to_vec(),
                    });
                }
            }

            ControlFlow::Continue(())
        }
    }

    if let Some(height) = u64::try_from(block_height).ok() {
        let mut tweak_block_data = TweakBlockData::new(height);

        let mut index_block = IndexBlockVisitor {
            daemon,
            tweak_block_data: &mut tweak_block_data,
            min_dust,
        };
        match bsl::Block::visit(&block, &mut index_block) {
            Ok(_) => {}
            Err(_) => {}
        };

        batch.tweak_rows.push(tweak_block_data.into_boxed_slice());
        batch.sp_tip_row = serialize(&block_hash).into_boxed_slice();
    }
}
