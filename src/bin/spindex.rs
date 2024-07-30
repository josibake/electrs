use clap::Parser;
use libbitcoinkernel_sys::{
    BlockManagerOptions, ChainType, ChainstateLoadOptions, ChainstateManager,
    ChainstateManagerOptions,
};
use rayon::prelude::*;
use std::path::PathBuf;

use electrs::db::{DBStore, WriteBatch};
use electrs::index::scan_single_block_for_silent_payments_without_daemon;
use electrs::kernel::{create_context, setup_logging};
use log::info;

/// CLI tool for rebuilding the silent payment index. Note: requires that bitcoind is offline
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Data directory
    #[arg(long)]
    datadir: String,

    /// Electrs DB
    #[arg(long)]
    db: String,

    /// Network
    #[arg(long)]
    network: String,

    /// Birthday
    #[arg(long)]
    birthday: i32,
}

fn main() {
    let args = Args::parse();
    let chain_type = match args.network.to_lowercase().as_str() {
        "mainnet" => ChainType::MAINNET,
        "testnet" => ChainType::TESTNET,
        "regtest" => ChainType::REGTEST,
        "signet" => ChainType::SIGNET,
        _ => {
            eprintln!("Invalid network type: {}", args.network);
            std::process::exit(1);
        }
    };
    let data_dir = args.datadir;
    let blocks_dir = data_dir.clone() + "/blocks";

    // Set up the kernel
    let _ = setup_logging().unwrap();
    let context = create_context(chain_type);
    let chainman = ChainstateManager::new(
        ChainstateManagerOptions::new(&context, &data_dir).unwrap(),
        BlockManagerOptions::new(&context, &blocks_dir).unwrap(),
        &context,
    )
    .unwrap();
    chainman
        .load_chainstate(
            ChainstateLoadOptions::new()
                .set_chainstate_readonly(true)
                .unwrap(),
        )
        .unwrap();
    chainman.import_blocks().unwrap();

    // Open the database
    let store = DBStore::open(&PathBuf::from(args.db), None, false).unwrap();
    let batch_size = 2000;
    let block_numbers = args.birthday..chainman.get_block_index_tip().info().height;
    block_numbers
        .collect::<Vec<_>>()
        .chunks(batch_size)
        .for_each(|chunk| {
            info!("indexing blocks {:?} to {:?}", chunk.first(), chunk.last(),);
            let mut batch = WriteBatch::default();
            chunk.par_iter().for_each(|&height| {
                let block_index = chainman.get_block_index_by_height(height).unwrap();
                let raw_block: Vec<u8> = chainman.read_block_data(&block_index).unwrap().into();
                let undo = chainman.read_undo_data(&block_index).unwrap();
                scan_single_block_for_silent_payments_without_daemon(
                    height as usize,
                    raw_block,
                    undo,
                    &mut batch,
                    546,
                );
            });
            store.write(&batch);
        });
}
