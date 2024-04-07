use bitcoin::{
    secp256k1::{Parity::Even, PublicKey, XOnlyPublicKey},
    ScriptBuf, Txid,
};
use bitcoin_slices::bitcoin_hashes::{hash160, Hash};

use anyhow::Error;

// ** Putting all the pubkey extraction logic in the test utils for now. **
// NUMS_H (defined in BIP340)
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

// Define OP_CODES used in script template matching for readability
const OP_1: u8 = 0x51;
const OP_0: u8 = 0x00;
const OP_PUSHBYTES_20: u8 = 0x14;
const OP_PUSHBYTES_32: u8 = 0x20;
const OP_HASH160: u8 = 0xA9;
const OP_EQUAL: u8 = 0x87;
const OP_DUP: u8 = 0x76;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xAC;

// Only compressed pubkeys are supported for silent payments
const COMPRESSED_PUBKEY_SIZE: usize = 33;

pub struct VinData {
    pub script_sig: Vec<u8>,
    pub txinwitness: Vec<Vec<u8>>,
    pub script_pub_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct VoutData {
    pub vout: u32,
    pub amount: u64,
    pub script_pub_key: ScriptBuf,
}

#[derive(Clone, Debug)]
pub struct TweakData {
    pub txid: Txid,
    pub tweak: PublicKey,
    pub vout_data: Vec<VoutData>,
}

impl TweakData {
    pub fn from_boxed_slice(data: Box<[u8]>, passed_chunk: &mut usize) -> Option<Self> {
        let data = data.into_vec();

        let mut chunk = passed_chunk.clone();

        let txid_bytes = &data[chunk..chunk + 32];
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);
        let txid = Txid::from_slice(&txid).ok();

        chunk += 32;

        let tweak_bytes = &data[chunk..chunk + 33];
        let mut tweak = [0u8; 33];
        tweak.copy_from_slice(&tweak_bytes);
        let tweak = PublicKey::from_slice(&tweak).ok();

        chunk += 33;

        let vout_data_len_bytes = &data[chunk..chunk + 8];
        let mut vout_data_len = [0u8; 8];
        vout_data_len.copy_from_slice(&vout_data_len_bytes);
        let vout_data_len = u64::from_be_bytes(vout_data_len) as usize;

        chunk += 8;

        let mut vout_data = vec![];

        for _ in 0..vout_data_len {
            let vout_bytes = &data[chunk..chunk + 4];
            let mut vout = [0u8; 4];
            vout.copy_from_slice(&vout_bytes);
            let vout = u32::from_be_bytes(vout);

            chunk += 4;

            let amount_bytes = &data[chunk..chunk + 8];
            let mut amount = [0u8; 8];
            amount.copy_from_slice(&amount_bytes);
            let amount = u64::from_be_bytes(amount);

            chunk += 8;

            let script_pub_key_bytes = &data[chunk..chunk + 34];
            let mut script_pub_key = [0u8; 34];
            script_pub_key.copy_from_slice(&script_pub_key_bytes);
            let script_pub_key = ScriptBuf::from_bytes(script_pub_key.to_vec());

            chunk += 34;

            vout_data.push(VoutData {
                vout,
                amount,
                script_pub_key,
            });
        }

        *passed_chunk = chunk;

        if let Some(txid) = txid {
            if let Some(tweak) = tweak {
                return Some(Self {
                    txid,
                    tweak,
                    vout_data,
                });
            }
        }

        None
    }

    pub fn to_be_bytes(self) -> Vec<u8> {
        let mut data = vec![];
        data.extend_from_slice(&self.txid.as_ref());
        data.extend_from_slice(&self.tweak.serialize());

        let vout_data = self.vout_data;

        data.extend_from_slice(&vout_data.len().to_be_bytes());

        for vout in vout_data {
            data.extend_from_slice(&vout.vout.to_be_bytes());
            data.extend_from_slice(&vout.amount.to_be_bytes());
            data.extend_from_slice(&vout.script_pub_key.as_bytes());
        }

        data
    }
}

#[derive(Clone, Debug)]
pub struct TweakBlockData {
    pub block_height: u64,
    pub tx_data: Vec<TweakData>,
}

impl TweakBlockData {
    pub fn new(block_height: u64) -> Self {
        Self {
            block_height,
            tx_data: vec![],
        }
    }

    pub fn from_boxed_slice(key: Box<[u8]>, data: Box<[u8]>) -> Self {
        let data = data.into_vec();

        let block_height_bytes = &key[..];
        let mut block_height = [0u8; 8];
        block_height.copy_from_slice(&block_height_bytes);
        let block_height = u64::from_be_bytes(block_height);

        let mut result = Self::new(block_height);
        let mut chunk = 0;

        while data.len() > chunk {
            if let Some(tweak_data) =
                TweakData::from_boxed_slice(data.clone().into_boxed_slice(), &mut chunk)
            {
                result.tx_data.push(tweak_data);
            }
        }

        result
    }

    pub fn into_boxed_slice(self) -> Box<[u8]> {
        let mut data = vec![];
        data.extend_from_slice(&self.block_height.to_be_bytes());
        for tweak in self.tx_data {
            data.extend_from_slice(&tweak.to_be_bytes());
        }

        data.into_boxed_slice()
    }
}

// script templates for inputs allowed in BIP352 shared secret derivation
pub fn is_p2tr(spk: &[u8]) -> bool {
    matches!(spk, [OP_1, OP_PUSHBYTES_32, ..] if spk.len() == 34)
}

fn is_p2wpkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_0, OP_PUSHBYTES_20, ..] if spk.len() == 22)
}

fn is_p2sh(spk: &[u8]) -> bool {
    matches!(spk, [OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUAL] if spk.len() == 23)
}

fn is_p2pkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_DUP, OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUALVERIFY, OP_CHECKSIG] if spk.len() == 25)
}

pub fn get_pubkey_from_input(vin: &VinData) -> Result<Option<PublicKey>, Error> {
    if is_p2pkh(&vin.script_pub_key) {
        match (&vin.txinwitness.is_empty(), &vin.script_sig.is_empty()) {
            (true, false) => {
                let spk_hash = &vin.script_pub_key[3..23];
                for i in (COMPRESSED_PUBKEY_SIZE..=vin.script_sig.len()).rev() {
                    if let Some(pubkey_bytes) = &vin.script_sig.get(i - COMPRESSED_PUBKEY_SIZE..i) {
                        let pubkey_hash = hash160::Hash::hash(pubkey_bytes);
                        if pubkey_hash.to_byte_array() == spk_hash {
                            return Ok(Some(PublicKey::from_slice(pubkey_bytes)?));
                        }
                    } else {
                        return Ok(None);
                    }
                }
            }
            (_, true) => return Err(Error::msg("Empty script_sig for spending a p2pkh")),
            (false, _) => return Err(Error::msg("non empty witness for spending a p2pkh")),
        }
    } else if is_p2sh(&vin.script_pub_key) {
        match (&vin.txinwitness.is_empty(), &vin.script_sig.is_empty()) {
            (false, false) => {
                let redeem_script = &vin.script_sig[1..];
                if is_p2wpkh(redeem_script) {
                    if let Some(value) = vin.txinwitness.last() {
                        if let Ok(pubkey) = PublicKey::from_slice(value) {
                            return Ok(Some(pubkey));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }
            (_, true) => {
                return Err(Error::msg(
                    "Empty script_sig for spending a p2sh".to_owned(),
                ))
            }
            (true, false) => {
                return Ok(None);
            }
        }
    } else if is_p2wpkh(&vin.script_pub_key) {
        match (&vin.txinwitness.is_empty(), &vin.script_sig.is_empty()) {
            (false, true) => {
                if let Some(value) = vin.txinwitness.last() {
                    if let Ok(pubkey) = PublicKey::from_slice(value) {
                        return Ok(Some(pubkey));
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Err(Error::msg("Empty witness".to_owned()));
                }
            }
            (_, false) => {
                return Err(Error::msg(
                    "Non empty script sig for spending a segwit output".to_owned(),
                ))
            }
            (true, _) => {
                return Err(Error::msg(
                    "Empty witness for spending a segwit output".to_owned(),
                ))
            }
        }
    } else if is_p2tr(&vin.script_pub_key) {
        match (&vin.txinwitness.is_empty(), &vin.script_sig.is_empty()) {
            (false, true) => {
                // check for the optional annex
                let annex = match vin.txinwitness.last().and_then(|value| value.get(0)) {
                    Some(&0x50) => 1,
                    Some(_) => 0,
                    None => return Err(Error::msg("Empty or invalid witness".to_owned())),
                };

                // Check for script path
                let stack_size = vin.txinwitness.len();
                if stack_size > annex && vin.txinwitness[stack_size - annex - 1][1..33] == NUMS_H {
                    return Ok(None);
                }

                // Return the pubkey from the script pubkey
                return XOnlyPublicKey::from_slice(&vin.script_pub_key[2..34])
                    .map_err(|e| Error::new(e))
                    .map(|x_only_public_key| {
                        Some(PublicKey::from_x_only_public_key(x_only_public_key, Even))
                    });
            }
            (_, false) => {
                return Err(Error::msg(
                    "Non empty script sig for spending a segwit output".to_owned(),
                ))
            }
            (true, _) => {
                return Err(Error::msg(
                    "Empty witness for spending a segwit output".to_owned(),
                ))
            }
        }
    }
    return Ok(None);
}

// pub fn sender_get_a_sum_secret_keys(input: &Vec<(SecretKey, bool)>) -> SecretKey {
//     let secp = secp256k1::Secp256k1::new();

//     let mut negated_keys: Vec<SecretKey> = vec![];

//     for (key, is_xonly) in input {
//         let (_, parity) = key.x_only_public_key(&secp);

//         if *is_xonly && parity == secp256k1::Parity::Odd {
//             negated_keys.push(key.negate());
//         } else {
//             negated_keys.push(key.clone());
//         }
//     }

//     let (head, tail) = negated_keys.split_first().unwrap();

//     let result: SecretKey = tail
//         .iter()
//         .fold(*head, |acc, &item| acc.add_tweak(&item.into()).unwrap());

//     result
// }
