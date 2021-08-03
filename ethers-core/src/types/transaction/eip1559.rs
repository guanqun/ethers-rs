use super::{eip2930::AccessList, rlp_opt};
use crate::{
    types::{Address, Bytes, NameOrAddress, Signature, U256, U64},
};
use rlp::RlpStream;

/// EIP-1559 transactions have 9 fields
const NUM_TX_FIELDS: usize = 9;

use serde::{Deserialize, Serialize};
use bytes::BytesMut;

/// Parameters for sending a transaction
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Eip1559TransactionRequest {
    /// Sender address or ENS name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,

    /// Recipient address (None for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<NameOrAddress>,

    /// Supplied gas (None for sensible default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<U256>,

    /// Transfered value (None for no transfer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,

    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see Ethereum Contract ABI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,

    /// Transaction nonce (None for next available nonce)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,

    #[serde(
        rename = "accessList",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_list: Option<AccessList>,

    #[serde(
        rename = "maxPriorityFeePerGas",
        default,
        skip_serializing_if = "Option::is_none"
    )]

    /// Represents the maximum tx fee that will go to the miner as part of the user's
    /// fee payment. It serves 3 purposes:
    /// 1. Compensates miners for the uncle/ommer risk + fixed costs of including transaction in a block;
    /// 2. Allows users with high opportunity costs to pay a premium to miners;
    /// 3. In times where demand exceeds the available block space (i.e. 100% full, 30mm gas),
    /// this component allows first price auctions (i.e. the pre-1559 fee model) to happen on the priority fee.
    ///
    /// More context [here](https://hackmd.io/@q8X_WM2nTfu6nuvAzqXiTQ/1559-wallets)
    pub max_priority_fee_per_gas: Option<U256>,

    #[serde(
        rename = "maxFeePerGas",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    /// Represents the maximum amount that a user is willing to pay for their tx (inclusive of baseFeePerGas and maxPriorityFeePerGas).
    /// The difference between maxFeePerGas and baseFeePerGas + maxPriorityFeePerGas is “refunded” to the user.
    pub max_fee_per_gas: Option<U256>,

    #[serde(rename = "chainId", default = "U64::one")]
    pub chain_id: U64,
}

impl From<Eip1559TransactionRequest> for super::request::TransactionRequest {
    fn from(tx: Eip1559TransactionRequest) -> Self {
        Self {
            from: tx.from,
            to: tx.to,
            gas: tx.gas,
            gas_price: tx.max_fee_per_gas,
            value: tx.value,
            data: tx.data,
            nonce: tx.nonce,
            #[cfg(feature = "celo")]
            fee_currency: None,
            #[cfg(feature = "celo")]
            gateway_fee_recipient: None,
            #[cfg(feature = "celo")]
            gateway_fee: None,
        }
    }
}

impl Eip1559TransactionRequest {
    /// Creates an empty transaction request with all fields left empty
    pub fn new() -> Self {
        Self::default()
    }

    // Builder pattern helpers

    /// Sets the `from` field in the transaction to the provided value
    pub fn from<T: Into<Address>>(mut self, from: T) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Sets the `to` field in the transaction to the provided value
    pub fn to<T: Into<NameOrAddress>>(mut self, to: T) -> Self {
        self.to = Some(to.into());
        self
    }

    /// Sets the `gas` field in the transaction to the provided value
    pub fn gas<T: Into<U256>>(mut self, gas: T) -> Self {
        self.gas = Some(gas.into());
        self
    }

    /// Sets the `max_priority_fee_per_gas` field in the transaction to the provided value
    pub fn max_priority_fee_per_gas<T: Into<U256>>(mut self, max_priority_fee_per_gas: T) -> Self {
        self.max_priority_fee_per_gas = Some(max_priority_fee_per_gas.into());
        self
    }

    /// Sets the `max_fee_per_gas` field in the transaction to the provided value
    pub fn max_fee_per_gas<T: Into<U256>>(mut self, max_fee_per_gas: T) -> Self {
        self.max_fee_per_gas = Some(max_fee_per_gas.into());
        self
    }

    /// Sets the `value` field in the transaction to the provided value
    pub fn value<T: Into<U256>>(mut self, value: T) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Sets the `data` field in the transaction to the provided value
    pub fn data<T: Into<Bytes>>(mut self, data: T) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Sets the `access_list` field in the transaction to the provided value
    pub fn access_list<T: Into<AccessList>>(mut self, access_list: T) -> Self {
        self.access_list = Some(access_list.into());
        self
    }

    /// Sets the `nonce` field in the transaction to the provided value
    pub fn nonce<T: Into<U256>>(mut self, nonce: T) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the `chain_id` field in the transaction to the provided value
    pub fn chain_id<T: Into<U64>>(mut self, chain_id: T) -> Self {
        self.chain_id = chain_id.into();
        self
    }

    /// Gets the unsigned transaction's RLP encoding
    /// 0x2 | rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, destination, value, data, accessList])
    pub fn rlp_with_buffer<T: Into<U64>>(&self, chain_id: T, buf: BytesMut) -> Bytes {
        assert_eq!(self.chain_id, chain_id.into());

        let mut rlp = RlpStream::new_with_buffer(buf);
        rlp.begin_list(NUM_TX_FIELDS);
        self.rlp_base(&mut rlp);

        rlp.out().freeze().into()
    }

    /// Produces the RLP encoding of the transaction with the provided signature
    /// 0x2 | rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, destination, value, data, accessList, signatureYParity, signatureR, signatureS])
    pub fn rlp_signed_with_buffer(&self, signature: &Signature, buf: BytesMut) -> Bytes {
        let mut rlp = RlpStream::new_with_buffer(buf);
        rlp.begin_list(NUM_TX_FIELDS + 3 /* 3 signed fields */);
        self.rlp_base(&mut rlp);

        // append the signature, v is either 0 or 1
        // assume the signature is calculated in eip155 style.
        let v = signature.v - self.chain_id.as_u64() * 2 - 35;
        rlp.append(&v);
        rlp.append(&signature.r);
        rlp.append(&signature.s);
        rlp.out().freeze().into()
    }

    /// rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, destination, value, data, accessList])
    pub(crate) fn rlp_base(&self, rlp: &mut RlpStream) {
        rlp.append(&self.chain_id);
        rlp_opt(rlp, &self.nonce);
        rlp_opt(rlp, &self.max_priority_fee_per_gas);
        rlp_opt(rlp, &self.max_fee_per_gas);
        rlp_opt(rlp, &self.gas);
        rlp_opt(rlp, &self.to.as_ref());
        rlp_opt(rlp, &self.value);
        rlp_opt(rlp, &self.data.as_ref().map(|d| d.as_ref()));
        rlp.append(&self.access_list);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::transaction::eip2718::TypedTransaction;
    use std::str::FromStr;
    use ethabi::ethereum_types::H256;

    #[test]
    fn test_typed_tx_without_access_list() {
        let tx: Eip1559TransactionRequest = serde_json::from_str(
            r#"{
            "gas": "0x186a0",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x77359400",
            "data": "0x5544",
            "nonce": "0x2",
            "to": "0x96216849c49358B10257cb55b28eA603c874b05E",
            "value": "0x5af3107a4000",
            "type": "0x2",
            "chainId": "0x539",
            "accessList": [],
            "v": "0x1",
            "r": "0xc3000cd391f991169ebfd5d3b9e93c89d31a61c998a21b07a11dc6b9d66f8a8e",
            "s": "0x22cfe8424b2fbd78b16c9911da1be2349027b0a3c40adf4b6459222323773f74"
        }"#).unwrap();

        let envelope = TypedTransaction::Eip1559(tx);

        let expected = H256::from_str("0xa1ea3121940930f7e7b54506d80717f14c5163807951624c36354202a8bffda6").unwrap();
        let actual = envelope.sighash(0x539);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_typed_tx() {
        let tx: Eip1559TransactionRequest = serde_json::from_str(
            r#"{
            "gas": "0x186a0",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x77359400",
            "data": "0x5544",
            "nonce": "0x2",
            "to": "0x96216849c49358B10257cb55b28eA603c874b05E",
            "value": "0x5af3107a4000",
            "type": "0x2",
            "accessList": [
                {
                    "address": "0x0000000000000000000000000000000000000001",
                    "storageKeys": [
                        "0x0100000000000000000000000000000000000000000000000000000000000000"
                    ]
                }
            ],
            "chainId": "0x539",
            "v": "0x1",
            "r": "0xc3000cd391f991169ebfd5d3b9e93c89d31a61c998a21b07a11dc6b9d66f8a8e",
            "s": "0x22cfe8424b2fbd78b16c9911da1be2349027b0a3c40adf4b6459222323773f74"
        }"#).unwrap();

        let envelope = TypedTransaction::Eip1559(tx);

        let expected = H256::from_str("0x090b19818d9d087a49c3d2ecee4829ee4acea46089c1381ac5e588188627466d").unwrap();
        let actual = envelope.sighash(0x539);
        assert_eq!(expected, actual);
    }
}