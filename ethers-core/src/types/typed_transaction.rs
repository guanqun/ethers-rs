use super::transaction::SIGNED_TX_FIELDS;
use crate::{
    types::{Address, Bytes, Signature, TransactionRequest, H256, U64, U256},
    utils::keccak256,
};

use rlp::RlpStream;
use rlp_derive::RlpEncodable;
use serde::{Deserialize, Serialize};
use crate::types::NameOrAddress;

const NUM_EIP2930_FIELDS: usize = SIGNED_TX_FIELDS + 1;

/// Access list
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable)]
pub struct AccessList(Vec<AccessListItem>);

impl From<Vec<AccessListItem>> for AccessList {
    fn from(src: Vec<AccessListItem>) -> AccessList {
        AccessList(src)
    }
}

/// Access list item
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    /// Accessed address
    pub address: Address,
    /// Accessed storage keys
    pub storage_keys: Vec<H256>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "type")]
pub enum TransactionEnvelope {
    /// 0x00
    #[serde(rename = "0x00")]
    Legacy(TransactionRequest),
    /// 0x01
    #[serde(rename = "0x01")]
    AccessList(AccessListTransactionRequest),
    /// 0x02
    #[serde(rename = "0x02")]
    DynamicFee(DynamicFeeTransactionRequest),
}

impl TransactionEnvelope {
    /// Hashes the transaction's data with the provided chain id
    pub fn sighash<T: Into<U64>>(&self, chain_id: Option<T>) -> H256 {
        let encoded = match self {
            TransactionEnvelope::Legacy(ref tx) => {
                let mut encoded = vec![0];
                encoded.extend_from_slice(tx.rlp(chain_id).as_ref());
                encoded
            }
            TransactionEnvelope::AccessList(ref tx) => {
                let mut encoded = vec![1];
                encoded.extend_from_slice(tx.rlp(chain_id.expect("expect chain_id set")).as_ref());
                encoded
            }
            TransactionEnvelope::DynamicFee(ref tx) => {
                let mut encoded = vec![2];
                encoded.extend_from_slice(tx.rlp(chain_id).as_ref());
                encoded
            }
        };
        keccak256(encoded).into()
    }
}

impl From<TransactionRequest> for TransactionEnvelope {
    fn from(src: TransactionRequest) -> TransactionEnvelope {
        TransactionEnvelope::Legacy(src)
    }
}

impl From<AccessListTransactionRequest> for TransactionEnvelope {
    fn from(src: AccessListTransactionRequest) -> TransactionEnvelope {
        TransactionEnvelope::AccessList(src)
    }
}

impl From<DynamicFeeTransactionRequest> for TransactionEnvelope {
    fn from(src: DynamicFeeTransactionRequest) -> TransactionEnvelope {
        TransactionEnvelope::DynamicFee(src)
    }
}

/// An EIP-2930 transaction is a legacy transaction including an [`AccessList`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct AccessListTransactionRequest {
    #[serde(flatten)]
    pub tx: TransactionRequest,
    pub access_list: AccessList,
}

impl AccessListTransactionRequest {
    pub fn new(tx: TransactionRequest, access_list: AccessList) -> Self {
        Self { tx, access_list }
    }

    pub fn rlp<T: Into<U64>>(&self, chain_id: T) -> Bytes {
        let mut rlp = RlpStream::new();
        rlp.begin_list(NUM_EIP2930_FIELDS);
        self.tx.rlp_base(&mut rlp);

        // append the access list in addition to the base rlp encoding
        rlp.append(&self.access_list);

        // append the signature fields
        rlp.append(&chain_id.into());
        rlp.append(&0u8);
        rlp.append(&0u8);
        rlp.out().freeze().into()
    }

    /// Produces the RLP encoding of the transaction with the provided signature
    pub fn rlp_signed(&self, signature: &Signature) -> Bytes {
        let mut rlp = RlpStream::new();
        rlp.begin_list(NUM_EIP2930_FIELDS);
        self.tx.rlp_base(&mut rlp);

        // append the access list in addition to the base rlp encoding
        rlp.append(&self.access_list);

        // append the signature
        rlp.append(&signature.v);
        rlp.append(&signature.r);
        rlp.append(&signature.s);
        rlp.out().freeze().into()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct DynamicFeeTransactionRequest {
    /// Sender address or ENS name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,

    /// Recipient address (None for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<NameOrAddress>,

    /// Supplied gas (None for sensible default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<U256>,

    /// Transffered value (None for no transfer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,

    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see Ethereum Contract ABI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,

    /// Transaction nonce (None for next available nonce)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,

    pub access_list: AccessList,

    pub max_priority_fee_per_gas: U256,

    pub max_fee_per_gas: U256,
}

impl DynamicFeeTransactionRequest {
    /// Creates an empty transaction request with all fields left empty
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience function for sending a new payment transaction to the receiver.
    pub fn pay<T: Into<NameOrAddress>, V: Into<U256>>(to: T, value: V) -> Self {
        Self {
            to: Some(to.into()),
            value: Some(value.into()),
            ..Default::default()
        }
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

    /// Sets the `nonce` field in the transaction to the provided value
    pub fn nonce<T: Into<U256>>(mut self, nonce: T) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the `from` field in the transaction to the provided value
    pub fn access_list<T: Into<AccessList>>(
        mut self,
        access_list: T,
    ) -> Self {
        self.access_list = access_list.into();
        self
    }

    /// Sets the `max_priority_fee_per_gas` field in the transaction to the provided value
    pub fn max_priority_fee_per_gas<T: Into<U256>>(mut self, max_priority_fee_per_gas: T) -> Self {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas.into();
        self
    }

    /// Sets the `max_fee_per_gas` field in the transaction to the provided value
    pub fn max_fee_per_gas<T: Into<U256>>(mut self, max_fee_per_gas: T) -> Self {
        self.max_fee_per_gas = max_fee_per_gas.into();
        self
    }

    /// rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, destination, value, data, accessList])
    pub fn rlp<T: Into<U64>>(&self, chain_id: Option<T>) -> Bytes {
        let mut rlp = RlpStream::new();
        rlp.begin_list(9);

        rlp.append(&chain_id.map_or(U64::zero(), |id| id.into()));
        rlp_opt(&mut rlp, self.nonce);
        rlp.append(&self.max_priority_fee_per_gas);
        rlp.append(&self.max_fee_per_gas);
        rlp_opt(&mut rlp, self.gas);
        rlp_opt(&mut rlp, self.to.as_ref());
        rlp_opt(&mut rlp, self.value);
        rlp_opt(&mut rlp, self.data.as_ref().map(|d| d.as_ref()));
        rlp.append(&self.access_list);

        rlp.out().freeze().into()
    }

    /// rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, destination, value, data, accessList, signatureYParity, signatureR, signatureS])
    pub fn rlp_signed<T: Into<U64>>(&self, chain_id: Option<T>, signature: &Signature) -> Bytes {
        let mut rlp = RlpStream::new();
        rlp.begin_list(9 + 3 /* signature fields */);

        rlp.append(&chain_id.map_or(U64::zero(), |id| id.into()));
        rlp_opt(&mut rlp, self.nonce);
        rlp.append(&self.max_priority_fee_per_gas);
        rlp.append(&self.max_fee_per_gas);
        rlp_opt(&mut rlp, self.gas);
        rlp_opt(&mut rlp, self.to.as_ref());
        rlp_opt(&mut rlp, self.value);
        rlp_opt(&mut rlp, self.data.as_ref().map(|d| d.as_ref()));
        rlp.append(&self.access_list);

        // append the signature
        rlp.append(&signature.v);
        rlp.append(&signature.r);
        rlp.append(&signature.s);

        rlp.out().freeze().into()
    }
}

fn rlp_opt<T: rlp::Encodable>(rlp: &mut RlpStream, opt: Option<T>) {
    if let Some(ref inner) = opt {
        rlp.append(inner);
    } else {
        rlp.append(&"");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_legacy_tx() {
        let tx = TransactionRequest::new()
            .to(Address::zero())
            .value(U256::from(100));
        let tx = TransactionEnvelope::from(tx);
        let serialized = serde_json::to_string(&tx).unwrap();

        // deserializes to either the envelope type or the inner type
        let de: TransactionEnvelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, de);

        let de: TransactionRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, TransactionEnvelope::Legacy(de));
    }

    #[test]
    fn serde_eip2930_tx() {
        let access_list = vec![AccessListItem {
            address: Address::zero(),
            storage_keys: vec![H256::zero()],
        }];
        let tx = TransactionRequest::new()
            .to(Address::zero())
            .value(U256::from(100))
            .with_access_list(access_list);
        let tx = TransactionEnvelope::from(tx);
        let serialized = serde_json::to_string(&tx).unwrap();
        dbg!(&serialized);

        // deserializes to either the envelope type or the inner type
        let de: TransactionEnvelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, de);

        let de: AccessListTransactionRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, TransactionEnvelope::AccessList(de));
    }
}
