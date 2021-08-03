use super::{eip1559::Eip1559TransactionRequest, eip2930::Eip2930TransactionRequest};
use crate::{
    types::{Address, Bytes, NameOrAddress, Signature, TransactionRequest, H256, U256, U64},
};
use serde::{Deserialize, Serialize};
use crate::utils::keccak256;
use bytes::BytesMut;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "type")]
pub enum TypedTransaction {
    // 0x00
    #[serde(rename = "0x00")]
    Legacy(TransactionRequest),
    // 0x01
    #[serde(rename = "0x01")]
    Eip2930(Eip2930TransactionRequest),
    // 0x02
    #[serde(rename = "0x02")]
    Eip1559(Eip1559TransactionRequest),
}

impl TypedTransaction {
    pub fn from(&self) -> Option<&Address> {
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.from.as_ref(),
            Eip2930(inner) => inner.tx.from.as_ref(),
            Eip1559(inner) => inner.from.as_ref(),
        }
    }

    pub fn set_from(&mut self, from: Address) {
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.from = Some(from),
            Eip2930(inner) => inner.tx.from = Some(from),
            Eip1559(inner) => inner.from = Some(from),
        };
    }

    pub fn to(&self) -> Option<&NameOrAddress> {
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.to.as_ref(),
            Eip2930(inner) => inner.tx.to.as_ref(),
            Eip1559(inner) => inner.to.as_ref(),
        }
    }

    pub fn set_to<T: Into<NameOrAddress>>(&mut self, to: T) {
        let to = to.into();
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.to = Some(to),
            Eip2930(inner) => inner.tx.to = Some(to),
            Eip1559(inner) => inner.to = Some(to),
        };
    }

    pub fn nonce(&self) -> Option<&U256> {
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.nonce.as_ref(),
            Eip2930(inner) => inner.tx.nonce.as_ref(),
            Eip1559(inner) => inner.nonce.as_ref(),
        }
    }

    pub fn set_nonce<T: Into<U256>>(&mut self, nonce: T) {
        let nonce = nonce.into();
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.nonce = Some(nonce),
            Eip2930(inner) => inner.tx.nonce = Some(nonce),
            Eip1559(inner) => inner.nonce = Some(nonce),
        };
    }

    pub fn value(&self) -> Option<&U256> {
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.value.as_ref(),
            Eip2930(inner) => inner.tx.value.as_ref(),
            Eip1559(inner) => inner.value.as_ref(),
        }
    }

    pub fn set_value<T: Into<U256>>(&mut self, value: T) {
        let value = value.into();
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.value = Some(value),
            Eip2930(inner) => inner.tx.value = Some(value),
            Eip1559(inner) => inner.value = Some(value),
        };
    }

    pub fn gas(&self) -> Option<&U256> {
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.gas.as_ref(),
            Eip2930(inner) => inner.tx.gas.as_ref(),
            Eip1559(inner) => inner.gas.as_ref(),
        }
    }

    pub fn set_gas<T: Into<U256>>(&mut self, gas: T) {
        let gas = gas.into();
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.gas = Some(gas),
            Eip2930(inner) => inner.tx.gas = Some(gas),
            Eip1559(inner) => inner.gas = Some(gas),
        };
    }

    pub fn set_gas_price<T: Into<U256>>(&mut self, gas_price: T) {
        let gas_price = gas_price.into();
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.gas_price = Some(gas_price),
            Eip2930(inner) => inner.tx.gas_price = Some(gas_price),
            Eip1559(inner) => {
                inner.max_fee_per_gas = Some(gas_price);
                inner.max_priority_fee_per_gas = Some(gas_price);
            }
        };
    }

    pub fn data(&self) -> Option<&Bytes> {
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.data.as_ref(),
            Eip2930(inner) => inner.tx.data.as_ref(),
            Eip1559(inner) => inner.data.as_ref(),
        }
    }

    pub fn set_data(&mut self, data: Bytes) {
        use TypedTransaction::*;
        match self {
            Legacy(inner) => inner.data = Some(data),
            Eip2930(inner) => inner.tx.data = Some(data),
            Eip1559(inner) => inner.data = Some(data),
        };
    }

    /// This includes the header byte
    pub fn encode_signed(&self, signature: &Signature) -> Bytes {
        use TypedTransaction::*;
        let mut buf = BytesMut::new();
        match self {
            Legacy(inner) => {
                buf.extend_from_slice(&[0x0]);
                inner.rlp_signed_with_buffer(signature, buf)
            },
            Eip2930(inner) => {
                buf.extend_from_slice(&[0x1]);
                inner.tx.rlp_signed_with_buffer(signature, buf)
            },
            Eip1559(inner) => {
                buf.extend_from_slice(&[0x2]);
                inner.rlp_signed_with_buffer(signature, buf)
            },
        }
    }

    /// This includes the header byte
    pub fn encode_unsigned<T: Into<U64>>(&self, chain_id: T) -> Bytes {
        let chain_id = chain_id.into();
        use TypedTransaction::*;
        let mut buf = BytesMut::new();
        match self {
            Legacy(inner) => {
                buf.extend_from_slice(&[0x0]);
                inner.rlp_with_buffer(chain_id, buf)
            },
            Eip2930(inner) => {
                buf.extend_from_slice(&[0x1]);
                inner.tx.rlp_with_buffer(chain_id, buf)
            },
            Eip1559(inner) => {
                buf.extend_from_slice(&[0x2]);
                inner.rlp_with_buffer(chain_id, buf)
            },
        }
    }

    /// Hashes the transaction's data with the provided chain id
    pub fn sighash<T: Into<U64>>(&self, chain_id: T) -> H256 {
        keccak256(self.encode_unsigned(chain_id).as_ref()).into()
    }
}

impl From<TransactionRequest> for TypedTransaction {
    fn from(src: TransactionRequest) -> TypedTransaction {
        TypedTransaction::Legacy(src)
    }
}

impl From<Eip2930TransactionRequest> for TypedTransaction {
    fn from(src: Eip2930TransactionRequest) -> TypedTransaction {
        TypedTransaction::Eip2930(src)
    }
}

impl From<Eip1559TransactionRequest> for TypedTransaction {
    fn from(src: Eip1559TransactionRequest) -> TypedTransaction {
        TypedTransaction::Eip1559(src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, U256};

    #[test]
    fn serde_legacy_tx() {
        let tx = TransactionRequest::new()
            .to(Address::zero())
            .value(U256::from(100));
        let tx: TypedTransaction = tx.into();
        let serialized = serde_json::to_string(&tx).unwrap();

        // deserializes to either the envelope type or the inner type
        let de: TypedTransaction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, de);

        let de: TransactionRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, TypedTransaction::Legacy(de));
    }
}
