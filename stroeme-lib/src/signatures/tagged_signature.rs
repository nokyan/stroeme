use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::algorithms::AlgorithmCombination;

#[derive(Serialize, Deserialize, Debug, Clone, Default, Hash)]
pub struct TaggedSignature {
    pub algorithm: AlgorithmCombination,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub signature: Vec<u8>,
}

// Adapted from https://gist.github.com/silmeth/62a92e155d72bb9c5f19c8cdf4c8993e
fn as_base64<T: AsRef<[u8]>, S: Serializer>(val: &T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(val))
}

// Adapted from https://gist.github.com/silmeth/62a92e155d72bb9c5f19c8cdf4c8993e
fn from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    use serde::de;

    <&str>::deserialize(deserializer).and_then(|s| {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| de::Error::custom(format!("invalid base64 string: {}, {}", s, e)))
    })
}
