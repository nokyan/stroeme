use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::signatures::tagged_signature::TaggedSignature;

#[derive(Serialize, Deserialize, Debug, Clone, Default, Hash)]
pub struct DistributedFile {
    pub id: Uuid,
    pub path: PathBuf,
    pub signature: TaggedSignature,
}
