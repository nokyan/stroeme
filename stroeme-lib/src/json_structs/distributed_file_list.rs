use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DistributedFilesList {
    pub utc: DateTime<Utc>,
    pub list: BTreeMap<Uuid, String>,
}
