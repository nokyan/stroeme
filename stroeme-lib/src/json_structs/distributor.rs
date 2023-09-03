use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct NewDistributorResponse {
    pub uuid: Uuid,
    pub api_key: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct NewDistributorBody<'r> {
    pub url: &'r str,
    pub protocol_version: u16,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DistributorCredentials {
    pub api_key: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RandomDistributors {
    pub distributors: Vec<Url>,
}
