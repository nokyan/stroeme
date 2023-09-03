use std::{error::Error, path::Path};

use base64::Engine;
use rand::Rng;
use reqwest::IntoUrl;
use url::Url;
use uuid::Uuid;

use crate::broker::Broker;

#[derive(Debug, Clone, Hash)]
pub struct Distributor {
    pub url: Url,
    pub protocol_version: u16,
    pub uuid: Option<Uuid>,
    pub api_key: Option<String>,
    pub validated: bool,
}
impl Distributor {
    pub async fn handshake<P: AsRef<Path>, U: IntoUrl>(
        broker_url: U,
        distributor_url: U,
        protocol_version: u16,
        well_known_dir: P,
    ) -> Result<(Distributor, Broker), Box<dyn Error + Send + Sync>> {
        let broker_url = broker_url.into_url()?;
        let distributor_url = distributor_url.into_url()?;

        let broker = Broker::new(broker_url.clone(), [distributor_url.clone()]).await?;

        let credentials = broker
            .add_distributor(distributor_url.clone(), protocol_version)
            .await?;

        let well_known_file = expanduser::expanduser(
            well_known_dir
                .as_ref()
                .join("stroeme.txt")
                .to_string_lossy(),
        )?;
        tokio::fs::write(well_known_file, credentials.uuid.to_string().as_bytes()).await?;

        if broker
            .validate_distributor(credentials.uuid, credentials.api_key.clone())
            .await?
        {
            Ok((
                Distributor {
                    url: distributor_url,
                    protocol_version,
                    uuid: Some(credentials.uuid),
                    api_key: Some(credentials.api_key),
                    validated: true,
                },
                broker,
            ))
        } else {
            Err(format!("couldn't validate {} to {}", credentials.uuid, broker_url).into())
        }
    }
}

pub fn generate_uuid() -> Uuid {
    let mut rng = rand::thread_rng();
    Uuid::from_u128(rng.gen())
}

pub fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..24).map(|_| rng.gen::<u8>()).collect();
    base64::engine::general_purpose::STANDARD.encode(random_bytes)
}
