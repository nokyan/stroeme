use std::{error::Error, path::Path, str::FromStr, time::Instant};

use futures_util::StreamExt;
use reqwest::{IntoUrl, Response};
use tokio::{fs::File, io::AsyncWriteExt};
use url::Url;
use uuid::Uuid;

use crate::{
    json_structs::{
        distributed_file_list::DistributedFilesList,
        distributor::{
            DistributorCredentials, NewDistributorBody, NewDistributorResponse, RandomDistributors,
        },
    },
    signatures::{
        algorithms::{init_verifying_key, AlgorithmCombination, VerifiyingAlgorithmCombination},
        tagged_signature::TaggedSignature,
    },
};

// Adapted from https://stackoverflow.com/a/49806368
macro_rules! continue_on_err {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(_) => {
                continue;
            }
        }
    };
}

pub struct Broker {
    pub url: Url,
    distributors: Vec<Url>,
    ignore_distributors: Vec<Url>,
    pub verifying_key: VerifiyingAlgorithmCombination,
}

static RTT_MEASUREMENTS: usize = 3;
static REFRESH_TRIES: usize = 3;

impl Broker {
    pub async fn new<V: Into<Vec<Url>>>(
        broker_url: Url,
        ignore_distributors: V,
    ) -> Result<Broker, Box<dyn Error + Send + Sync>> {
        let ignore_distributors_vec = ignore_distributors.into();
        let distributors =
            Self::get_new_distributors(broker_url.clone(), &ignore_distributors_vec).await?;
        let verifying_key = Self::get_verifying_key(broker_url.clone()).await?;
        Ok(Self {
            url: broker_url,
            distributors,
            ignore_distributors: ignore_distributors_vec,
            verifying_key,
        })
    }

    pub async fn add_distributor<U: IntoUrl>(
        &self,
        distributor_url: U,
        protocol_version: u16,
    ) -> Result<NewDistributorResponse, Box<dyn Error + Send + Sync>> {
        Ok(reqwest::Client::new()
            .post(self.url.clone().join("known_distributors")?)
            .header("Content-Type", "application/json")
            .json(&NewDistributorBody {
                url: distributor_url.as_str(),
                protocol_version,
            })
            .send()
            .await?
            .json::<NewDistributorResponse>()
            .await?)
    }

    pub async fn validate_distributor<S: Into<String>>(
        &self,
        uuid: Uuid,
        api_key: S,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        Ok(reqwest::Client::new()
            .post(
                self.url
                    .clone()
                    .join(&format!("known_distributors/{}/validate", uuid))?,
            )
            .header("Content-Type", "application/json")
            .json(&DistributorCredentials {
                api_key: api_key.into(),
            })
            .send()
            .await?
            .status()
            .is_success())
    }

    pub async fn get<S: AsRef<str>>(
        &self,
        endpoint: S,
    ) -> Result<Response, Box<dyn Error + Send + Sync>> {
        for distributor in self.distributors.iter() {
            let url = continue_on_err!(distributor.clone().join(endpoint.as_ref()));
            return Ok(continue_on_err!(
                reqwest::Client::new().get(url).send().await
            ));
        }
        Err("no broker could fulfill the request".into())
    }

    pub async fn get_adamantly<S: AsRef<str>>(
        &mut self,
        endpoint: S,
    ) -> Result<Response, Box<dyn Error + Send + Sync>> {
        for _ in 0..REFRESH_TRIES {
            for distributor in self.distributors.iter() {
                let url = continue_on_err!(distributor.clone().join(endpoint.as_ref()));
                return Ok(continue_on_err!(
                    reqwest::Client::new().get(url).send().await
                ));
            }
            continue_on_err!(self.refresh_distributors().await);
        }
        // if after `REFRESH_TRIES` no distributor has been found, try asking the broker
        self.get_from_broker(endpoint).await
    }

    pub async fn get_file<P: AsRef<Path>>(
        &self,
        uuid: Uuid,
        path: P,
        skip_verification: bool,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut byte_stream = self.get(format!("/file/{}", uuid)).await?.bytes_stream();
        let mut file = File::create(path.as_ref()).await?;
        while let Some(bytes) = byte_stream.next().await {
            let chunk = bytes?;
            file.write_all(&chunk).await?;
        }
        if !skip_verification {
            let signature = self.get_file_signature(uuid).await?.signature;
            if self.verifying_key.verify_file(path.as_ref(), signature)? {
                Ok(())
            } else {
                tokio::fs::remove_file(path).await?;
                Err("verification error".into())
            }
        } else {
            Ok(())
        }
    }

    pub async fn get_file_adamantly<P: AsRef<Path>>(
        &mut self,
        uuid: Uuid,
        path: P,
        skip_verification: bool,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut byte_stream = self
            .get_adamantly(format!("/file/{}", uuid))
            .await?
            .bytes_stream();
        let mut file = File::create(path.as_ref()).await?;
        while let Some(bytes) = byte_stream.next().await {
            let chunk = bytes?;
            file.write_all(&chunk).await?;
        }
        if !skip_verification {
            let signature = self.get_file_signature_adamantly(uuid).await?.signature;
            if self.verifying_key.verify_file(path.as_ref(), signature)? {
                Ok(())
            } else {
                tokio::fs::remove_file(path).await?;
                Err("verification error".into())
            }
        } else {
            Ok(())
        }
    }

    pub async fn get_file_signature(
        &self,
        uuid: Uuid,
    ) -> Result<TaggedSignature, Box<dyn Error + Send + Sync>> {
        Ok(self
            .get(format!("/signature/{}", uuid))
            .await?
            .json()
            .await?)
    }

    pub async fn get_file_signature_adamantly(
        &mut self,
        uuid: Uuid,
    ) -> Result<TaggedSignature, Box<dyn Error + Send + Sync>> {
        Ok(self
            .get_adamantly(format!("/signature/{}", uuid))
            .await?
            .json()
            .await?)
    }

    pub async fn get_from_broker<S: AsRef<str>>(
        &self,
        endpoint: S,
    ) -> Result<Response, Box<dyn Error + Send + Sync>> {
        Ok(reqwest::Client::new()
            .get(self.url.clone().join(endpoint.as_ref())?)
            .send()
            .await?)
    }

    pub async fn get_file_list(
        &self,
    ) -> Result<DistributedFilesList, Box<dyn Error + Send + Sync>> {
        let file_list_response = self
            .get_from_broker("/list")
            .await?
            .json::<DistributedFilesList>()
            .await?;
        let file_list_signature = self.get_file_list_signature().await?;
        if self.verifying_key.verify(
            serde_json::to_string(&file_list_response)?.as_bytes(),
            file_list_signature.signature.clone(),
        )? {
            Ok(file_list_response)
        } else {
            Err("failed".into())
        }
    }

    pub async fn get_file_list_signature(
        &self,
    ) -> Result<TaggedSignature, Box<dyn Error + Send + Sync>> {
        Ok(self
            .get_from_broker("/list_signature")
            .await?
            .json::<TaggedSignature>()
            .await?)
    }

    pub async fn refresh_distributors(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.distributors =
            Self::get_new_distributors(self.url.clone(), &self.ignore_distributors).await?;
        Ok(())
    }

    async fn measure_rtt(server: Url) -> Result<(Url, usize), Box<dyn Error + Send + Sync>> {
        let mut measurements = Vec::with_capacity(RTT_MEASUREMENTS);

        for _ in 0..RTT_MEASUREMENTS {
            let start_time = Instant::now();
            let response = reqwest::Client::new()
                .get(server.clone().join("/hearbeat")?)
                .send()
                .await?
                .status()
                .as_u16();
            let end_time = Instant::now();

            if response == 429 {
                let rtt = end_time - start_time;
                measurements.push(rtt.as_micros() as usize);
            }
        }

        Ok((
            server,
            measurements
                .iter()
                .sum::<usize>()
                .checked_div(RTT_MEASUREMENTS)
                .ok_or("division by 0?")?,
        ))
    }

    async fn get_new_distributors<V: AsRef<[Url]>>(
        broker_url: Url,
        ignore_distributors: V,
    ) -> Result<Vec<Url>, Box<dyn Error + Send + Sync>> {
        let response = reqwest::Client::new()
            .get(broker_url.clone().join("/known_distributors")?)
            .send()
            .await?
            .json::<RandomDistributors>()
            .await?;

        let mut rtt_url_pairs: Vec<(Url, usize)> = futures::future::join_all(
            response
                .distributors
                .iter()
                .filter(|url| !ignore_distributors.as_ref().contains(url))
                .map(|url| Self::measure_rtt(url.clone())),
        )
        .await
        .into_iter()
        .filter_map(|result| result.ok())
        .collect::<Vec<(Url, usize)>>();

        rtt_url_pairs.sort_by(|(_, a), (_, b)| a.cmp(b));

        Ok(rtt_url_pairs.into_iter().map(|(url, _)| url).collect())
    }

    async fn get_verifying_key(
        broker_url: Url,
    ) -> Result<VerifiyingAlgorithmCombination, Box<dyn Error + Send + Sync>> {
        let algorithm = AlgorithmCombination::from_str(
            &reqwest::Client::new()
                .get(broker_url.clone().join("/algorithm")?)
                .send()
                .await?
                .text()
                .await?,
        )?;

        init_verifying_key(
            algorithm,
            reqwest::Client::new()
                .get(broker_url.clone().join("/public_key")?)
                .send()
                .await?
                .text()
                .await?,
        )
    }
}
