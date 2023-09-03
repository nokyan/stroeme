use std::{collections::BTreeMap, error::Error, path::Path};

use chrono::{DateTime, Utc};
use rocket::{
    serde::{uuid::Uuid, Deserialize, Serialize},
    tokio,
};
use stroeme_lib::{broker::Broker, distributed_file::DistributedFile};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct DistributedFilesContext {
    pub utc: DateTime<Utc>,
    pub list: BTreeMap<Uuid, DistributedFile>,
}

pub async fn sync_distributed_files<P: AsRef<Path>>(
    distributed_directory: P,
    broker: &mut Broker,
) -> Result<DistributedFilesContext, Box<dyn Error + Send + Sync>> {
    println!("Starting sync");
    let new_list = broker.get_file_list().await?;
    let mut new_distributed_files = BTreeMap::new();

    for (uuid, file) in new_list.list.iter() {
        let file_path = distributed_directory.as_ref().join(file);
        let file_signature = broker.get_file_signature_adamantly(*uuid).await?;
        if file_path.is_file()
            && broker
                .verifying_key
                .verify_file(&file_path, file_signature.clone().signature)?
        {
            println!("{} ({}) has remained intact locally.", uuid, file);
            continue;
        } else {
            println!(
                "Downloading {} ({}) to {}.",
                uuid,
                file,
                file_path.to_string_lossy()
            );
            // do the verification ourselves because we already have the signature
            broker.get_file_adamantly(*uuid, &file_path, true).await?;
            if !broker
                .verifying_key
                .verify_file(&file_path, file_signature.signature.clone())?
            {
                tokio::fs::remove_file(&file_path).await?;
                return Err("verification error".into());
            }
        }

        let distributed_file = DistributedFile {
            id: *uuid,
            path: file_path,
            signature: file_signature,
        };

        new_distributed_files.insert(*uuid, distributed_file);
    }

    let new_context = DistributedFilesContext {
        utc: new_list.utc,
        list: new_distributed_files,
    };

    Ok(new_context)
}
