use std::{collections::BTreeMap, error::Error, fs::DirEntry, path::Path};

use anyhow::Result;

use rayon::prelude::*;

use rocket::serde::uuid::Uuid;
use std::fs;

use stroeme_lib::distributed_file::DistributedFile;

use crate::config::{init_signing_key, SIGNING_KEY};

pub fn get_distributed_files<S: AsRef<str>>(public_folder: S) -> BTreeMap<Uuid, DistributedFile> {
    let paths = fs::read_dir(expanduser::expanduser(public_folder.as_ref()).unwrap())
        .unwrap()
        .flatten()
        .collect::<Vec<DirEntry>>();
    paths
        .par_iter()
        .map(|path| {
            let distributed_file = from_path(path.path()).ok()?;
            println!(
                "Found and registered file \"{}\" as {}",
                distributed_file.path.file_name()?.to_string_lossy(),
                distributed_file.id
            );
            Some((distributed_file.id, distributed_file))
        })
        .flatten()
        .collect::<BTreeMap<Uuid, DistributedFile>>()
}

fn generate_deterministic_uuid<P: AsRef<Path>>(path: P) -> Result<Uuid, Box<dyn Error>> {
    // subject to change
    Ok(Uuid::from_bytes(
        blake3::hash(
            path.as_ref()
                .file_name()
                .unwrap_or(path.as_ref().as_os_str())
                .to_string_lossy()
                .as_bytes(),
        )
        .as_bytes()[0..16]
            .try_into()?,
    ))
}

fn from_path<P: AsRef<Path>>(path: P) -> Result<DistributedFile, Box<dyn Error>> {
    let signature = SIGNING_KEY.get_or_init(init_signing_key).sign_file(&path)?;
    let id = generate_deterministic_uuid(&path)?;

    Ok(DistributedFile {
        id,
        path: path.as_ref().to_path_buf(),
        signature,
    })
}
