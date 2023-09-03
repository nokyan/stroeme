mod config;
mod distributed_file;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    str::FromStr,
};

use chrono::{DateTime, Utc};
use config::{
    init_signing_key, init_verifying_key, read_config, BROKER_CONFIG, SIGNING_KEY, VERIFYING_KEY,
};
use distributed_file::get_distributed_files;
use rand::seq::IteratorRandom;
use rocket::{
    fs::NamedFile,
    futures::lock::Mutex,
    http::Status,
    serde::{
        json::{serde_json, Json},
        uuid::Uuid,
    },
    State,
};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use stroeme_lib::{
    distributed_file::DistributedFile,
    distributor::{generate_api_key, generate_uuid, Distributor},
    json_structs::{
        distributed_file_list::DistributedFilesList,
        distributor::{
            DistributorCredentials, NewDistributorBody, NewDistributorResponse, RandomDistributors,
        },
    },
    signatures::{
        algorithms::{AlgorithmCombination, VerifiyingAlgorithmCombination},
        tagged_signature::TaggedSignature,
    },
};
use url::Url;

#[macro_use]
extern crate rocket;

type DistributorList = Mutex<HashMap<Uuid, Distributor>>;
type Distributors<'r> = &'r State<DistributorList>;

type DistributedFilesListInner = Mutex<BTreeMap<Uuid, DistributedFile>>;
type DistributedFiles<'r> = &'r State<DistributedFilesListInner>;

type DistributedLastChangedInner = Mutex<DateTime<Utc>>;
type DistributedLastChanged<'r> = &'r State<DistributedLastChangedInner>;

fn validate_api_key(distributor: &Distributor, other_key: &str) -> Result<(), Status> {
    if distributor
        .api_key
        .as_ref()
        .ok_or(Status::InternalServerError)?
        == other_key
    {
        return Ok(());
    }
    Err(Status::Forbidden)
}

#[get("/heartbeat")]
async fn heartbeat() -> Status {
    Status::ImATeapot
}

#[get("/list")]
async fn list_files(
    files_map: DistributedFiles<'_>,
    last_changed: DistributedLastChanged<'_>,
) -> Result<Json<DistributedFilesList>, Status> {
    let list = files_map
        .lock()
        .await
        .iter()
        .map(|(uuid, file)| {
            (
                *uuid,
                file.path.file_name().unwrap().to_string_lossy().into(),
            )
        })
        .collect();
    Ok(Json(DistributedFilesList {
        utc: *last_changed.lock().await,
        list,
    }))
}

#[get("/public_key")]
async fn public_key() -> Result<String, Status> {
    match VERIFYING_KEY.get_or_init(init_verifying_key) {
        VerifiyingAlgorithmCombination::Ed25519phBlake2b512(key)
        | VerifiyingAlgorithmCombination::Ed25519phSha3512(key)
        | VerifiyingAlgorithmCombination::Ed25519phSha2512(key) => key
            .to_public_key_pem(LineEnding::default())
            .or(Err(Status::InternalServerError)),
        VerifiyingAlgorithmCombination::RsaBlake3(key) => key
            .to_public_key_pem(LineEnding::default())
            .or(Err(Status::InternalServerError)),
        VerifiyingAlgorithmCombination::RsaBlake2b512(key) => key
            .to_public_key_pem(LineEnding::default())
            .or(Err(Status::InternalServerError)),
        VerifiyingAlgorithmCombination::RsaSha3512(key) => key
            .to_public_key_pem(LineEnding::default())
            .or(Err(Status::InternalServerError)),
        VerifiyingAlgorithmCombination::RsaSha2512(key) => key
            .to_public_key_pem(LineEnding::default())
            .or(Err(Status::InternalServerError)),
    }
}

#[get("/algorithm")]
async fn algorihm() -> String {
    AlgorithmCombination::from(VERIFYING_KEY.get_or_init(init_verifying_key).clone()).to_string()
}

#[get("/list_signature")]
async fn list_signature(
    files_map: DistributedFiles<'_>,
    last_changed: DistributedLastChanged<'_>,
) -> Result<Json<TaggedSignature>, Status> {
    let list = list_files(files_map, last_changed).await?;
    let list_string = serde_json::to_string(&list.0).or(Err(Status::InternalServerError))?;
    let list_bytes = list_string.as_bytes();
    SIGNING_KEY
        .get_or_init(init_signing_key)
        .sign(list_bytes)
        .or(Err(Status::InternalServerError))
        .map(Json)
}

#[get("/file/<uuid>")]
async fn get_file(uuid: Uuid, files_map: DistributedFiles<'_>) -> Result<NamedFile, Status> {
    NamedFile::open(
        &files_map
            .lock()
            .await
            .get(&uuid)
            .map(|df| df.path.clone())
            .ok_or(Status::NotFound)?,
    )
    .await
    .or(Err(Status::NotFound))
}

#[get("/signature/<uuid>")]
async fn get_file_signature(
    uuid: Uuid,
    files_map: DistributedFiles<'_>,
) -> Result<Json<TaggedSignature>, Status> {
    files_map
        .lock()
        .await
        .get(&uuid)
        .map(|df| Json(df.signature.clone()))
        .ok_or(Status::NotFound)
}

#[get("/known_distributors")]
async fn get_random_distributors(
    distributors_map: Distributors<'_>,
) -> Result<Json<RandomDistributors>, Status> {
    // select random distributors
    let mut return_distributors = RandomDistributors::default();
    let distributors = distributors_map.lock().await;

    if distributors.len() < 16 {
        distributors
            .values()
            .filter(|distributor| distributor.validated)
            .map(|distributor| distributor.url.clone())
            .for_each(|url| return_distributors.distributors.push(url));
    } else {
        let mut selected_distributor = HashSet::new();
        while selected_distributor.len() < 16 {
            if let Some(item) = distributors
                .values()
                .filter(|distributor| distributor.validated)
                .choose(&mut rand::thread_rng())
            {
                if selected_distributor.insert(item.uuid) {
                    return_distributors.distributors.push(item.url.clone());
                }
            }
        }
    }

    Ok(Json(return_distributors))
}

#[post("/known_distributors", format = "json", data = "<body>")]
async fn add_new_distributor(
    body: Json<NewDistributorBody<'_>>,
    distributors_map: Distributors<'_>,
) -> Result<Json<NewDistributorResponse>, Status> {
    let url = Url::parse(body.url).or(Err(Status::BadRequest))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(Status::NotAcceptable);
    }

    let mut map = distributors_map.lock().await;

    if map
        .values()
        .map(|distributor| distributor.url.clone())
        .any(|old_url| old_url == url)
    {
        println!("{} wants to re-register", url);
        map.retain(|_, distributor| distributor.url != url);
    } else {
        println!("{} wants to register", url);
    }

    let response = NewDistributorResponse {
        uuid: generate_uuid(),
        api_key: generate_api_key(),
    };

    let new_distributor = Distributor {
        url,
        protocol_version: body.protocol_version,
        uuid: Some(response.uuid),
        api_key: Some(response.api_key.clone()),
        validated: false,
    };
    map.insert(response.uuid, new_distributor);

    Ok(Json(response))
}

#[delete("/known_distributors/<uuid>", data = "<body>", format = "json")]
async fn delete_distributor(
    uuid: Uuid,
    body: Json<DistributorCredentials>,
    distributors_map: Distributors<'_>,
) -> Result<Status, Status> {
    let mut map = distributors_map.lock().await;
    let distributor = map.get(&uuid).ok_or(Status::NotFound)?;
    if distributor
        .api_key
        .as_ref()
        .ok_or(Status::InternalServerError)?
        == &body.api_key
    {
        map.remove(&uuid);
    } else {
        return Err(Status::Forbidden);
    }

    Ok(Status::Ok)
}

#[post(
    "/known_distributors/<uuid>/validate",
    format = "json",
    data = "<body>"
)]
async fn validate_distributor(
    uuid: Uuid,
    body: Json<DistributorCredentials>,
    distributors_map: Distributors<'_>,
) -> Result<(), Status> {
    let mut map = distributors_map.lock().await;

    let distributor = map.get_mut(&uuid).ok_or(Status::NotFound)?;
    validate_api_key(distributor, &body.api_key)?;

    if distributor.validated {
        return Err(Status::Conflict);
    }

    let mut well_known = distributor.url.clone();
    well_known.set_path(".well-known/stroeme.txt");

    let resp = reqwest::get(well_known)
        .await
        .or(Err(Status::NotFound))?
        .text()
        .await
        .or(Err(Status::BadRequest))?
        .replace(['\n', ' '], "");

    if Uuid::from_str(&resp).or(Err(Status::BadRequest))?
        != distributor.uuid.ok_or(Status::InternalServerError)?
    {
        return Err(Status::BadRequest);
    }

    distributor.validated = true;
    println!("{} has been successfully validated", distributor.url);
    Ok(())
}

#[launch]
fn rocket() -> _ {
    let mut rocket_config = rocket::Config::default();
    let broker_config = BROKER_CONFIG.get_or_init(read_config);

    rocket_config.address =
        IpAddr::from_str(&broker_config.get_string("address").unwrap()).unwrap();
    rocket_config.port = broker_config.get_int("port").unwrap() as u16;

    rocket::custom(rocket_config)
        .mount(
            "/",
            routes![
                add_new_distributor,
                algorihm,
                delete_distributor,
                get_file,
                get_file_signature,
                get_random_distributors,
                heartbeat,
                list_files,
                list_signature,
                public_key,
                validate_distributor
            ],
        )
        .manage(DistributorList::new(HashMap::new()))
        .manage(DistributedFilesListInner::new(get_distributed_files(
            broker_config.get_string("distributed_directory").unwrap(),
        )))
        .manage(DistributedLastChangedInner::new(Utc::now()))
}
