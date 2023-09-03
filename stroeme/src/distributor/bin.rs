use std::{net::IpAddr, process::exit, str::FromStr};

use config::{read_config, DISTRIBUTOR_CONFIG};
use distributed_file::DistributedFilesContext;
use rocket::{
    fs::NamedFile,
    futures::lock::Mutex,
    get,
    http::Status,
    launch, routes,
    serde::{json::Json, uuid::Uuid},
    Build, Rocket, State,
};
use stroeme_lib::{
    broker::Broker, distributor::Distributor, signatures::tagged_signature::TaggedSignature,
};

use crate::distributed_file::sync_distributed_files;

mod config;
mod distributed_file;

type DistributedFilesInner = Mutex<DistributedFilesContext>;
type DistributedFiles<'r> = &'r State<DistributedFilesInner>;

type ContextInner = Mutex<(Distributor, Broker)>;
type Context<'r> = &'r State<ContextInner>;

#[get("/heartbeat")]
async fn heartbeat() -> Status {
    Status::ImATeapot
}

/*#[get("/list")]
async fn list_files(
    files_list: DistributedFiles<'_>,
) -> Result<Json<DistributedFilesListResponse>, Status> {
    Ok(Json(files_list.lock().await.list_response.clone()))
}

#[get("/list_signature")]
async fn list_signature(files_list: DistributedFiles<'_>) -> Result<Json<TaggedSignature>, Status> {
    Ok(Json(files_list.lock().await.tagged_signature.clone()))
}*/

#[get("/file/<uuid>")]
async fn get_file(uuid: Uuid, files_map: DistributedFiles<'_>) -> Result<NamedFile, Status> {
    NamedFile::open(
        &files_map
            .lock()
            .await
            .list
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
        .list
        .get(&uuid)
        .map(|df| Json(df.signature.clone()))
        .ok_or(Status::NotFound)
}

#[launch]
async fn rocket() -> Rocket<Build> {
    let mut rocket_config = rocket::Config::default();
    let distributor_config = DISTRIBUTOR_CONFIG.get_or_init(read_config);

    if distributor_config.get_string("url").unwrap().is_empty() {
        println!(
            "`url` needs to be defined StroemeDistributor.toml, but it isn't currently. Exiting."
        );
        exit(1);
    }

    if distributor_config
        .get_string("broker_url")
        .unwrap()
        .is_empty()
    {
        println!(
            "`broker_url` needs to be defined StroemeDistributor.toml, but it isn't currently. Exiting."
        );
        exit(1);
    }

    rocket_config.address =
        IpAddr::from_str(&distributor_config.get_string("address").unwrap()).unwrap();
    rocket_config.port = distributor_config.get_int("port").unwrap() as u16;

    println!(
        "Initializing Handshake with {} as {}",
        distributor_config.get_string("broker_url").unwrap(),
        distributor_config.get_string("url").unwrap()
    );

    let (distributor, mut broker) = stroeme_lib::distributor::Distributor::handshake(
        distributor_config.get_string("broker_url").unwrap(),
        distributor_config.get_string("url").unwrap(),
        distributor_config.get("protocol_version").unwrap(),
        distributor_config
            .get_string("well_known_directory")
            .unwrap(),
    )
    .await
    .expect("Handshake failed. Exiting.");

    println!("Handshake succeeded.");

    rocket::custom(rocket_config)
        .mount(
            "/",
            routes![
                get_file,
                get_file_signature,
                heartbeat,
                /*list_files,
                list_signature,*/
            ],
        )
        .manage(DistributedFilesInner::new(
            sync_distributed_files(
                expanduser::expanduser(
                    distributor_config
                        .get_string("distributed_directory")
                        .unwrap(),
                )
                .unwrap(),
                &mut broker,
            )
            .await
            .unwrap(),
        ))
        .manage(ContextInner::new((distributor, broker)))
    //.attach(AdHoc::on_liftoff("sync_distributed_files", |_| {}))
}
