use std::sync::OnceLock;

use config::Config;

pub static DISTRIBUTOR_CONFIG: OnceLock<Config> = OnceLock::new();

pub fn read_config() -> Config {
    Config::builder()
        .add_source(config::File::with_name("StroemeDistributor.toml"))
        /*.add_source(config::File::with_name(
            "~/.config/stroeme/distributor/StroemeDistributor.toml",
        ))
        .add_source(config::File::with_name(
            "/etc/stroeme/distributor/StroemeDistributor.toml",
        ))*/
        .add_source(config::Environment::with_prefix("STROEME_DISTRIBUTOR"))
        .set_default("address", "0.0.0.0")
        .unwrap()
        .set_default("port", 443)
        .unwrap()
        .set_default("url", "")
        .unwrap()
        .set_default("broker_url", "")
        .unwrap()
        .set_default("protocol_version", 1)
        .unwrap()
        .set_default("well_known_directory", "/var/www/.well-known/")
        .unwrap()
        .set_default(
            "distributed_directory",
            "~/.config/distributor/stroeme/distributed",
        )
        .unwrap()
        .build()
        .unwrap()
}
