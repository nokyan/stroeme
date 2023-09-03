use std::{str::FromStr, sync::OnceLock};

use config::Config;
use stroeme_lib::signatures::algorithms::{
    AlgorithmCombination, SigningAlgorithmCombination, VerifiyingAlgorithmCombination,
};

pub static BROKER_CONFIG: OnceLock<Config> = OnceLock::new();
pub static SIGNING_KEY: OnceLock<SigningAlgorithmCombination> = OnceLock::new();
pub static VERIFYING_KEY: OnceLock<VerifiyingAlgorithmCombination> = OnceLock::new();

pub fn init_verifying_key() -> VerifiyingAlgorithmCombination {
    let preferred_algorithm_combination = AlgorithmCombination::from_str(
        &BROKER_CONFIG
            .get_or_init(read_config)
            .get_string("preferred_algorithm")
            .unwrap(),
    )
    .unwrap();

    let input_source = match preferred_algorithm_combination {
        AlgorithmCombination::Ed25519phBlake2b512
        | AlgorithmCombination::Ed25519phSha3512
        | AlgorithmCombination::Ed25519phSha2512 => expanduser::expanduser(
            BROKER_CONFIG
                .get_or_init(read_config)
                .get_string("ed25519_verifying_key")
                .unwrap(),
        )
        .unwrap(),
        AlgorithmCombination::RsaBlake3
        | AlgorithmCombination::RsaBlake2b512
        | AlgorithmCombination::RsaSha3512
        | AlgorithmCombination::RsaSha2512 => expanduser::expanduser(
            BROKER_CONFIG
                .get_or_init(read_config)
                .get_string("rsa_verifying_key")
                .unwrap(),
        )
        .unwrap(),
    };

    let input = std::fs::read_to_string(input_source).unwrap();

    stroeme_lib::signatures::algorithms::init_verifying_key(preferred_algorithm_combination, input)
        .unwrap()
}

pub fn init_signing_key() -> SigningAlgorithmCombination {
    let preferred_algorithm_combination = AlgorithmCombination::from_str(
        &BROKER_CONFIG
            .get_or_init(read_config)
            .get_string("preferred_algorithm")
            .unwrap(),
    )
    .unwrap();

    let input_source = match preferred_algorithm_combination {
        AlgorithmCombination::Ed25519phBlake2b512
        | AlgorithmCombination::Ed25519phSha3512
        | AlgorithmCombination::Ed25519phSha2512 => expanduser::expanduser(
            BROKER_CONFIG
                .get_or_init(read_config)
                .get_string("ed25519_signing_key")
                .unwrap(),
        )
        .unwrap(),
        AlgorithmCombination::RsaBlake3
        | AlgorithmCombination::RsaBlake2b512
        | AlgorithmCombination::RsaSha3512
        | AlgorithmCombination::RsaSha2512 => expanduser::expanduser(
            BROKER_CONFIG
                .get_or_init(read_config)
                .get_string("rsa_signing_key")
                .unwrap(),
        )
        .unwrap(),
    };

    let input = std::fs::read_to_string(input_source).unwrap();

    stroeme_lib::signatures::algorithms::init_signing_key(preferred_algorithm_combination, input)
        .unwrap()
}

pub fn read_config() -> Config {
    Config::builder()
        .add_source(config::File::with_name("StroemeBroker.toml"))
        /*.add_source(config::File::with_name(
            &expanduser::expanduser("~/.config/stroeme/broker/StroemeBroker.toml")
                .unwrap()
                .to_string_lossy(),
        ))
        .add_source(config::File::with_name(
            "/etc/stroeme/broker/StroemeBroker.toml",
        ))*/
        .add_source(config::Environment::with_prefix("STROEME_BROKER"))
        .set_default("address", "0.0.0.0")
        .unwrap()
        .set_default("port", 443)
        .unwrap()
        .set_default(
            "ed25519_signing_key",
            "~/.config/stroeme/broker/stroeme_ed25519_signing.pem",
        )
        .unwrap()
        .set_default(
            "ed25519_verifying_key",
            "~/.config/stroeme/broker/stroeme_ed25519_verifying.pem",
        )
        .unwrap()
        .set_default(
            "rsa_signing_key",
            "~/.config/stroeme/broker/stroeme_ed25519_signing.pem",
        )
        .unwrap()
        .set_default(
            "rsa_verifying_key",
            "~/.config/stroeme/broker/stroeme_ed25519_verifying.pem",
        )
        .unwrap()
        .set_default(
            "distributed_directory",
            "~/.config/stroeme/broker/distributed",
        )
        .unwrap()
        .set_default("preferred_algorithm", "RsaBlake3")
        .unwrap()
        .build()
        .unwrap()
}
