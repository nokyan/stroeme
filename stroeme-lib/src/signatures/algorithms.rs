use std::{error::Error, fs::File, path::Path};

use blake2::{digest::FixedOutputReset, Blake2b512, Digest};
use ed25519_dalek::{
    ed25519::SignatureEncoding,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Verifier,
};

use memmap2::Mmap;
use rsa::signature::RandomizedSigner;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::Sha3_512;
use strum::{Display, EnumString};

use super::tagged_signature::TaggedSignature;

#[derive(Clone, Debug)]
pub enum SigningAlgorithmCombination {
    Ed25519phBlake2b512(ed25519_dalek::SigningKey),
    Ed25519phSha3512(ed25519_dalek::SigningKey),
    Ed25519phSha2512(ed25519_dalek::SigningKey),
    RsaBlake3(rsa::pss::SigningKey<blake3::Hasher>),
    RsaBlake2b512(rsa::pss::SigningKey<blake2::Blake2b512>),
    RsaSha3512(rsa::pss::SigningKey<sha3::Sha3_512>),
    RsaSha2512(rsa::pss::SigningKey<sha2::Sha512>),
}

#[derive(Clone, Debug)]
pub enum VerifiyingAlgorithmCombination {
    Ed25519phBlake2b512(ed25519_dalek::VerifyingKey),
    Ed25519phSha3512(ed25519_dalek::VerifyingKey),
    Ed25519phSha2512(ed25519_dalek::VerifyingKey),
    RsaBlake3(rsa::pss::VerifyingKey<blake3::Hasher>),
    RsaBlake2b512(rsa::pss::VerifyingKey<blake2::Blake2b512>),
    RsaSha3512(rsa::pss::VerifyingKey<sha3::Sha3_512>),
    RsaSha2512(rsa::pss::VerifyingKey<sha2::Sha512>),
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Hash, EnumString, Display)]
pub enum AlgorithmCombination {
    #[default]
    Ed25519phBlake2b512,
    Ed25519phSha3512,
    Ed25519phSha2512,
    RsaBlake3,
    RsaBlake2b512,
    RsaSha3512,
    RsaSha2512,
}

impl From<VerifiyingAlgorithmCombination> for AlgorithmCombination {
    fn from(value: VerifiyingAlgorithmCombination) -> Self {
        match value {
            VerifiyingAlgorithmCombination::Ed25519phBlake2b512(_) => {
                AlgorithmCombination::Ed25519phBlake2b512
            }
            VerifiyingAlgorithmCombination::Ed25519phSha3512(_) => {
                AlgorithmCombination::Ed25519phSha3512
            }
            VerifiyingAlgorithmCombination::Ed25519phSha2512(_) => {
                AlgorithmCombination::Ed25519phSha2512
            }
            VerifiyingAlgorithmCombination::RsaBlake3(_) => AlgorithmCombination::RsaBlake3,
            VerifiyingAlgorithmCombination::RsaBlake2b512(_) => AlgorithmCombination::RsaBlake2b512,
            VerifiyingAlgorithmCombination::RsaSha3512(_) => AlgorithmCombination::RsaSha3512,
            VerifiyingAlgorithmCombination::RsaSha2512(_) => AlgorithmCombination::RsaSha2512,
        }
    }
}

impl From<SigningAlgorithmCombination> for AlgorithmCombination {
    fn from(value: SigningAlgorithmCombination) -> Self {
        match value {
            SigningAlgorithmCombination::Ed25519phBlake2b512(_) => {
                AlgorithmCombination::Ed25519phBlake2b512
            }
            SigningAlgorithmCombination::Ed25519phSha3512(_) => {
                AlgorithmCombination::Ed25519phSha3512
            }
            SigningAlgorithmCombination::Ed25519phSha2512(_) => {
                AlgorithmCombination::Ed25519phSha2512
            }
            SigningAlgorithmCombination::RsaBlake3(_) => AlgorithmCombination::RsaBlake3,
            SigningAlgorithmCombination::RsaBlake2b512(_) => AlgorithmCombination::RsaBlake2b512,
            SigningAlgorithmCombination::RsaSha3512(_) => AlgorithmCombination::RsaSha3512,
            SigningAlgorithmCombination::RsaSha2512(_) => AlgorithmCombination::RsaSha2512,
        }
    }
}

impl SigningAlgorithmCombination {
    pub fn sign_file<P: AsRef<Path>>(&self, path: P) -> Result<TaggedSignature, Box<dyn Error>> {
        let mmap = unsafe { Mmap::map(&File::open(path.as_ref())?)? };
        self.sign(mmap)
    }

    pub fn sign<B: AsRef<[u8]>>(&self, bytes: B) -> Result<TaggedSignature, Box<dyn Error>> {
        let signature = match self {
            SigningAlgorithmCombination::Ed25519phBlake2b512(key) => {
                Self::ed25519ph_blake2b512_sign(key, bytes)
            }
            SigningAlgorithmCombination::Ed25519phSha3512(key) => {
                Self::ed25519ph_sha3512_sign(key, bytes)
            }
            SigningAlgorithmCombination::Ed25519phSha2512(key) => {
                Self::ed25519ph_sha2512_sign(key, bytes)
            }
            SigningAlgorithmCombination::RsaBlake3(key) => Self::rsa_sign(key, bytes),
            SigningAlgorithmCombination::RsaBlake2b512(key) => Self::rsa_sign(key, bytes),
            SigningAlgorithmCombination::RsaSha3512(key) => Self::rsa_sign(key, bytes),
            SigningAlgorithmCombination::RsaSha2512(key) => Self::rsa_sign(key, bytes),
        }?;
        Ok(TaggedSignature {
            algorithm: AlgorithmCombination::from(self.clone()),
            signature,
        })
    }

    fn rsa_sign<B: AsRef<[u8]>, D: Digest + FixedOutputReset>(
        signing_key: &rsa::pss::SigningKey<D>,
        bytes: B,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        Ok(signing_key
            .try_sign_with_rng(&mut rng, bytes.as_ref())
            .map(|sig| sig.to_bytes().to_vec())?)
    }

    //TODO: There's gotta be a cleaner way to do this
    fn ed25519ph_blake2b512_sign<B: AsRef<[u8]>>(
        signing_key: &ed25519_dalek::SigningKey,
        bytes: B,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut hasher = Blake2b512::new();
        bytes
            .as_ref()
            .chunks(512 * 1024)
            .for_each(|chunk| hasher.update(chunk));

        Ok(signing_key
            .sign_prehashed(hasher, None)?
            .to_bytes()
            .to_vec())
    }

    fn ed25519ph_sha3512_sign<B: AsRef<[u8]>>(
        signing_key: &ed25519_dalek::SigningKey,
        bytes: B,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut hasher = Sha3_512::new();
        bytes
            .as_ref()
            .chunks(512 * 1024)
            .for_each(|chunk| hasher.update(chunk));

        Ok(signing_key
            .sign_prehashed(hasher, None)?
            .to_bytes()
            .to_vec())
    }

    fn ed25519ph_sha2512_sign<B: AsRef<[u8]>>(
        signing_key: &ed25519_dalek::SigningKey,
        bytes: B,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut hasher = Sha512::new();
        bytes
            .as_ref()
            .chunks(512 * 1024)
            .for_each(|chunk| hasher.update(chunk));

        Ok(signing_key
            .sign_prehashed(hasher, None)?
            .to_bytes()
            .to_vec())
    }
}

impl VerifiyingAlgorithmCombination {
    pub fn verify_file<P: AsRef<Path>>(
        &self,
        path: P,
        signature: Vec<u8>,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let mmap = unsafe { Mmap::map(&File::open(path.as_ref())?)? };
        self.verify(mmap, signature)
    }

    pub fn verify<B: AsRef<[u8]>>(
        &self,
        bytes: B,
        signature: Vec<u8>,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        match self {
            VerifiyingAlgorithmCombination::Ed25519phBlake2b512(key) => {
                Self::ed25519ph_blake2b512_verify(key, bytes, signature)
            }
            VerifiyingAlgorithmCombination::Ed25519phSha3512(key) => {
                Self::ed25519ph_sha3512_verify(key, bytes, signature)
            }
            VerifiyingAlgorithmCombination::Ed25519phSha2512(key) => {
                Self::ed25519ph_sha2512_verify(key, bytes, signature)
            }
            VerifiyingAlgorithmCombination::RsaBlake3(key) => {
                Self::rsa_verify(key, bytes, signature)
            }
            VerifiyingAlgorithmCombination::RsaBlake2b512(key) => {
                Self::rsa_verify(key, bytes, signature)
            }
            VerifiyingAlgorithmCombination::RsaSha3512(key) => {
                Self::rsa_verify(key, bytes, signature)
            }
            VerifiyingAlgorithmCombination::RsaSha2512(key) => {
                Self::rsa_verify(key, bytes, signature)
            }
        }
    }

    fn rsa_verify<B: AsRef<[u8]>, D: Digest + FixedOutputReset>(
        verifying_key: &rsa::pss::VerifyingKey<D>,
        bytes: B,
        signature: Vec<u8>,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        Ok(verifying_key
            .verify(
                bytes.as_ref(),
                &rsa::pss::Signature::try_from(&signature[..])?,
            )
            .is_ok())
    }

    //TODO: There's gotta be a cleaner way to do this
    fn ed25519ph_blake2b512_verify<B: AsRef<[u8]>>(
        verifying_key: &ed25519_dalek::VerifyingKey,
        bytes: B,
        signature: Vec<u8>,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let mut hasher = Blake2b512::new();
        bytes
            .as_ref()
            .chunks(512 * 1024)
            .for_each(|chunk| hasher.update(chunk));
        Ok(verifying_key
            .verify_prehashed_strict(
                hasher,
                None,
                &ed25519_dalek::Signature::from_bytes(&signature[..].try_into()?),
            )
            .is_ok())
    }

    fn ed25519ph_sha3512_verify<B: AsRef<[u8]>>(
        verifying_key: &ed25519_dalek::VerifyingKey,
        bytes: B,
        signature: Vec<u8>,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let mut hasher = Sha3_512::new();
        bytes
            .as_ref()
            .chunks(512 * 1024)
            .for_each(|chunk| hasher.update(chunk));

        Ok(verifying_key
            .verify_prehashed_strict(
                hasher,
                None,
                &ed25519_dalek::Signature::from_bytes(&signature[..].try_into()?),
            )
            .is_ok())
    }

    fn ed25519ph_sha2512_verify<B: AsRef<[u8]>>(
        verifying_key: &ed25519_dalek::VerifyingKey,
        bytes: B,
        signature: Vec<u8>,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let mut hasher = Sha512::new();
        bytes
            .as_ref()
            .chunks(512 * 1024)
            .for_each(|chunk| hasher.update(chunk));

        Ok(verifying_key
            .verify_prehashed_strict(
                hasher,
                None,
                &ed25519_dalek::Signature::from_bytes(&signature[..].try_into()?),
            )
            .is_ok())
    }
}

pub fn init_signing_key(
    preferred_algorithm_combination: AlgorithmCombination,
    input: String,
) -> Result<SigningAlgorithmCombination, Box<dyn Error + Send + Sync>> {
    Ok(match preferred_algorithm_combination {
        AlgorithmCombination::Ed25519phBlake2b512 => {
            SigningAlgorithmCombination::Ed25519phBlake2b512(read_ed25519ph_signing_key(input)?)
        }
        AlgorithmCombination::Ed25519phSha3512 => {
            SigningAlgorithmCombination::Ed25519phSha3512(read_ed25519ph_signing_key(input)?)
        }
        AlgorithmCombination::Ed25519phSha2512 => {
            SigningAlgorithmCombination::Ed25519phSha2512(read_ed25519ph_signing_key(input)?)
        }
        AlgorithmCombination::RsaBlake3 => SigningAlgorithmCombination::RsaBlake3(
            rsa::pss::SigningKey::<blake3::Hasher>::new(read_rsa_private_key(input)?),
        ),
        AlgorithmCombination::RsaBlake2b512 => SigningAlgorithmCombination::RsaBlake2b512(
            rsa::pss::SigningKey::<Blake2b512>::new(read_rsa_private_key(input)?),
        ),
        AlgorithmCombination::RsaSha3512 => SigningAlgorithmCombination::RsaSha3512(
            rsa::pss::SigningKey::<sha3::Sha3_512>::new(read_rsa_private_key(input)?),
        ),
        AlgorithmCombination::RsaSha2512 => SigningAlgorithmCombination::RsaSha2512(
            rsa::pss::SigningKey::<sha2::Sha512>::new(read_rsa_private_key(input)?),
        ),
    })
}

pub fn init_verifying_key(
    preferred_algorithm_combination: AlgorithmCombination,
    input: String,
) -> Result<VerifiyingAlgorithmCombination, Box<dyn Error + Send + Sync>> {
    /*let preferred_algorithm_combination = AlgorithmCombination::from_str(
        &BROKER_CONFIG
            .get_or_init(read_config)
            .get_string("preferred_algorithm")
            .unwrap(),
    )
    .unwrap();*/
    Ok(match preferred_algorithm_combination {
        AlgorithmCombination::Ed25519phBlake2b512 => {
            VerifiyingAlgorithmCombination::Ed25519phBlake2b512(read_ed25519ph_verifying_key(
                input,
            )?)
        }
        AlgorithmCombination::Ed25519phSha3512 => {
            VerifiyingAlgorithmCombination::Ed25519phSha3512(read_ed25519ph_verifying_key(input)?)
        }
        AlgorithmCombination::Ed25519phSha2512 => {
            VerifiyingAlgorithmCombination::Ed25519phSha2512(read_ed25519ph_verifying_key(input)?)
        }
        AlgorithmCombination::RsaBlake3 => VerifiyingAlgorithmCombination::RsaBlake3(
            rsa::pss::VerifyingKey::<blake3::Hasher>::new(read_rsa_verifying_key(input)?),
        ),
        AlgorithmCombination::RsaBlake2b512 => VerifiyingAlgorithmCombination::RsaBlake2b512(
            rsa::pss::VerifyingKey::<Blake2b512>::new(read_rsa_verifying_key(input)?),
        ),
        AlgorithmCombination::RsaSha3512 => VerifiyingAlgorithmCombination::RsaSha3512(
            rsa::pss::VerifyingKey::<sha3::Sha3_512>::new(read_rsa_verifying_key(input)?),
        ),
        AlgorithmCombination::RsaSha2512 => VerifiyingAlgorithmCombination::RsaSha2512(
            rsa::pss::VerifyingKey::<sha2::Sha512>::new(read_rsa_verifying_key(input)?),
        ),
    })
}

fn read_ed25519ph_signing_key(
    input: String,
) -> Result<ed25519_dalek::SigningKey, Box<dyn Error + Send + Sync>> {
    Ok(ed25519_dalek::SigningKey::from_pkcs8_pem(&input)?)
}

fn read_rsa_private_key(input: String) -> Result<rsa::RsaPrivateKey, Box<dyn Error + Send + Sync>> {
    Ok(rsa::RsaPrivateKey::from_pkcs8_pem(&input)?)
}

fn read_ed25519ph_verifying_key(
    input: String,
) -> Result<ed25519_dalek::VerifyingKey, Box<dyn Error + Send + Sync>> {
    Ok(ed25519_dalek::VerifyingKey::from_public_key_pem(&input)?)
}

fn read_rsa_verifying_key(
    input: String,
) -> Result<rsa::RsaPublicKey, Box<dyn Error + Send + Sync>> {
    Ok(rsa::RsaPublicKey::from_public_key_pem(&input)?)
}
