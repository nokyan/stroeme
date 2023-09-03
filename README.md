# stroeme

Centralized deployment, decentralized delivery.

## About

Stroeme is both a library and two programs written in Rust to allow for centralized deployment of files and decentralized delivery of said files.

## How it works

Stroeme networks have one server called Broker and many other servers called Distributors. The Broker initially offers files for download, along with a list of all downloadable files, its public key and signatures for both the file list itself and all the files. A volunteering Distributor can register with the Broker and be enlisted in the Broker's list of Distributors. A client wanting to download files can then ask the Broker for a list of some random Distributors, the file list (+ signature) and the Broker's public key. The client can then download the file (+ the Broker's signature) from one of the supplied Distributors.

## How to run

### Broker

If you want to run a Broker, run the following command:

```sh
cargo run --bin broker
```

Please make sure to adjust the configuration in StroemeBroker.toml accordingly. There must either be an ed25519 keypair or RSA keypair in PKCS#8 PEM format at the specified locations.

### Distributor

If you want to run a Broker, run the following command:

```sh
cargo run --bin distributor
```

Please make sure to adjust the configuration in StroemeDistributor.toml accordingly. You must enter your URL as well as the Broker's URL.

## General Progress

All of this is very work in progress, there's basically no documentation and the signing/verifying mechanism has not been audited by a security professional. Use at your own risk.

## To-do

This to-do list is not exhaustive and is randomly sorted.

- Broker
  - Detect file changes/additions/removals
  - Detect malicious or very slow Distributors and stop recommending them to clients
  - Documentation
  - Proper logging
- Distributor
  - Periodically check whether there are changes in the Broker's file list and sync accordingly
  - Better error handling
  - Fix the issue where file verifications don't work 10% or so of the time
  - Documentation
  - Proper logging
- Library
  - Lots of documentation
