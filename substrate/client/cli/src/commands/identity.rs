use sp_core::{Pair, ecdsa::PublicKey};
use sp_io::hashing::keccak_256;
use crate::Error;
use clap::Parser;
use array_bytes::bytes2hex;

/// Identity utilities for the cli.
#[derive(Debug, Clone, Parser)]
pub enum IdentitySubcommand {
    /// Generate a new identity with ETH format
    /// Return params contains Seed, Pubkey, AccountId
    Generate,
}

impl IdentitySubcommand {
    /// run the key subcommands
    pub fn run(&self) -> Result<(), Error> {
        match self {
            IdentitySubcommand::Generate => {
                let (pair, seed): (sp_core::ecdsa::Pair, [u8; 32]) = Pair::generate();
                let compress_pk = pair.public().0;
                let pk = PublicKey::from_slice(&compress_pk).map_err(|e| Error::Input(e.to_string()))?.serialize_uncompressed();
                let address = bytes2hex("0x", &keccak_256(&pk[1..])[12..]);
                let public_key = bytes2hex("0x",&compress_pk);
                let secret_seed = bytes2hex("0x", &seed);
                println!(
                    "  Secret seed:      {}\n  \
					Public key (hex): {}\n  \
					Account ID:       {}",
                    secret_seed,
                    public_key,
                    address,
                );
                Ok(())
            },
        }
    }
}

#[test]
fn test_identity_gen() {
    IdentitySubcommand::Generate.run().unwrap();
}
