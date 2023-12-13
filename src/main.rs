use std::path::PathBuf;

use instant_acme::LetsEncrypt;
use anydns_example::{run_server, certs::{AccountMode, CertsMode}};

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // Provision a new certificate, even if one already exists
    #[arg(short, long, action)]
    new_cert: bool,
    // Reset all configuration, creating a new letsencrypt account and provisioning a new certificate
    #[arg(short, long, action)]
    reset: bool,
    // Directory in which to store account information and certificate
    #[arg(short, long, default_value = "./config")]
    config_dir: PathBuf,
    // Use the letsencrypt staging environment instead of provisioning a real certificate (note: if there is already a certificate and you don't pass --new-cert or --reset, that certificate will be used, even if it does not match the environment specified with this option)
    #[arg(short, long, action)]
    staging: bool,
}

fn main() {
    // Serve an echo service over HTTPS, with proper error handling.
    let cli = Cli::parse();
    let (account_mode, cert_mode) = {
        match (cli.reset, cli.new_cert) {
            (true, _) => (AccountMode::ForceNew, CertsMode::ForceNew),
            (false, true) => (AccountMode::Reuse, CertsMode::ForceNew),
            (false, false) => (AccountMode::Reuse, CertsMode::Reuse),
        }
    };
    let le_environment = {
        if cli.staging { LetsEncrypt::Staging } else { LetsEncrypt::Production }
    };
    if let Err(e) = run_server(cert_mode, account_mode, le_environment, &cli.config_dir) {
        eprintln!("FAILED: {}", e);
        std::process::exit(1);
    }
}
