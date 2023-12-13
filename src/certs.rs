use std::{io::{Write, self}, time::Duration, fs::File, net::{SocketAddr, Ipv6Addr}, convert::Infallible, sync::Arc, path::PathBuf};


use rcgen::{Certificate, CertificateParams, DistinguishedName};
use tokio::{time::sleep, sync::oneshot};
use tracing::{error, info};

use hyper::{server::conn::AddrIncoming, service::{service_fn, make_service_fn}, Response, Request, Body, Server};

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, AccountCredentials,
};

#[derive(PartialEq, Eq)]
pub enum CertsMode {
    Reuse,
    ForceNew,
}

#[derive(PartialEq, Eq)]
pub enum AccountMode {
    Reuse,
    ForceNew,
}

pub async fn get_cert(
    ip: Ipv6Addr,
    domain: &str,
    config_dir: &PathBuf,
    certs_mode: CertsMode,
    account_mode: AccountMode,
    le_environment: LetsEncrypt,
) -> anyhow::Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    tracing_subscriber::fmt::init();
    
    let certs_filename = config_dir.join("fullchain.pem");
    let key_filename = config_dir.join("privkey.pem");

    if certs_mode == CertsMode::Reuse {
        // Try to get the private key and certificate chain from storage
        if let Ok(r) = load_certs_from_file(&certs_filename, &key_filename).await {
            return Ok(r)
        }
    }

    // Not available, so we'll need to make new ones
    let account = get_account(&(config_dir.join("creds.json")), account_mode, le_environment).await?;

    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.
    let identifier = Identifier::Dns(domain.to_string());
    let mut order = account
        .new_order(&NewOrder {
            
            identifiers: &[identifier],
        })
        .await
        .unwrap();

    let state = order.state();
    info!("order state: {:#?}", state);
    
    let names = {
        match state.status {
            OrderStatus::Pending => do_challenge(&mut order, ip).await?,
            OrderStatus::Ready => {
                order.authorizations().await.unwrap()
                    .into_iter()
                    .map(|auth| auth.identifier)
                    .map(|Identifier::Dns(identifier)| identifier)
                    .collect()
            }
            _ => panic!("Unexpected state: {:?}", state.status),
        }
    };


    let state = order.state();
    if state.status != OrderStatus::Ready {
        return Err(anyhow::anyhow!(
            "unexpected order status: {:?}",
            state.status
        ));
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.

    let mut params = CertificateParams::new(names.clone());
    params.distinguished_name = DistinguishedName::new();
    let cert = Certificate::from_params(params).unwrap();
    let csr = cert.serialize_request_der()?;

    // Finalize the order and print certificate chain, private key and account credentials.

    order.finalize(&csr).await.unwrap();
    let cert_chain_pem = loop {
        match order.certificate().await.unwrap() {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };

    // info!("certficate chain:\n\n{}", cert_chain_pem);
    // Write the certificate chain
    let mut cert_chain_file = File::create(certs_filename)?;
    cert_chain_file.write_all(cert_chain_pem.as_bytes())?;
    
    let priv_key_pem = cert.serialize_private_key_pem();
    // info!("private key:\n\n{}", priv_key_pem);
    let mut priv_key_file = File::create(key_filename)?;
    priv_key_file.write_all(priv_key_pem.as_bytes())?;
    
    let certs = parse_certs(cert_chain_pem)?;
    let key = parse_private_key(priv_key_pem)?;
    
    Ok((certs, key))
}

async fn do_challenge(order: &mut instant_acme::Order, ip: Ipv6Addr) -> Result<Vec<String>, anyhow::Error> {
    let mut server_thread: Option<_> = None;
    let mut server_trigger: Option<_> = None;
    let authorizations = order.authorizations().await.unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("no http01 challenge found"))?;

        let Identifier::Dns(identifier) = &authz.identifier;

        // Start up the http server and provide the challenge response
        let _token = &challenge.token;
        let resp = order.key_authorization(challenge).as_str().to_string();
        let resp_arc = Arc::new(resp);

        let addr = SocketAddr::from((ip, 80));
        let incoming = AddrIncoming::bind(&addr)?;

        let service =
            make_service_fn(move |_socket| {
                println!("Got challenge query!");
                let resp_arc = resp_arc.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(move |_: Request<Body>| {
                        let resp_arc = resp_arc.clone();
                        async move {
                            Ok::<_, Infallible>(
                                Response::new(Body::from(resp_arc.as_ref().to_string()))
                            )
                        }
                    }))
                }
            });

        // Prepare a trigger to shut down the server when we're done
        let (tx, rx) = oneshot::channel::<()>();

        let server = Server::builder(incoming).serve(service).with_graceful_shutdown(async {
            rx.await.ok();
        });

        assert!(server_thread.is_none());

        println!("Starting up http server");

        server_thread = Some(tokio::spawn(server));

        server_trigger = Some(tx);
        
        challenges.push((identifier, &challenge.url));
    }
    assert!(server_thread.is_some());
    for (_, url) in &challenges {
        order.set_challenge_ready(url).await.unwrap();
    }
    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    loop {
        sleep(delay).await;
        let state = order.refresh().await.unwrap();
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            info!("order state: {:#?}", state);
            break;
        }

        delay *= 2;
        if delay > Duration::from_secs(10) {
            delay = Duration::from_secs(10)
        }
        tries += 1;
        match tries < 15 {
            true => info!(?state, tries, "order is not ready, waiting {delay:?}"),
            false => {
                error!(tries, "order is not ready: {state:#?}");
                return Err(anyhow::anyhow!("order is not ready"));
            }
        }
    }
    server_trigger.unwrap().send(()).unwrap();
    server_thread.unwrap().await??;
    Ok(challenges.into_iter().map(|(identifier, _)| identifier.to_owned()).collect())
}

async fn load_certs_from_file(cert_filename: &PathBuf, key_filename: &PathBuf) -> anyhow::Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    // Get certificate
    let cert_file = File::open(cert_filename)
        .map_err(|e| error(format!("failed to open {}: {}", cert_filename.to_str().unwrap(), e)))?;
    let mut reader = io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader)        .map_err(|_| {
        println!("Certificates in {} are invalid!", cert_filename.to_str().unwrap());
        error("failed to load certificate".into())})?
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    // Get private key
    let key_file = File::open(key_filename)
        .map_err(|e| error(format!("failed to open {}: {}", key_filename.to_str().unwrap(), e)))?;
    let mut reader = io::BufReader::new(key_file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| {
            println!("{} is not a valid private key file!", key_filename.to_str().unwrap());
            error("failed to load private key".into())
        })?;
    if keys.len() != 1 {
        println!("{} is not a valid private key file!", key_filename.to_str().unwrap());
        return Err(error("expected a single private key".into()).into());
    }

    let key = rustls::PrivateKey(keys.into_iter().next().unwrap());
    
    Ok((certs, key))
}

// Attempts to load acccount information from the given file
// If the file does not exist, creates a new account and saves the details in the given file
async fn get_account(filename: &PathBuf, account_mode: AccountMode, le_environment: LetsEncrypt) -> anyhow::Result<Account> {
    // Try to load credentials from the file
    if account_mode  == AccountMode::Reuse {
        if let Ok(account) = load_account_from_file(filename).await {
            return Ok(account)
        }
    }
    
    println!("Creating new account");
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        le_environment.url(),
        None,
    )
        .await?;
    println!("Saving credentials to {}", filename.to_str().unwrap());
    let mut creds_file = File::create(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename.to_str().unwrap(), e)))?;
    let json_creds = serde_json::to_string_pretty(&credentials).unwrap();
    creds_file.write_all(json_creds.as_bytes())?;

    Ok(account)
}

async fn load_account_from_file(filename: &PathBuf) -> anyhow::Result<Account> {
    let file = File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename.to_str().unwrap(), e)))?;
    let reader = io::BufReader::new(file);
    let creds: AccountCredentials = serde_json::from_reader(reader)?;

    println!("Credentials found in {}", filename.to_str().unwrap());
    let account = Account::from_credentials(creds).await.map_err(
        |e| {
            println!("Failed to sign in using discovered credentials: {}", e);
            e
        })?;
    
    Ok(account)
}

fn parse_private_key(pem: String) -> io::Result<rustls::PrivateKey> {
    let mut reader = pem.as_bytes();
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.len() != 1 {
        println!("{:#?}", keys);
        return Err(error("expected a single private key".into()));
    }

    Ok(rustls::PrivateKey(keys.into_iter().next().unwrap()))
}


fn parse_certs(pem: String) -> io::Result<Vec<rustls::Certificate>> {
    let mut reader = pem.as_bytes();
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs
        .into_iter()
        .map(rustls::Certificate)
        .collect())
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
