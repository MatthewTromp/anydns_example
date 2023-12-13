//! Simple HTTPS echo service based on hyper-rustls
//!
//! First parameter is the mandatory port to use.
//! Certificate and private key are hardcoded to sample files.
//! hyper will automatically use HTTP/2 if a client starts talking HTTP/2,
//! otherwise HTTP/1.1 will be used.

use std::convert::Infallible;
use std::fs::create_dir_all;
use std::net::{SocketAddr, Ipv6Addr};
use std::path::{PathBuf};
use std::vec::Vec;
use std::{io};


use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use hyper_rustls::TlsAcceptor;
use hyper_rustls::acceptor::TlsStream;

pub mod certs;
use certs::{get_cert, CertsMode, AccountMode};
use instant_acme::LetsEncrypt;

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
pub async fn run_server(certs_mode: CertsMode, account_mode: AccountMode, le_environment: LetsEncrypt, config_path: &PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    let public_addr = get_public_ipv6()?;
    println!("Detected public IPv6 as {}", public_addr);

    let mut domain = format!("{:032x}", u128::from_be_bytes(public_addr.octets()));
    domain.push_str(".anydns.online");

    println!("Domain to register: {}", domain);

    // This is the path where we store the certificate chain, private key and account credentials
    let domain_config_path = config_path.join(domain.clone());
    create_dir_all(&domain_config_path)?;

    // Get certificate chain and private key (gets from file or creates new ones if not available)
    let (cert_chain, key) = get_cert(public_addr, &domain, &domain_config_path, certs_mode, account_mode, le_environment).await?;
    
    let port = 443;
    let addr = SocketAddr::new(public_addr.into(), port);

    // Build TLS configuration.

    // Create a TCP listener via tokio.
    let incoming = AddrIncoming::bind(&addr)?;
    let acceptor = TlsAcceptor::builder()
        .with_single_cert(cert_chain, key)
        .map_err(|e| error(format!("{}", e)))?
        .with_all_versions_alpn()
        .with_incoming(incoming);
    
    let service =
        make_service_fn(|socket: &TlsStream| {
            // This is where you could slot in your own service!
            let addr = socket.io().unwrap().remote_addr().ip();
            async move {
                Ok::<_, Infallible>(service_fn(move |_: Request<Body>| async move {
                    Ok::<_, Infallible>(
                        Response::new(Body::from(format!("Hello, {addr}!")))
                    )
                }))
            }
        });
    let server = Server::builder(acceptor).serve(service);

    // Run the future, keep going until an error occurs.
    println!("Starting to serve on https://{}", addr);
    println!("Your domain is: {}", domain);
    server.await?;
    Ok(())
}


// Get what is probably this user's publicly routable ipv6
// TODO: prompt the user to confirm, let them choose another one
fn get_public_ipv6() -> io::Result<Ipv6Addr> {
    // Get the list of ip addresses of interfaces on this device
    let addrs = get_if_addrs::get_if_addrs().unwrap();
    let candidate_addrs = addrs.into_iter().filter(
        // Remove loopback addresses
        |i| {
            !i.is_loopback() 
        }
    ).filter_map(
        // Remove ipv4 addresses
        |i| {
            match i.addr {
                get_if_addrs::IfAddr::V4(_) => None,
                get_if_addrs::IfAddr::V6(addr) => Some(addr.ip),
            }
        }
    ).collect::<Vec<Ipv6Addr>>();

    // Hopefully there's only one of these and it's the right one
    // TODO: Fix this. Detect link local addresses, maybe?
    // Or query some kind of service just to be sure?
    assert_eq!(candidate_addrs.len(), 1);

    Ok(candidate_addrs[0])
}
    
