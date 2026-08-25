#[path = "../fault_server/mod.rs"]
mod fault_server;

use std::io::Write;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let server = match fault_server::FaultServer::bind().await {
        Ok(server) => server,
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::exit(1);
        }
    };
    match server.endpoint() {
        Ok(endpoint) => {
            println!("FAULT_SERVER_URL={endpoint}");
            let _ = std::io::stdout().flush();
        }
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::exit(1);
        }
    }
    if let Err(error) = server.serve().await {
        eprintln!("ERROR: {error}");
        std::process::exit(1);
    }
}
