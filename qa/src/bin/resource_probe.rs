#[path = "../fault_server/mod.rs"]
mod fault_server;
#[path = "../resource_probe/mod.rs"]
mod resource_probe;

use std::{env, process};

use resource_probe::ProbeConfig;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = match ProbeConfig::from_args(env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ERROR: {error}");
            process::exit(2);
        }
    };
    if let Err(error) = resource_probe::run(config).await {
        eprintln!("ERROR: resource probe failed: {error}");
        process::exit(1);
    }
}
