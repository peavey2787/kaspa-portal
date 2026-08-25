mod crypto;
mod fault;
mod indexer;
mod network;
mod standard;

use std::{io::Write, str::FromStr, time::Duration};

use kaspa_portal::primitives::NetworkId;

pub struct ProbeConfig {
    pub scenario: ProbeScenario,
    pub warmup: usize,
    pub batches: usize,
    pub iterations: usize,
    pub idle_ms: u64,
    pub endpoint: String,
}

#[derive(Clone, Copy)]
pub enum ProbeScenario {
    Standard,
    Network,
    Indexer,
    Crypto,
    Fault,
}

impl FromStr for ProbeScenario {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "standard" => Ok(Self::Standard),
            "network" => Ok(Self::Network),
            "indexer" => Ok(Self::Indexer),
            "crypto" => Ok(Self::Crypto),
            "fault" => Ok(Self::Fault),
            other => Err(format!("unknown scenario: {other}")),
        }
    }
}

impl ProbeConfig {
    pub fn from_args(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let scenario = args
            .next()
            .ok_or_else(|| {
                "usage: resource_probe SCENARIO --warmup N --batches N --iterations N \
                 --idle-ms N [--endpoint URL]"
                    .to_string()
            })?
            .parse()?;
        let mut config = Self {
            scenario,
            warmup: 1,
            batches: 1,
            iterations: 1,
            idle_ms: 3_000,
            endpoint: std::env::var("KASPA_PORTAL_E2E_STANDARD_ENDPOINT")
                .or_else(|_| std::env::var("KASPA_PORTAL_E2E_ENDPOINT"))
                .unwrap_or_else(|_| {
                    "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/borsh".to_string()
                }),
        };
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?;
            match flag.as_str() {
                "--warmup" => config.warmup = parse_positive(&value, "warmup")?,
                "--batches" => config.batches = parse_positive(&value, "batches")?,
                "--iterations" => config.iterations = parse_positive(&value, "iterations")?,
                "--idle-ms" => {
                    config.idle_ms = value
                        .parse()
                        .map_err(|_| "invalid idle-ms".to_string())?
                }
                "--endpoint" => config.endpoint = value,
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(config)
    }
}

pub fn standard_network_name() -> String {
    std::env::var("KASPA_PORTAL_E2E_STANDARD_NETWORK")
        .unwrap_or_else(|_| "testnet-10".to_owned())
}

pub fn standard_network() -> NetworkId {
    NetworkId::parse(&standard_network_name()).expect("valid standard resource network")
}

pub fn covenant_network() -> NetworkId {
    let name = std::env::var("KASPA_PORTAL_E2E_COVENANT_NETWORK")
        .unwrap_or_else(|_| "testnet-12".to_owned());
    NetworkId::parse(&name).expect("valid covenant resource network")
}

fn parse_positive(value: &str, label: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {label}"))?;
    if parsed == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(parsed)
}

pub async fn run(config: ProbeConfig) -> Result<(), String> {
    emit("warmup", None);
    for index in 0..config.warmup {
        run_one(config.scenario, index, &config.endpoint).await?;
    }
    emit("baseline", None);
    for batch in 0..config.batches {
        for iteration in 0..config.iterations {
            run_one(config.scenario, iteration, &config.endpoint).await?;
        }
        emit("batch", Some(batch));
    }
    emit("idle_begin", None);
    tokio::time::sleep(Duration::from_millis(config.idle_ms)).await;
    emit("idle_end", None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    emit("done", None);
    Ok(())
}

async fn run_one(scenario: ProbeScenario, iteration: usize, endpoint: &str) -> Result<(), String> {
    match scenario {
        ProbeScenario::Standard => standard::run(iteration),
        ProbeScenario::Network => network::run(endpoint).await,
        ProbeScenario::Indexer => indexer::run(iteration),
        ProbeScenario::Crypto => crypto::run(iteration),
        ProbeScenario::Fault => fault::run(iteration).await,
    }
}

fn emit(event: &str, index: Option<usize>) {
    match index {
        Some(index) => println!(r#"{{"event":"{event}","index":{index}}}"#),
        None => println!(r#"{{"event":"{event}"}}"#),
    }
    let _ = std::io::stdout().flush();
}
