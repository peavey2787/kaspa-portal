use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use kaspa_portal::{
    primitives::NetworkId,
    wallet::key::xpub::{
        derive_and_serialize_xprv, import_xprv_with_metadata, serialize_account_kpub, KPUB_MAX_LEN,
        XPRV_MAX_LEN,
    },
    KaspaPortal,
};
use zeroize::Zeroize;

const FUNDED_XPRV_ENV: &str = "KASPA_PORTAL_E2E_XPRV";
const DEFAULT_STATE_FILE: &str = ".kaspa-portal-e2e/wallet.env";
const LEGACY_STATE_FILE: &str = ".kaspa-portal-e2e/testnet12-wallet.env";
const SOMPI_PER_KAS: u64 = 100_000_000;
const REQUIRED_KAS: u64 = 10;
const REQUIRED_SOMPI: u64 = REQUIRED_KAS * SOMPI_PER_KAS;
const NOT_FUNDED_EXIT_CODE: i32 = 10;

struct Args {
    state_path: PathBuf,
    check_funded: bool,
    network_name: String,
    endpoint: String,
    rest_endpoint: String,
    faucet: String,
}

fn parse_args() -> Result<Args, String> {
    let mut state_path = PathBuf::from(DEFAULT_STATE_FILE);
    let mut check_funded = false;
    let mut network_name = None;
    let mut endpoint = None;
    let mut rest_endpoint = String::new();
    let mut faucet = String::new();
    let mut args = env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == OsStr::new("--state-file") {
            state_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--state-file requires a path".to_owned())?;
        } else if arg == OsStr::new("--network") {
            network_name = Some(
                args.next()
                    .ok_or_else(|| "--network requires a value".to_owned())?
                    .to_string_lossy()
                    .into_owned(),
            );
        } else if arg == OsStr::new("--endpoint") {
            endpoint = Some(
                args.next()
                    .ok_or_else(|| "--endpoint requires a value".to_owned())?
                    .to_string_lossy()
                    .into_owned(),
            );
        } else if arg == OsStr::new("--rest-endpoint") {
            rest_endpoint = args
                .next()
                .ok_or_else(|| "--rest-endpoint requires a value".to_owned())?
                .to_string_lossy()
                .into_owned();
        } else if arg == OsStr::new("--faucet") {
            faucet = args
                .next()
                .ok_or_else(|| "--faucet requires a value".to_owned())?
                .to_string_lossy()
                .into_owned();
        } else if arg == OsStr::new("--check-funded") {
            check_funded = true;
        } else {
            return Err(
                "usage: e2e_wallet [--state-file PATH] --network NAME --endpoint URL [--rest-endpoint URL] [--faucet URL] [--check-funded]"
                    .to_owned(),
            );
        }
    }
    let network_name = network_name.ok_or_else(|| "--network is required".to_owned())?;
    NetworkId::parse(&network_name)?;
    let endpoint = endpoint.ok_or_else(|| "--endpoint is required".to_owned())?;
    if !endpoint.starts_with("ws://") && !endpoint.starts_with("wss://") {
        return Err("--endpoint must use ws:// or wss://".to_owned());
    }
    Ok(Args {
        state_path,
        check_funded,
        network_name,
        endpoint,
        rest_endpoint,
        faucet,
    })
}

fn read_state_xprv(path: &Path) -> Result<Option<String>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let xprv = text.lines().find_map(|line| {
        line.strip_prefix("KASPA_PORTAL_E2E_XPRV=")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    });
    xprv.ok_or_else(|| format!("{} is missing KASPA_PORTAL_E2E_XPRV", path.display()))
        .map(Some)
}

fn serialize_kpub(xprv: &str) -> Result<String, String> {
    let imported = import_xprv_with_metadata(xprv.as_bytes())
        .map_err(|error| format!("invalid E2E XPRV: {error}"))?;
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let length = serialize_account_kpub(&imported.key, imported.parent_fingerprint, &mut encoded)
        .map_err(|error| format!("serialize E2E KPUB: {error}"))?;
    std::str::from_utf8(&encoded[..length])
        .map(str::to_owned)
        .map_err(|error| format!("E2E KPUB is not UTF-8: {error}"))
}

fn wallet_address(xprv: &str, network: NetworkId) -> Result<String, String> {
    let kpub = serialize_kpub(xprv)?;
    let portal = KaspaPortal::builder()
        .network(network)
        .build()
        .map_err(|error| format!("build {network} portal: {error}"))?;
    let wallet = portal
        .wallet()
        .import_kpub(&kpub)
        .map_err(|error| format!("derive E2E wallet: {error}"))?;
    wallet
        .receive_addresses
        .first()
        .cloned()
        .ok_or_else(|| "E2E wallet produced no receive address".to_owned())
}

fn generate_xprv() -> Result<String, String> {
    let mut seed = [0u8; 64];
    getrandom::getrandom(&mut seed).map_err(|error| format!("OS RNG failed: {error}"))?;
    let mut encoded = [0u8; XPRV_MAX_LEN];
    let result = derive_and_serialize_xprv(&seed, &mut encoded)
        .map_err(|error| format!("derive E2E XPRV: {error}"));
    seed.zeroize();
    let length = result?;
    let text = std::str::from_utf8(&encoded[..length])
        .map(str::to_owned)
        .map_err(|error| format!("E2E XPRV is not UTF-8: {error}"));
    encoded.zeroize();
    text
}

fn write_state(path: &Path, xprv: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let mut contents = format!("KASPA_PORTAL_E2E_XPRV={xprv}\n");
    let write_result = fs::write(path, contents.as_bytes())
        .map_err(|error| format!("write {}: {error}", path.display()));
    contents.zeroize();
    write_result?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("protect {}: {error}", path.display()))?;
    }
    Ok(())
}

fn print_wallet(address: &str, args: &Args, state: Option<&Path>) {
    println!("{} E2E wallet address: {address}", args.network_name);
    if !args.faucet.trim().is_empty() {
        println!("{} faucet: {}", args.network_name, args.faucet);
    }
    println!("Required funded balance: at least {REQUIRED_KAS} KAS");
    if let Some(path) = state {
        println!("Local test-only XPRV state: {}", path.display());
    } else {
        println!("Using {FUNDED_XPRV_ENV} from the environment; no secret was written by this helper.");
    }
}

fn format_kas(sompi: u64) -> String {
    format!("{}.{:08}", sompi / SOMPI_PER_KAS, sompi % SOMPI_PER_KAS)
}

fn parse_rest_balance(value: &serde_json::Value) -> Result<u64, String> {
    let balance = value
        .get("balance")
        .or_else(|| value.pointer("/data/balance"))
        .ok_or_else(|| "REST balance response is missing balance".to_owned())?;
    if let Some(number) = balance.as_u64() {
        return Ok(number);
    }
    if let Some(text) = balance.as_str() {
        return text
            .parse::<u64>()
            .map_err(|_| "REST balance is not a valid u64".to_owned());
    }
    Err("REST balance must be a u64 number or decimal string".to_owned())
}

async fn rest_balance(address: &str, args: &Args) -> Result<u64, String> {
    if args.rest_endpoint.trim().is_empty() {
        return Err("no REST endpoint configured".to_owned());
    }
    let url = format!(
        "{}/addresses/{address}/balance",
        args.rest_endpoint.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| format!("build REST client: {error}"))?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("query {url}: {error}"))?
        .error_for_status()
        .map_err(|error| format!("query {url}: {error}"))?;
    let value = response
        .json::<serde_json::Value>()
        .await
        .map_err(|error| format!("decode {url}: {error}"))?;
    parse_rest_balance(&value)
}

async fn funded_balance(
    xprv: &str,
    address: &str,
    args: &Args,
    network: NetworkId,
) -> Result<u64, String> {
    match rest_balance(address, args).await {
        Ok(balance) => return Ok(balance),
        Err(error) if !args.rest_endpoint.trim().is_empty() => {
            eprintln!(
                "WARNING: {} REST balance check failed ({error}); falling back to wRPC {}",
                args.network_name, args.endpoint
            );
        }
        Err(_) => {}
    }

    let kpub = serialize_kpub(xprv)?;
    let portal = KaspaPortal::builder()
        .network(network)
        .endpoint(args.endpoint.clone())
        .timeout_ms(15_000)
        .max_retries(3)
        .connect()
        .await
        .map_err(|error| format!("connect to public {} node: {error}", args.network_name))?;
    let wallet = portal
        .wallet()
        .import_kpub(&kpub)
        .map_err(|error| format!("derive E2E wallet: {error}"))?;
    let balance = portal
        .wallet()
        .balance(&wallet)
        .await
        .map_err(|error| format!("query E2E wallet balance: {error}"))?;
    portal
        .disconnect()
        .map_err(|error| format!("disconnect {} portal: {error}", args.network_name))?;
    Ok(balance.total_sompi)
}

async fn run() -> Result<i32, String> {
    let args = parse_args()?;
    let network = NetworkId::parse(&args.network_name)?;
    let mut created = false;
    let (mut xprv, state) = if let Ok(xprv) = env::var(FUNDED_XPRV_ENV) {
        if xprv.trim().is_empty() {
            return Err(format!("{FUNDED_XPRV_ENV} is set but empty"));
        }
        (xprv, None)
    } else if let Some(xprv) = read_state_xprv(&args.state_path)? {
        (xprv, Some(args.state_path.as_path()))
    } else if args.state_path.ends_with(DEFAULT_STATE_FILE) {
        if let Some(xprv) = read_state_xprv(Path::new(LEGACY_STATE_FILE))? {
            write_state(&args.state_path, &xprv)?;
                println!(
                "Migrated the legacy Testnet-12 E2E XPRV into the shared network wallet state."
            );
            (xprv, Some(args.state_path.as_path()))
        } else {
            let xprv = generate_xprv()?;
            created = true;
            (xprv, Some(args.state_path.as_path()))
        }
    } else {
        let xprv = generate_xprv()?;
        created = true;
        (xprv, Some(args.state_path.as_path()))
    };

    let address = wallet_address(&xprv, network)?;
    if created {
        write_state(&args.state_path, &xprv)?;
        println!("Created a dedicated local Kaspa E2E wallet.");
    }
    print_wallet(&address, &args, state);
    if created {
        println!("The private XPRV is intentionally not printed to the console.");
    }

    if !args.check_funded {
        xprv.zeroize();
        return Ok(0);
    }

    println!(
        "Checking the wallet balance on public {}...",
        args.network_name
    );
    let balance = funded_balance(&xprv, &address, &args, network).await;
    xprv.zeroize();
    let balance = balance?;
    if balance < REQUIRED_SOMPI {
        println!(
            "Wallet is not funded enough yet on {}: {} KAS ({balance} sompi); at least {REQUIRED_KAS} KAS is required.",
            args.network_name,
            format_kas(balance)
        );
        return Ok(NOT_FUNDED_EXIT_CODE);
    }
    println!(
        "Wallet funding verified on {}: {} KAS ({balance} sompi).",
        args.network_name,
        format_kas(balance)
    );
    Ok(0)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match run().await {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_rest_balance;

    #[test]
    fn parses_rest_balance_number_and_decimal_string() {
        assert_eq!(
            parse_rest_balance(&serde_json::json!({"balance": 42})).unwrap(),
            42
        );
        assert_eq!(
            parse_rest_balance(&serde_json::json!({"balance": "18446744073709551615"})).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn rejects_missing_or_invalid_rest_balance() {
        assert!(parse_rest_balance(&serde_json::json!({})).is_err());
        assert!(parse_rest_balance(&serde_json::json!({"balance": -1})).is_err());
    }
}
