#!/usr/bin/env python3
from pathlib import Path
import re, sys
sys.dont_write_bytecode = True
from manifest import read_package
ROOT=Path(__file__).resolve().parents[2]
errors=[]

def fail(msg): errors.append(msg)
manifest={'package': read_package(ROOT/'Cargo.toml')}
if manifest.get('package',{}).get('name')!='kaspa-portal': fail('root package must be kaspa-portal')
if manifest.get('package',{}).get('version')!='1.0.1': fail('root package must be version 1.0.1')
for manifest_path in [ROOT/'qa/Cargo.toml', ROOT/'qa/benches/Cargo.toml', ROOT/'qa/tests/fuzz/Cargo.toml']:
    if not manifest_path.is_file():
        fail(f'missing QA manifest: {manifest_path.relative_to(ROOT)}')
        continue
    qa_manifest={'package': read_package(manifest_path)}
    if qa_manifest.get('package',{}).get('version')!='1.0.1':
        fail(f'QA package must be version 1.0.1: {manifest_path.relative_to(ROOT)}')
required={'portal','network','chain','wallet','transaction','contract','privacy','indexer','randomness','crypto','primitives','platform'}
actual={x.name for x in (ROOT/'src').iterdir() if x.is_dir()}
missing=required-actual
if missing: fail('missing source domains: '+', '.join(sorted(missing)))
for bad in ['tests','benches','fuzz','crates','apps']:
    if (ROOT/bad).exists(): fail(f'forbidden top-level directory: {bad}')
for needed in ['qa/tests/fuzz','qa/benches','scripts']:
    if not (ROOT/needed).is_dir(): fail(f'missing {needed}')
for needed_file in ['qa/scripts/run-all.sh', 'qa/scripts/run-all.cmd', 'qa/scripts/cleanup_windows_progress_artifacts.py', 'qa/scripts/check_capability_parity.py', 'qa/scripts/check_resource_coverage.py', 'qa/e2e/capabilities.toml', 'qa/resource/profiles.toml', 'qa/scripts/run-e2e-resources.sh', 'qa/scripts/run-e2e-resources.cmd', 'run-all-linux.sh', 'run-all-windows.cmd', 'scripts/run-e2e-browser-linux.sh', 'scripts/run-e2e-browser-windows.cmd', 'scripts/run-e2e-rust-linux.sh', 'scripts/run-e2e-rust-windows.cmd', 'scripts/run-e2e-resources-linux.sh', 'scripts/run-e2e-resources-windows.cmd', 'scripts/run-e2e-soak-linux.sh', 'scripts/run-e2e-soak-windows.cmd', 'qa/src/bin/e2e_wallet.rs', 'qa/e2e/networks.toml', 'qa/scripts/select_e2e_network.py', 'qa/scripts/load-e2e-networks.sh', 'qa/scripts/load-e2e-networks.cmd', 'qa/scripts/prepare-e2e-funding.sh', 'qa/scripts/prepare-e2e-funding.cmd', '.gitignore']:
    if not (ROOT/needed_file).is_file(): fail(f'missing {needed_file}')

windows_runner = ROOT/'qa/scripts/run-all.cmd'
if windows_runner.is_file():
    windows_runner_text = windows_runner.read_text(errors='replace')
    if 'cleanup_windows_progress_artifacts.py' not in windows_runner_text:
        fail('legacy Windows progress-artifact cleanup is not wired into qa/scripts/run-all.cmd')

for runner in [ROOT/'qa/scripts/run-all.sh', ROOT/'qa/scripts/run-all.cmd']:
    if not runner.is_file():
        continue
    runner_text = runner.read_text(errors='replace')
    if 'check_capability_parity.py' not in runner_text:
        fail(f'capability/parity gate is not wired into {runner.relative_to(ROOT)}')
    if 'check_resource_coverage.py' not in runner_text:
        fail(f'resource coverage gate is not wired into {runner.relative_to(ROOT)}')
    for e2e_runner in ['run-e2e-rust', 'run-e2e-browser', 'run-e2e-resources']:
        if e2e_runner not in runner_text:
            fail(f'{e2e_runner} is not wired into {runner.relative_to(ROOT)}')

# Funded E2E setup is role-specific and remains interactive in the same
# invocation. Standard-network and covenant-network funding are verified
# independently so declining one cannot suppress the other role.
network_config = (ROOT/'qa/e2e/networks.toml').read_text(errors='replace')
for required_fragment in [
    'standard_network = "testnet-10"',
    'covenant_network = "testnet-12"',
    '[network.testnet-10]',
    '[network.testnet-12]',
    '[network.mainnet]',
    'wrpc_endpoint = "resolver"',
]:
    if required_fragment not in network_config:
        fail(f'central E2E network configuration is missing: {required_fragment}')
selector = (ROOT/'qa/scripts/select_e2e_network.py').read_text(errors='replace')
resource_probe = (ROOT/'qa/scripts/run_resource_probe.py').read_text(errors='replace')
for required_fragment in [
    '1. testnet-10', '2. testnet-12', '3. mainnet', '4. custom',
    'testnet suffix must be 1..=127', 'KASPA_PORTAL_E2E_STANDARD_NETWORK',
    'KASPA_PORTAL_E2E_COVENANT_NETWORK',
    'PUBLIC_RESOLVERS', '/v{RESOLVER_VERSION}/kaspa/{network}/tls/wrpc/borsh',
]:
    if required_fragment not in selector:
        fail(f'E2E network selector is missing configurable-network behavior: {required_fragment}')
if 'return default_network' not in selector:
    fail('E2E network selector Enter/default path must follow networks.toml, not hard-code TN10')

funding_runners = [
    ROOT/'qa/scripts/prepare-e2e-funding.sh',
    ROOT/'qa/scripts/prepare-e2e-funding.cmd',
]
for runner in funding_runners:
    runner_text = runner.read_text(errors='replace')
    if 'rerun' in runner_text.lower():
        fail(f'funding flow must stay in the same invocation; remove rerun instruction: {runner.relative_to(ROOT)}')
    if '--check-funded' not in runner_text:
        fail(f'funding flow does not verify the selected network balance: {runner.relative_to(ROOT)}')
    if '[Y/N]' not in runner_text:
        fail(f'funding flow is missing the Y/N same-session prompt: {runner.relative_to(ROOT)}')
    if 'SKIP_' not in runner_text or 'FUNDED' not in runner_text:
        fail(f'funding flow cannot skip only one funded network role on N: {runner.relative_to(ROOT)}')
    if runner.suffix == '.cmd':
        if 'choice /C YN' not in runner_text or 'goto :fund_prompt' not in runner_text:
            fail('Windows underfunded Y path must loop to the same funding prompt')
        if 'if "%FUND_RC%"=="10"' not in runner_text:
            fail('Windows funding helper must recognize the underfunded exit code')
    if runner.suffix == '.sh':
        if 'read -r answer' not in runner_text or 'while true' not in runner_text:
            fail('Linux funding helper must keep the Y/N loop in-process')
        if '[[ "$rc" -eq 10 ]]' not in runner_text:
            fail('Linux funding helper must recognize the underfunded exit code')

    # A user's N decision must remain sticky for the rest of the parent run.
    # run-all invokes role preparation before Rust E2E, while standalone Rust/
    # browser runners defensively invoke it too; those nested calls must honor
    # the already-exported role-specific SKIP_*_FUNDED flag instead of asking
    # the same funding question again.
    if runner.suffix == '.cmd':
        if 'FUND_SKIP' not in runner_text or 'if "%FUND_SKIP%"=="1" exit /b 0' not in runner_text:
            fail('Windows funding helper must honor an existing per-role N/skip decision without re-prompting')
    if runner.suffix == '.sh':
        if '[[ "${!skip_var:-0}" == "1" ]]' not in runner_text:
            fail('Linux funding helper must honor an existing per-role N/skip decision without re-prompting')

for orchestrator in [ROOT/'qa/scripts/run-all.sh', ROOT/'qa/scripts/run-all.cmd']:
    text = orchestrator.read_text(errors='replace')
    if 'prepare-e2e-funding' not in text or 'standard' not in text.lower() or 'covenant' not in text.lower():
        fail(f'run-all must prepare standard and covenant funding independently: {orchestrator.relative_to(ROOT)}')

wallet_helper = ROOT/'qa/src/bin/e2e_wallet.rs'
if wallet_helper.is_file():
    wallet_helper_text = wallet_helper.read_text(errors='replace')
    for required_fragment in ['--check-funded', 'balance(&wallet)', 'NOT_FUNDED_EXIT_CODE', '--network', '--endpoint', '--rest-endpoint', 'rest_balance']:
        if required_fragment not in wallet_helper_text:
            fail(f'E2E wallet helper is missing generic funded-network behavior: {required_fragment}')


transport_text = (ROOT/'src/platform/native/websocket.rs').read_text(errors='replace')
platform_text = (ROOT/'src/platform/mod.rs').read_text(errors='replace')
for required_fragment in ['with_config', 'max_retries', 'tokio::time::sleep']:
    if required_fragment not in transport_text:
        fail(f'native WebSocket transport must honor configured connection retries: {required_fragment}')
for required_fragment in ['timeout_ms', 'max_retries', 'with_config']:
    if required_fragment not in platform_text:
        fail(f'platform network client must pass PortalConfig transport policy: {required_fragment}')

# Public Markdown lives under docs/, except for the repository landing README.
if not (ROOT/'docs').is_dir():
    fail('missing docs directory')
for needed_doc in ['docs/ARCHITECTURE.md', 'docs/SECURITY.md', 'docs/PUBLIC_API.md', 'docs/E2E_CAPABILITIES.md']:
    if not (ROOT/needed_doc).is_file():
        fail(f'missing public documentation: {needed_doc}')
for markdown in ROOT.rglob('*.md'):
    rel=markdown.relative_to(ROOT).as_posix()
    if rel != 'README.md' and not rel.startswith('docs/'):
        fail(f'Markdown file must live under docs/: {rel}')
if (ROOT/'README.md').is_file():
    readme=(ROOT/'README.md').read_text(errors='replace')
    if '[docs/PUBLIC_API.md](docs/PUBLIC_API.md)' not in readme:
        fail('README must link to docs/PUBLIC_API.md')
    if '[docs/E2E_CAPABILITIES.md](docs/E2E_CAPABILITIES.md)' not in readme:
        fail('README must link to docs/E2E_CAPABILITIES.md')
# Windows batch files must use CRLF. LF-only batch files can make cmd.exe
# lose nested CALL labels after returning from another subroutine.
for batch_path in ROOT.rglob('*.cmd'):
    if batch_path.is_file():
        batch_bytes = batch_path.read_bytes()
        if b'\n' in batch_bytes.replace(b'\r\n', b''):
            fail(f'Windows batch file must use CRLF line endings: {batch_path.relative_to(ROOT)}')
root_file_names = {path.name for path in ROOT.iterdir() if path.is_file()}
for root_script in sorted(name for name in root_file_names if name.endswith(('.sh', '.cmd'))):
    if root_script not in {'run-all-linux.sh', 'run-all-windows.cmd'}:
        fail(f'only run-all launchers may live at repository root; move script to scripts/: {root_script}')
# These extensionless files were emitted by a historical Windows batch bug:
# `echo ==> Label ...` treats `>` as redirection and creates a file named Label.
# Keep every known artifact forbidden so stale copies are caught immediately.
for stray in ['Kaspa', 'Windows', 'Rust', 'WASM', 'Formatting']:
    if (ROOT/stray).is_file():
        fail(f'stray top-level artifact is forbidden: {stray}')

# In cmd.exe, an unescaped progress marker such as `echo ==> Rust QA` redirects
# stdout into a file named `Rust`. Progress arrows in batch files must escape
# the greater-than sign (`==^>`) so status output can never mutate the repo.
bad_batch_progress = re.compile(r'(?mi)^\s*echo\s+==>')
for batch_path in ROOT.rglob('*.cmd'):
    if not batch_path.is_file():
        continue
    batch_text = batch_path.read_text(errors='replace')
    if bad_batch_progress.search(batch_text):
        fail(
            'Windows batch progress marker contains unescaped > redirection; '
            f'use ==^>: {batch_path.relative_to(ROOT)}'
        )

# Rust documentation examples in production source must be compiled by
# `cargo test --doc`; `ignore` silently turns examples into unverified prose.
for rust_path in (ROOT/'src').rglob('*.rs'):
    rust_text = rust_path.read_text(errors='replace')
    if re.search(r'(?m)^\s*///\s*```ignore\s*$', rust_text):
        fail(f'ignored Rust doctest is forbidden; make it executable or use a non-Rust fence: {rust_path.relative_to(ROOT)}')

# The repository-root launchers must forward resume arguments, and both QA
# runners must expose the WASM-stage resume used after a late compile failure.
root_windows = (ROOT/'run-all-windows.cmd').read_text(errors='replace')
root_linux = (ROOT/'run-all-linux.sh').read_text(errors='replace')
qa_windows = (ROOT/'qa/scripts/run-all.cmd').read_text(errors='replace')
qa_linux = (ROOT/'qa/scripts/run-all.sh').read_text(errors='replace')
if 'run-all.cmd" %*' not in root_windows:
    fail('run-all-windows.cmd must forward command-line arguments to the QA runner')
if 'run-all.sh "$@"' not in root_linux:
    fail('run-all-linux.sh must forward command-line arguments to the QA runner')
if '--from-wasm' not in qa_windows or ':wasm_compile_qa' not in qa_windows:
    fail('Windows run-all must support --from-wasm at the WASM compile stage')
if '--from-wasm' not in qa_linux or 'resume_stage="wasm"' not in qa_linux:
    fail('Linux run-all must support --from-wasm at the WASM compile stage')
if '--from-formatting' not in qa_windows or ':formatting_qa' not in qa_windows:
    fail('Windows run-all must support --from-formatting at the formatting stage')
if '--from-formatting' not in qa_linux or 'resume_stage="formatting"' not in qa_linux:
    fail('Linux run-all must support --from-formatting at the formatting stage')
if '--from-rust-e2e' not in qa_windows or ':rust_e2e_qa' not in qa_windows:
    fail('Windows run-all must support --from-rust-e2e at the Full Rust E2E stage')
if '--from-rust-e2e' not in qa_linux or 'resume_stage="rust-e2e"' not in qa_linux:
    fail('Linux run-all must support --from-rust-e2e at the Full Rust E2E stage')
if '--from-live-e2e' not in qa_windows or 'RUST_E2E_RESUME_ARG=--from-live' not in qa_windows:
    fail('Windows run-all must support --from-live-e2e at the public standard-network Rust E2E stage')
if '--from-live-e2e' not in qa_linux or 'resume_stage="live-e2e"' not in qa_linux:
    fail('Linux run-all must support --from-live-e2e at the public standard-network Rust E2E stage')
if '--from-funded-e2e' not in qa_windows or 'RUST_E2E_RESUME_ARG=--from-funded' not in qa_windows:
    fail('Windows run-all must support --from-funded-e2e at the funded Rust E2E stage')
if '--from-funded-e2e' not in qa_linux or 'resume_stage="funded-e2e"' not in qa_linux:
    fail('Linux run-all must support --from-funded-e2e at the funded Rust E2E stage')
if '--from-browser-e2e' not in qa_windows or ':browser_e2e_qa' not in qa_windows:
    fail('Windows run-all must support --from-browser-e2e at the Full browser/WASM E2E stage')
if '--from-browser-e2e' not in qa_linux or 'resume_stage="browser-e2e"' not in qa_linux:
    fail('Linux run-all must support --from-browser-e2e at the Full browser/WASM E2E stage')
if '--from-resources-e2e' not in qa_windows or ':resource_e2e_qa' not in qa_windows:
    fail('Windows run-all must support --from-resources-e2e at the quick resource/fault E2E stage')
if '--from-resources-e2e' not in qa_linux or 'resume_stage="resources-e2e"' not in qa_linux:
    fail('Linux run-all must support --from-resources-e2e at the quick resource/fault E2E stage')

# npm and npx are .cmd shims on Windows. A batch file that invokes them from
# inside a CALL :label helper without another CALL transfers control into the
# shim instead of returning to the helper, producing "batch label ... - run".
unsafe_cmd_shim = re.compile(r'(?mi)^\s*call\s+:run\s+(?:npm|npx)\b')
for batch_path in ROOT.rglob('*.cmd'):
    if unsafe_cmd_shim.search(batch_path.read_text(errors='replace')):
        fail(
            'Windows npm/npx invocation inside :run must use nested CALL '
            f'(call :run call npm/npx): {batch_path.relative_to(ROOT)}'
        )

# Offline and live E2E are separate integration crates. Keep their helpers split
# so compiling one suite cannot emit dead-code warnings for the other suite.
legacy_support = ROOT/'qa/tests/e2e/support.rs'
if legacy_support.exists():
    fail('shared qa/tests/e2e/support.rs is forbidden; use offline_support.rs/live_support.rs')
for support_file in ['qa/tests/e2e/offline_support.rs', 'qa/tests/e2e/live_support.rs']:
    if not (ROOT/support_file).is_file():
        fail(f'missing split E2E support module: {support_file}')
for root_file, support_name in [
    ('qa/tests/e2e/rust_offline.rs', 'offline_support.rs'),
    ('qa/tests/e2e/rust_live_standard.rs', 'live_support.rs'),
]:
    root_text = (ROOT/root_file).read_text(errors='replace')
    if f'#[path = "{support_name}"]' not in root_text:
        fail(f'{root_file} must use only {support_name}')
    if '#![deny(warnings)]' not in root_text:
        fail(f'{root_file} must deny warnings')
funded_root = (ROOT/'qa/tests/e2e/rust_funded_networks.rs').read_text(errors='replace')
if '#![deny(warnings)]' not in funded_root:
    fail('qa/tests/e2e/rust_funded_networks.rs must deny warnings')

# Live indexer fixtures must use a current wall-clock observation timestamp.
# Indexer lookups purge records older than transaction_ttl_ms before returning them.
live_network_rust = (ROOT/'qa/tests/e2e/live_network_chain.rs').read_text(errors='replace')
live_network_browser = (ROOT/'qa/e2e/browser/scenarios/live_network_chain.mjs').read_text(errors='replace')
live_reads_rust = (ROOT/'qa/tests/e2e/live_transaction_reads.rs').read_text(errors='replace')
live_reads_browser = (ROOT/'qa/e2e/browser/scenarios/live_transaction_reads.mjs').read_text(errors='replace')
if 'observed_at_ms: 1,' in live_network_rust:
    fail('live Rust network/indexer E2E must not insert an immediately-expired observed_at_ms=1 transaction')
if "observed_at_ms: '1'" in live_network_browser:
    fail('live browser network/indexer E2E must not insert an immediately-expired observed_at_ms=1 transaction')
if 'scanned.contains("kaspatest:")' in live_reads_rust:
    fail('live multisig branch E2E must allow a valid empty scan with no returned address strings')
if "JSON.stringify(result.scanned)).toContain('kaspatest:')" in live_reads_browser:
    fail('browser multisig branch E2E must allow a valid empty scan with no returned address strings')

# Exact mass/fee analysis finalizes the PSKB to measure completed signature
# scripts. QA must not feed unsigned planner output into analyze()/analyze_with_fee_rate().
offline_tx = (ROOT/'qa/tests/e2e/offline_transaction.rs').read_text(errors='replace')
resource_standard = (ROOT/'qa/src/resource_probe/standard.rs').read_text(errors='replace')
browser_fixture = (ROOT/'qa/src/bin/browser_parity_fixture.rs').read_text(errors='replace')
if '.analyze_with_fee_rate(&with_payload' in offline_tx:
    fail('offline transaction E2E must analyze a signed/finalizable PSKB, not unsigned with_payload')
if '.analyze(&payload_wire)' in funded_root:
    fail('funded transaction E2E must sign/merge payload_wire before exact mass analysis')
browser_funded_fixture = (ROOT/'qa/src/bin/browser_funded_fixture.rs').read_text(errors='replace')
for rel, text in [
    ('qa/tests/e2e/rust_funded_networks.rs', funded_root),
    ('qa/src/bin/browser_funded_fixture.rs', browser_funded_fixture),
]:
    if 'plan_signed_send_with_adaptive_fee' not in text:
        fail(f'{rel} must adapt funded transaction fees from signed live-network analysis')
    if 'analysis.recommended_fee_sompi' not in text or 'analysis.fee_sufficient' not in text:
        fail(f'{rel} adaptive funded fee flow must consume live recommended fee analysis')
if '.analyze_with_fee_rate(&payload' in resource_standard:
    fail('resource probe must analyze a signed/finalizable PSKB, not unsigned planner output')
if '.analyze_with_fee_rate(&with_payload' in browser_fixture:
    fail('browser parity fixture must analyze a signed/finalizable PSKB')
for rel, text in [
    ('qa/tests/e2e/offline_transaction.rs', offline_tx),
    ('qa/src/resource_probe/standard.rs', resource_standard),
    ('qa/src/bin/browser_parity_fixture.rs', browser_fixture),
]:
    if re.search(r'fn\s+finalizable[^\{]*\{.*?json!\(\s*\[\s*\{', text, re.S):
        fail(f'{rel} finalizable fixture must be a single PSKT object; encode_document adds the PSKB array wrapper')
    if 'partialSigs' in text or re.search(r'fn\s+finalizable_(?:document|analysis_document)', text):
        fail(f'{rel} must not handcraft fake PSKB signatures; use the real compact-KSPT sign/merge path')

offline_support = (ROOT/'qa/tests/e2e/offline_support.rs').read_text(errors='replace')
if 'sign_transaction_account_multi_addr_with_entropy' not in offline_support or 'merge_signed_kspt_into_pskb' not in offline_support:
    fail('offline E2E support must sign planner output through the real account KSPT sign/merge pipeline')
if 'sign_pskb_for_account(&with_payload' not in offline_tx:
    fail('offline transaction E2E must sign its planner-generated payload PSKB before analysis/finalization')
if 'sign_pskb_for_seed(&payload' not in resource_standard:
    fail('resource probe must sign its planner-generated PSKB through the real account signing path')
if 'let organizer = [0x51, 0xac];' in resource_standard:
    fail('resource probe crowdfund organizer output script must satisfy the production 3..=260 byte validation')
if 'organizer_output_spk: &organizer_spk' not in resource_standard or 'value.extend_from_slice(&third);' not in resource_standard:
    fail('resource probe crowdfund fixture must use a supported P2PK organizer output script')
if 'sign_pskb_for_account(&with_payload' not in browser_fixture:
    fail('browser parity fixture must sign its planner-generated payload PSKB through the real account signing path')
browser_scenario = (ROOT/'qa/e2e/browser/scenarios/offline_transaction.mjs').read_text(errors='replace')
if 'fixture.transaction.analysisWire' not in browser_scenario:
    fail('browser offline transaction E2E must analyze/finalize the signed parity fixture wire')
if re.search(r'analyzeWithFeeRate\(\s*withPayload', browser_scenario):
    fail('browser offline transaction E2E must not analyze unsigned withPayload')

# PSKB exact-width u64 fields must stay decimal strings on the JSON wire. This
# protects browser callers from IEEE-754 truncation and matches exact_json.rs.
mutation_text = (ROOT/'src/transaction/interchange/pskt/wire/mutation.rs').read_text(errors='replace')
if 'Value::String(gas.to_string())' not in mutation_text:
    fail('set_tx_lane must encode gas as a canonical decimal string')
if 'Value::from(gas)' in mutation_text:
    fail('set_tx_lane must not encode u64 gas as a JSON number')
for forbidden_launcher in ['RUN-ALL-LINUX.sh', 'RUN-ALL-WINDOWS.cmd']:
    if forbidden_launcher in root_file_names:
        fail(f'uppercase launcher forbidden; use lowercase name: {forbidden_launcher}')
for path in ROOT.rglob('*'):
    if not path.is_file(): continue
    rel=path.relative_to(ROOT).as_posix()
    lower=rel.lower()
    if lower.endswith('.ps1'):
        fail(f'PowerShell script forbidden; use .cmd on Windows: {rel}')
    if lower.endswith('.wasm') or 'kaspa_bg.wasm' in lower or lower.endswith('/kaspa.js'):
        fail(f'official/bundled wasm artifact forbidden: {rel}')
for path in (ROOT/'src').rglob('*.rs'):
    text=path.read_text(errors='replace')
    rel=path.relative_to(ROOT).as_posix()
    # Obsolete role crate names must not remain as Rust paths.
    if re.search(r'\b(crate::)?(offline_signer|online_watcher|shared_signer|wasm_api)::',text):
        fail(f'legacy application path remains: {rel}')
    if rel.startswith('src/randomness/') and re.search(r'\b(bitcoin|btc)\b',text,re.I):
        fail(f'Bitcoin source is forbidden in randomness: {rel}')
    if 'Math.random' in text: fail(f'insecure Math.random use: {rel}')
    if re.search(r'#\s*\[\s*allow\s*\(\s*(?:dead_code|unused(?:_imports|_variables)?)\s*\)\s*\]', text):
        fail(f'warning-suppression attribute is forbidden; remove or wire the code: {rel}')
    if re.search(r'"[0-9]+"\s*u(?:8|16|32|64|128|size)\b', text):
        fail(f'invalid numeric suffix attached to string literal: {rel}')
# Browser-specific implementation is isolated.
for path in (ROOT/'src').rglob('*.rs'):
    rel=path.relative_to(ROOT).as_posix()
    if rel.startswith('src/platform/browser/'): continue
    text=path.read_text(errors='replace')
    if 'web_sys::' in text or 'js_sys::' in text:
        fail(f'browser API leaked outside platform/browser: {rel}')
# Keep production modules bounded and navigable. The BIP39 wordlist is static
# protocol data rather than executable logic and is the sole size exception.
for path in (ROOT/'src').rglob('*.rs'):
    if 'unit-tests' in path.parts or path.name == 'wordlist.rs':
        continue
    line_count = sum(1 for _ in path.open(errors='replace'))
    if line_count > 500:
        fail(f'production source exceeds 500 lines; refactor for SRP: {path.relative_to(ROOT)} ({line_count})')
for directory in (ROOT/'src').rglob('*'):
    if not directory.is_dir() or 'unit-tests' in directory.parts:
        continue
    direct_rust = [item for item in directory.iterdir() if item.is_file() and item.suffix == '.rs']
    if len(direct_rust) > 12:
        fail(f'source folder has more than 12 direct Rust files; regroup it: {directory.relative_to(ROOT)}')
for directory in (ROOT/'src').rglob('*'):
    if directory.is_dir() and directory.name == 'unit_tests':
        fail(f'unit test directory must be named unit-tests: {directory.relative_to(ROOT)}')

# Resolve ordinary Rust `mod name;` declarations in addition to explicit path
# attributes. This catches migration mistakes even when Cargo is unavailable.
mod_re = re.compile(r'(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;')
for path in (ROOT/'src').rglob('*.rs'):
    text = path.read_text(errors='replace')
    module_dir = path.parent if path.name in {'lib.rs', 'main.rs', 'mod.rs'} else path.parent/path.stem
    for match in mod_re.finditer(text):
        before = text[max(0, match.start()-500):match.start()]
        explicit = re.search(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]\s*$', before)
        if explicit:
            continue
        name = match.group(1)
        if not ((module_dir/f'{name}.rs').exists() or (module_dir/name/'mod.rs').exists()):
            fail(f'unresolved module declaration {name} in {path.relative_to(ROOT)}')

# Every explicit #[path = "..."] target must exist relative to the module file.
path_re=re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]')
for path in (ROOT/'src').rglob('*.rs'):
    text=path.read_text(errors='replace')
    for target in path_re.findall(text):
        if not (path.parent/target).exists(): fail(f'missing #[path] target {target} from {path.relative_to(ROOT)}')

# A unit-test source must not be compiled through both an aggregate
# `unit-tests/mod.rs` and a leaf module's explicit `#[path]`. That topology
# makes `super` resolve to different production namespaces and was a source of
# large compile-only failure cascades during the 1.0 refactor.
explicit_test_targets = {}
for path in (ROOT/'src').rglob('*.rs'):
    text = path.read_text(errors='replace')
    for target in path_re.findall(text):
        resolved = (path.parent/target).resolve()
        explicit_test_targets.setdefault(resolved, []).append(path)
for aggregate, owners in list(explicit_test_targets.items()):
    if aggregate.name != 'mod.rs' or aggregate.parent.name != 'unit-tests' or not aggregate.is_file():
        continue
    aggregate_text = aggregate.read_text(errors='replace')
    aggregate_dir = aggregate.parent
    for match in mod_re.finditer(aggregate_text):
        name = match.group(1)
        child_file = (aggregate_dir/f'{name}.rs').resolve()
        child_mod = (aggregate_dir/name/'mod.rs').resolve()
        child = child_file if child_file.is_file() else child_mod
        direct_owners = explicit_test_targets.get(child, []) if child else []
        if direct_owners:
            aggregate_owner = ', '.join(str(owner.relative_to(ROOT)) for owner in owners)
            direct_owner = ', '.join(str(owner.relative_to(ROOT)) for owner in direct_owners)
            fail(
                f'duplicate unit-test mount for {child.relative_to(ROOT)}: '
                f'aggregate owner {aggregate_owner}; direct owner {direct_owner}'
            )

# Repository hygiene and public-surface checks.
for path in ROOT.rglob('*'):
    rel=path.relative_to(ROOT).as_posix()
    if path.is_dir() and path.name in {'__pycache__', '.pytest_cache', '.idea', 'target'}:
        fail(f'generated/local directory must not ship: {rel}')

public_text_paths = [ROOT/'README.md', ROOT/'docs/SECURITY.md', ROOT/'docs/ARCHITECTURE.md', ROOT/'docs/PUBLIC_API.md']
public_text_paths += list((ROOT/'examples').rglob('*')) if (ROOT/'examples').exists() else []
public_text_paths += list((ROOT/'src').rglob('*.rs'))
legacy_surface = re.compile(r'\b(?:offline[-_]signer|online[-_]watcher|shared[-_]signer|WatchWallet|watcher\(\)|signer\(\))\b', re.I)
for path in public_text_paths:
    if not path.is_file():
        continue
    text=path.read_text(errors='replace')
    rel=path.relative_to(ROOT).as_posix()
    if legacy_surface.search(text):
        fail(f'obsolete role terminology remains: {rel}')
    if '2.0.0' in text:
        fail(f'obsolete package version remains: {rel}')

# Every production Rust source file must be reachable from src/lib.rs through
# ordinary or explicit-path module declarations. This catches orphaned migration
# files that Cargo would otherwise never compile.
reachable=set()
queue=[ROOT/'src/lib.rs']
explicit_mod_re=re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', re.M)
while queue:
    current=queue.pop()
    try:
        current=current.resolve()
    except FileNotFoundError:
        continue
    if current in reachable or not current.is_file():
        continue
    reachable.add(current)
    text=current.read_text(errors='replace')
    module_dir=current.parent if current.name in {'lib.rs','main.rs','mod.rs'} else current.parent/current.stem
    explicit_spans=[]
    for match in explicit_mod_re.finditer(text):
        explicit_spans.append(match.span())
        target=(current.parent/match.group(1)).resolve()
        if target.is_file():
            queue.append(target)
    for match in mod_re.finditer(text):
        if any(start <= match.start() < end for start,end in explicit_spans):
            continue
        name=match.group(1)
        file_target=module_dir/f'{name}.rs'
        mod_target=module_dir/name/'mod.rs'
        if file_target.is_file(): queue.append(file_target)
        elif mod_target.is_file(): queue.append(mod_target)

for path in (ROOT/'src').rglob('*.rs'):
    if path.resolve() not in reachable:
        fail(f'orphan Rust source is not reachable from lib.rs: {path.relative_to(ROOT)}')


# Pass 3 functional browser E2E must not accidentally execute the Pass 4
# resource/fault specs. Those require profile JSON and a locally built fault
# server and are executed by run-e2e-resources instead.
for runner in [ROOT/'qa/scripts/run-e2e-browser.sh', ROOT/'qa/scripts/run-e2e-browser.cmd']:
    runner_text = runner.read_text(errors='replace')
    for functional_spec in ['offline.spec.mjs', 'live.spec.mjs', 'funded.spec.mjs', 'storage.spec.mjs', 'cross-browser.spec.mjs']:
        if functional_spec not in runner_text:
            fail(f'functional browser runner is missing {functional_spec}: {runner.relative_to(ROOT)}')
    if re.search(r'(?m)^\s*(?:call\s+:run\s+call\s+)?npx\s+playwright\s+test\s*$', runner_text):
        fail(f'functional browser runner must select Pass 3 specs explicitly: {runner.relative_to(ROOT)}')
    if 'resources.spec.mjs' in runner_text or 'faults.spec.mjs' in runner_text:
        fail(f'Pass 3 browser runner must not execute Pass 4 resource/fault specs: {runner.relative_to(ROOT)}')

# Playwright CLI positional filters are regular expressions matched against full
# test paths. Windows backslashes in selectors (for example tests\\offline...)
# become regex escapes and can result in "No tests found". Match spec basenames
# under testDir instead; this is portable on Windows and Unix.
for runner in [ROOT/'qa/scripts/run-e2e-browser.cmd', ROOT/'qa/scripts/run-e2e-resources.cmd']:
    runner_text = runner.read_text(errors='replace')
    if re.search(r'npx\s+playwright\s+test[^\r\n]*tests\\', runner_text, re.IGNORECASE):
        fail(f'Windows Playwright test filters must not use backslash paths: {runner.relative_to(ROOT)}')

# Browser indexers use the real wall clock. Deterministic fixture timestamps
# such as 100 ms after Unix epoch are immediately expired by transaction TTL.
for rel in [
    'qa/e2e/browser/scenarios/offline_indexer.mjs',
    'qa/e2e/browser/scenarios/browser_storage.mjs',
    'qa/e2e/browser/resource/scenarios.mjs',
]:
    browser_text = (ROOT/rel).read_text(errors='replace')
    if re.search(r"observed_at_ms:\s*['\"](?:1|100|101|102|103)['\"]", browser_text):
        fail(f'browser indexer fixture must use a current wall-clock observed_at_ms: {rel}')

browser_transaction = (ROOT/'qa/e2e/browser/scenarios/offline_transaction.mjs').read_text(errors='replace')
if 'result.sweep.plan.outputs' in browser_transaction:
    fail('WASM planSweep returns PskbPlan directly; browser E2E must read result.sweep.outputs')

# Stealth metadata is a pair of x-only keys, so payment derivation must survive
# encode/decode without depending on the discarded original Y parity.
stealth_metadata = (ROOT/'src/privacy/stealth/metadata.rs').read_text(errors='replace')
stealth_tests = (ROOT/'src/privacy/stealth/unit-tests/mod.rs').read_text(errors='replace')
parity_fixture = (ROOT/'qa/src/bin/browser_parity_fixture.rs').read_text(errors='replace')
if 'scan_pubkey: pubkey_from_xonly(&scan_x)?' not in stealth_metadata or 'spend_pubkey: pubkey_from_xonly(&spend_x)?' not in stealth_metadata:
    fail('derived stealth metadata must canonicalize x-only scan/spend points before payment use')
if 'derived_payment.one_time_pubkey' not in stealth_tests or 'decoded_payment.one_time_pubkey' not in stealth_tests:
    fail('stealth metadata tests must prove payment parity across encode/decode')
if '.generate_payment(&public_metadata, &[0x53; 32])' not in parity_fixture:
    fail('browser parity fixture must derive payment from the public encoded/decoded stealth metadata')

# Browser indexer configuration is a partial camelCase object layered on core
# defaults; portal construction must not deserialize it as a full IndexerConfig.
portal_binding = (ROOT/'src/platform/browser/bindings/portal.rs').read_text(errors='replace')
indexer_binding = (ROOT/'src/platform/browser/bindings/indexer.rs').read_text(errors='replace')
if 'indexer: Option<serde_json::Value>' not in portal_binding:
    fail('browser portal indexer config must remain partial instead of requiring every core field')
if 'parse_browser_indexer_config' not in portal_binding or '"maxTransactions" | "max_transactions"' not in indexer_binding:
    fail('browser indexer config parser must accept partial camelCase configuration')

# wasm-bindgen maps Rust Option<T>::None to JavaScript undefined. Public browser
# APIs that document a null sentinel must therefore construct JsValue::NULL
# explicitly rather than returning Option<String>.
privacy_binding = (ROOT/'src/platform/browser/bindings/core/privacy.rs').read_text(errors='replace')
contract_binding = (ROOT/'src/platform/browser/bindings/core/contract.rs').read_text(errors='replace')
if 'scan_raw_for_preimage' not in privacy_binding or 'None => JsValue::NULL' not in privacy_binding:
    fail('scanRawForPreimage must preserve the documented JavaScript null sentinel')
if 'optional_decimal_js' not in contract_binding or 'None => JsValue::NULL' not in contract_binding:
    fail('optional browser contract decimal methods must preserve documented JavaScript null sentinels')
contract_e2e = (ROOT/'qa/e2e/browser/scenarios/offline_contracts.mjs').read_text(errors='replace')
if 'expect(result.noCltv).toBeNull()' not in contract_e2e or 'expect(result.noCsv).toBeNull()' not in contract_e2e:
    fail('browser contract E2E must exercise documented null optionals')

browser_indexer_e2e = (ROOT/'qa/e2e/browser/scenarios/offline_indexer.mjs').read_text(errors='replace')
for expected in ["metrics.transactions).toBe('2')", "metrics.blocks).toBe('2')", "metrics.matches).toBe('6')"]:
    if expected not in browser_indexer_e2e:
        fail('browser indexer u64 metrics must remain canonical decimal strings in E2E assertions')

resource_browser = (ROOT/'qa/e2e/browser/resource/scenarios.mjs').read_text(errors='replace')
if 'standardNetwork' not in resource_browser or 'covenantNetwork' not in resource_browser:
    fail('browser resource scenarios must route ordinary and covenant work through separate configured networks')

# page.evaluate callbacks must not shadow a destructured `network` argument with
# `const network = portal.network()`. The local declaration creates a temporal
# dead zone and makes the config construction throw before the facade exists.
fault_spec = (ROOT/'qa/e2e/browser/tests/faults.spec.mjs').read_text(errors='replace')
for rel, text in [
    ('qa/e2e/browser/tests/faults.spec.mjs', fault_spec),
    ('qa/e2e/browser/resource/scenarios.mjs', resource_browser),
]:
    if re.search(r'page\.evaluate\(async \(\{[^}]*\bnetwork\b[^}]*\}\).*?const network = portal\.network\(\)', text, re.DOTALL):
        fail(f'browser fault callback shadows its network input and triggers a JavaScript TDZ: {rel}')
    if 'networkName' not in text:
        fail(f'browser fault callback must use an unambiguous networkName input: {rel}')

network_id_source = (ROOT/'src/primitives/mod.rs').read_text(errors='replace')
for required_fragment in ['Testnet(u8)', 'pub fn parse(value: &str)', '1..=127', 'testnet-14']:
    if required_fragment not in network_id_source:
        fail(f'NetworkId must support future configurable testnet-N values: {required_fragment}')

# The obsolete single-network fixture would reintroduce TN12 hard-coding.
if (ROOT/'qa/e2e/testnet12.toml').exists():
    fail('qa/e2e/testnet12.toml is obsolete; use qa/e2e/networks.toml')

resource_exporter = (ROOT/'qa/scripts/export_resource_profiles.py').read_text(errors='replace')
if 'raw in ("true", "false")' not in resource_exporter or 'value = raw == "true"' not in resource_exporter:
    fail('resource profile exporter must parse TOML boolean scalars used by supplemental profiles')

if 'KASPA_PORTAL_E2E_STANDARD_ENDPOINT' not in resource_probe:
    fail('resource probe must use the selected standard-network endpoint')

if errors:
    print('PROJECT CHECK: FAIL')
    for e in errors: print('ERROR:',e)
    sys.exit(1)
print('PROJECT CHECK: PASS')
print(f'Rust source files: {sum(1 for _ in (ROOT/"src").rglob("*.rs"))}')
