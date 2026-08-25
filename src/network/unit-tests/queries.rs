use crate::{
    network::queries::utxos::{fetch_for_address, fetch_for_addresses},
    test_support::{fail_network_client, ready},
};

#[test]
fn utxo_query_boundaries_reject_invalid_addresses_before_transport() {
    let client = fail_network_client();
    assert!(ready(fetch_for_address(&client, "not-an-address")).is_err());
    assert!(ready(fetch_for_addresses(
        &client,
        &["not-an-address".to_string()],
    ))
    .is_err());
}

#[test]
fn network_queries_propagate_transport_fail_closed() {
    use crate::network::queries::{blocks, chain, fees};

    const ADDRESS: &str = "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
    let client = fail_network_client();
    let transport_error = "test transport unavailable";

    assert!(ready(fetch_for_address(&client, ADDRESS))
        .expect_err("utxo transport")
        .contains(transport_error));
    assert!(ready(blocks::get_raw(&client, &[0x11; 32]))
        .expect_err("block transport")
        .contains(transport_error));
    assert!(ready(chain::virtual_daa_score(&client))
        .expect_err("dag transport")
        .contains(transport_error));
    assert!(ready(fees::get(&client))
        .expect_err("fees transport")
        .contains(transport_error));
}
