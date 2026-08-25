use kaspa_portal::{
    indexer::query::{PageRequest, TransactionQuery},
    KaspaPortal, Result,
};

fn main() -> Result<()> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "kaspa:example".into());
    let portal = KaspaPortal::builder().build()?;
    let indexer = portal.indexer();
    indexer.start()?;
    let matcher_id = indexer.watch_address(address.clone())?;
    let page = indexer.transactions(TransactionQuery {
        address: Some(address),
        page: PageRequest::default(),
        ..Default::default()
    })?;
    println!("matcher={matcher_id}, indexed={}", page.items.len());
    Ok(())
}
