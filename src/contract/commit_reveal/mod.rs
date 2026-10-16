mod reveal;
pub(crate) mod script;

pub use reveal::{read_commit_reveal_reveal, CommitRevealReveal};
pub use script::{build_commit_reveal_script, commit_reveal_script_fields, CommitRevealFields};
