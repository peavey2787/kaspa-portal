//! Compile-time proof that a sink must decide what covenant execution evidence means.

macro_rules! sink_contract {
    ($name:ident, $fence:literal, $covenant_execution:literal) => {
        #[doc = concat!(
            "```", $fence, "
",
            "use kaspa_portal::transaction::interchange::kspt::wire::*;
",
            "struct Sink;
",
            "impl DecodeSink for Sink {
",
            "    type Error = ();
",
            "    fn global(&mut self, _: Global<'_>) -> Result<(), ()> { Ok(()) }
",
            "    fn input(&mut self, _: u32, _: Input<'_>, _: u8) -> Result<(), ()> { Ok(()) }
",
            "    fn signature(&mut self, _: u32, _: u8, _: Signature) -> Result<(), ()> { Ok(()) }
",
            "    fn redeem(&mut self, _: u32, _: &[u8]) -> Result<(), ()> { Ok(()) }
",
            "    fn output(&mut self, _: u8, _: Output<'_>) -> Result<(), ()> { Ok(()) }
",
            "    fn network(&mut self, _: u8) -> Result<(), ()> { Ok(()) }
",
            "    fn stealth(&mut self, _: [u8; 32]) -> Result<(), ()> { Ok(()) }
",
            "    fn input_derivation(&mut self, _: u8, _: Derivation) -> Result<(), ()> { Ok(()) }
",
            "    fn output_derivation(&mut self, _: u8, _: Derivation) -> Result<(), ()> { Ok(()) }
",
            "    fn input_ms45(&mut self, _: u8, _: Ms45Derivation) -> Result<(), ()> { Ok(()) }
",
            "    fn output_ms45(&mut self, _: u8, _: Ms45Derivation) -> Result<(), ()> { Ok(()) }
",
            "    fn covenant(&mut self, _: u8, _: u16, _: [u8; 32]) -> Result<(), ()> { Ok(()) }
",
            $covenant_execution, "
",
            "}
",
            "```",
        )]
        pub struct $name;
    };
}

sink_contract!(
    AnExplicitSinkCompiles,
    "",
    "    fn covenant_execution(&mut self, _: u8, _: CovenantExecution) -> Result<(), ()> { Ok(()) }"
);
sink_contract!(ASinkCannotSilentlyDropCovenantExecution, "compile_fail", "");
