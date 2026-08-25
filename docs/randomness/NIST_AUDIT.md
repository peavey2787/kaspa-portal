# NIST Port Audit

The JavaScript files under `qa/tests/randomness/nist/reference-js/` are retained as a statistical reference, not as the normative production implementation. The Rust implementation under `src/randomness/health/nist/` is authoritative.

The audit found several reference-code defects that are intentionally **not** copied into Rust:

- `binary-matrix-rank.js`, `linear-complexity.js`, `random-excursions.js`, and `template-matching.js` used `gammaQ` without importing it. The retained QA copies add the missing import so the reference actually produces p-values.
- The reference Runs test used a variance expression that degenerates at an exactly balanced one/zero proportion. Rust uses the SP 800-22 Rev. 1a Runs statistic denominator.
- The reference Random Excursions test used the same visit-count probabilities for every state. Rust computes the state-dependent six-bin probabilities.
- The reference Random Excursions Variant test used a different mean/variance model. Rust uses the SP 800-22 Rev. 1a state-visit statistic.
- Statistical tests are health diagnostics only. Passing them is not evidence that a beacon, extractor, VRF, RNG, or key generator is cryptographically secure.

The full Rust suite exposes the same 18 configured result rows used by the reference runner: frequency, block frequency, runs, longest-run, rank, spectral DFT, both template tests, Maurer universal, linear complexity, serial m=2/m=3, approximate entropy m=2/m=3, forward/backward cumulative sums, random excursions, and random excursions variant.

Normative reference: NIST SP 800-22 Rev. 1a, https://doi.org/10.6028/NIST.SP.800-22r1a
