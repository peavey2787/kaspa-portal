import { createHash } from "node:crypto";
import { runNistSuite } from "./reference-js/nist.js";

// A deterministic SHA-256 stream makes this implementation-regression test
// reproducible. NIST statistical pass/fail outcomes are deliberately not a
// code-correctness gate: valid random streams can fail individual tests at
// the configured alpha, and some tests are legitimately not applicable to a
// particular stream. The gate verifies that the complete port executes and
// produces structurally valid results without implementation errors.
const byteLength = 131072; // 1,048,576 bits.
const chunks = [];
for (let counter = 0, total = 0; total < byteLength; counter++) {
  const hash = createHash("sha256");
  hash.update("kaspa-portal/nist/reference-stream/v1");
  const encodedCounter = Buffer.allocUnsafe(8);
  encodedCounter.writeBigUInt64BE(BigInt(counter));
  hash.update(encodedCounter);
  const digest = hash.digest();
  chunks.push(digest);
  total += digest.length;
}

const bytes = Buffer.concat(chunks).subarray(0, byteLength);
const lookup = Array.from({ length: 256 }, (_, value) =>
  value.toString(2).padStart(8, "0"),
);
let bits = "";
for (const byte of bytes) bits += lookup[byte];

const results = await runNistSuite(bits);
if (results.length < 16) {
  throw new Error(`expected broad NIST suite, got ${results.length} results`);
}

let notApplicable = 0;
for (const result of results) {
  if (!result.testName) throw new Error("NIST result missing test name");
  const error = result.details?.error;
  if (!error) continue;
  if (error.includes("Test not applicable")) {
    notApplicable += 1;
    continue;
  }
  throw new Error(`${result.testName}: ${error}`);
}

console.log(
  `NIST reference suite executed ${results.length} result rows (${notApplicable} not applicable to the deterministic sample).`,
);
