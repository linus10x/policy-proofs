import { AuditLog, defineGrants, grant, transfer } from "../dist/index.js";

const table = defineGrants({
  read: ["account"],
  transfer: ["payment"],
  approve: ["payment"],
});
const audit = new AuditLog("bench-audit-key-1");
const n = 10000;
const start = performance.now();
for (let i = 0; i < n; i += 1) {
  const proof = grant({
    table,
    action: "transfer",
    resource: "payment",
    subject: "ada",
    objectId: "pay-1",
    at: "2026-10-17T13:00:00Z",
    attrs: { role: "advisor", sameTenant: true, amountMinor: 100n },
    tuples: [{ subject: "ada", relation: "approver", object: "pay-1" }],
    allow: (attrs) => attrs.sameTenant,
    audit,
  });
  if (proof === null) {
    throw new Error("expected a proof");
  }
  transfer(proof, 100n, audit, "2026-10-17T13:00:00Z");
}
const elapsed = performance.now() - start;
console.log(`policy-proofs ${n} grants and transfers in ${elapsed.toFixed(1)} ms, chain ok ${audit.verify()}`);
