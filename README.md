# policy-proofs

Proof-carrying authorization for a few sensitive calls. `transfer` accepts only `Proof<"transfer", "payment">`. A read proof does not typecheck in that slot. An action name outside the grant table does not typecheck. Every grant and every call appends a hash-chained HMAC audit event.

This is a hands-on library. It is not Cedar, OPA, or OpenFGA, and it is not a client authorization system.

## Problem

Full ABAC and ReBAC evaluation is a runtime job. TypeScript does not have dependent types, so an arbitrary policy cannot be proved at compile time. The part that can be proved is narrower: a sensitive function demands a phantom proof object whose type parameters are the action and the resource. Grok described that as Ghosts-of-Departed-Proofs style and named OPA, OpenFGA, and Cedar as the runtime engines not to rebuild. Claude asked for the misspelled action to fail the build, plus a signed replayable audit trail.

## Design

- Actions are `read`, `transfer`, and `approve`. Resources are `account` and `payment`.
- `defineGrants` takes a table with exactly those actions. An extra key such as `wire` fails the type checker because the extra key is constrained to `never`.
- `grant` checks the table, an attribute predicate, and, for `transfer` and `approve`, an `owner` or `approver` relation tuple. A deny is an audit event and a `null` proof. An allow mints a proof that carries a private symbol. A cast of a plain object fails `transfer` at runtime because the symbol is missing.
- `transfer` and `readAccount` each require their own proof type and append another audit event.
- `AuditLog` hashes `seq|at|action|resource|subject|decision|prev` with SHA-256 and MACs the hash with HMAC-SHA256. `verify` walks the chain.

## Usage

```ts
import { AuditLog, defineGrants, grant, transfer } from "policy-proofs";

const table = defineGrants({
  read: ["account"],
  transfer: ["payment"],
  approve: ["payment"],
});
const audit = new AuditLog("test-audit-key-01");
const proof = grant({
  table,
  action: "transfer",
  resource: "payment",
  subject: "ada",
  objectId: "pay-1",
  at: "2026-10-17T13:00:00Z",
  attrs: { role: "advisor", sameTenant: true, amountMinor: 2500n },
  tuples: [{ subject: "ada", relation: "approver", object: "pay-1" }],
  allow: (attrs) => attrs.sameTenant && attrs.role !== "auditor",
  audit,
});
if (proof) {
  transfer(proof, 2500n, audit, "2026-10-17T13:00:00Z");
}
```

## Build

```bash
npm ci
npm test
npm run build
npm run test:types
```

## Benchmark

On this machine (Node v25.9.0, 2026-10-17), `npm run bench` granted and transferred 10,000 payments in 48.6 ms and `verify()` returned true. That is one local run. The audit log holds every event in memory.

## Limits

The action and resource sets are fixed. Attribute rules are a TypeScript predicate, not a policy language. Relation checks are a linear scan of tuples, not a graph engine. The HMAC key is a string the caller supplies. There is no key store. `events()` returns a frozen copy. Changing or shortening that copy does not change the log. `verify()` requires sequence numbers 1, 2, 3 with no gaps, then checks the hash and the HMAC. A caller who can import the module can still not forge the symbol without going through `grant`, but a determined cast inside this package could. Do not treat the chain as a legal record.
