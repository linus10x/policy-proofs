import { expectType } from "tsd";
import { defineGrants, grant, readAccount, transfer, type Proof } from "../src/proof.js";
import { AuditLog } from "../src/audit.js";

const table = defineGrants({
  read: ["account"],
  transfer: ["payment"],
  approve: ["payment"],
});

defineGrants({
  read: ["account"],
  transfer: ["payment"],
  approve: ["payment"],
  // @ts-expect-error wire is not an action
  wire: ["payment"],
});

declare const readProof: Proof<"read", "account">;
declare const transferProof: Proof<"transfer", "payment">;
declare const audit: AuditLog;

// @ts-expect-error a read proof cannot authorize a transfer
transfer(readProof, 1n, audit, "2026-10-17T13:00:00Z");

expectType<{ readonly posted: true; readonly amountMinor: bigint }>(
  transfer(transferProof, 1n, audit, "2026-10-17T13:00:00Z"),
);

expectType<{ readonly subject: string; readonly objectId: string }>(
  readAccount(readProof, audit, "2026-10-17T13:00:00Z"),
);

grant({
  table,
  // @ts-expect-error nope is not an action
  action: "nope",
  resource: "payment",
  subject: "ada",
  objectId: "pay-1",
  at: "2026-10-17T13:00:00Z",
  attrs: { role: "advisor", sameTenant: true, amountMinor: 1n },
  tuples: [],
  allow: () => true,
  audit,
});
