import { describe, expect, it } from "vitest";
import { AuditLog } from "../src/audit.js";
import {
  defineGrants,
  grant,
  readAccount,
  transfer,
  type Attributes,
  type GrantTable,
  type Proof,
} from "../src/proof.js";

const at = "2026-10-17T13:00:00Z";
const key = "test-audit-key-01";

const table = defineGrants({
  read: ["account"],
  transfer: ["payment"],
  approve: ["payment"],
});

const advisor: Attributes = { role: "advisor", sameTenant: true, amountMinor: 100n };
const allowSameTenant = (attrs: Attributes) => attrs.sameTenant && attrs.role !== "auditor";

function base() {
  return {
    table,
    subject: "ada",
    objectId: "pay-1",
    at,
    attrs: advisor,
    tuples: [{ subject: "ada", relation: "approver" as const, object: "pay-1" }],
    allow: allowSameTenant,
    audit: new AuditLog(key),
  };
}

describe("grants", () => {
  it("mints a transfer proof only when the relation and the predicate hold", () => {
    const args = base();
    const proof = grant({ ...args, action: "transfer", resource: "payment" });
    expect(proof?.action).toBe("transfer");
    expect(args.audit.verify()).toBe(true);
    expect(args.audit.events()[0]?.decision).toBe("allow");
  });

  it("records a deny when the predicate fails or the relation is missing", () => {
    const denied = base();
    const proof = grant({
      ...denied,
      action: "transfer",
      resource: "payment",
      allow: () => false,
    });
    expect(proof).toBeNull();
    const unrelated = base();
    expect(
      grant({
        ...unrelated,
        action: "approve",
        resource: "payment",
        tuples: [{ subject: "ada", relation: "viewer", object: "pay-1" }],
      }),
    ).toBeNull();
    expect(unrelated.audit.events()[0]?.decision).toBe("deny");
  });

  it("does not require a relation for a read", () => {
    const args = base();
    const proof = grant({
      ...args,
      action: "read",
      resource: "account",
      objectId: "acct-1",
      tuples: [],
    });
    expect(proof?.resource).toBe("account");
    if (proof === null) {
      throw new Error("expected a proof");
    }
    const view = readAccount(proof, args.audit, at);
    expect(view.objectId).toBe("acct-1");
    expect(args.audit.events()).toHaveLength(2);
  });

  it("posts a transfer and rejects a non-positive amount", () => {
    const args = base();
    const proof = grant({ ...args, action: "transfer", resource: "payment" });
    if (proof === null) {
      throw new Error("expected a proof");
    }
    expect(transfer(proof, 2500n, args.audit, at).posted).toBe(true);
    expect(() => transfer(proof, 0n, args.audit, at)).toThrow(/greater than zero/);
  });

  it("rejects a forged proof object and a short audit key", () => {
    const forged = {
      action: "transfer",
      resource: "payment",
      subject: "ada",
      objectId: "pay-1",
      at,
    } as Proof<"transfer", "payment">;
    expect(() => transfer(forged, 10n, new AuditLog(key), at)).toThrow(/missing proof/);
    expect(() => new AuditLog("short")).toThrow(/audit key/);
    expect(() =>
      grant({ ...base(), action: "read", resource: "account", subject: " ", objectId: "acct-1" }),
    ).toThrow(/subject and object/);
  });

  it("rejects an empty grant list and a tampered chain", () => {
    expect(() =>
      defineGrants({
        read: ["account"],
        transfer: ["payment"],
        approve: [],
      }),
    ).toThrow(/no resources/);
    const weird = { read: ["nope"], transfer: ["payment"], approve: ["payment"] } as unknown as GrantTable;
    expect(() => defineGrants(weird)).toThrow(/unknown resource/);
    const log = new AuditLog(key);
    log.append({ at, action: "read", resource: "account", subject: "ada", decision: "allow" });
    const event = log.events()[0];
    if (event === undefined) {
      throw new Error("expected an event");
    }
    (event as { mac: string }).mac = "0";
    expect(log.verify()).toBe(false);
  });
});
