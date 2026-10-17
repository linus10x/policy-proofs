import { AuditLog } from "./audit.js";

const proofBrand: unique symbol = Symbol("policy-proof");

export const actions = ["read", "transfer", "approve"] as const;
export type ActionName = (typeof actions)[number];

export const resources = ["account", "payment"] as const;
export type ResourceName = (typeof resources)[number];

export type GrantTable = {
  readonly [A in ActionName]: readonly ResourceName[];
};

export type Role = "advisor" | "operator" | "auditor";

export type Attributes = {
  readonly role: Role;
  readonly sameTenant: boolean;
  readonly amountMinor: bigint;
};

export type Relation = "owner" | "approver" | "viewer";

export type RelationTuple = {
  readonly subject: string;
  readonly relation: Relation;
  readonly object: string;
};

export type Proof<A extends ActionName, R extends ResourceName> = {
  readonly [proofBrand]: true;
  readonly action: A;
  readonly resource: R;
  readonly subject: string;
  readonly objectId: string;
  readonly at: string;
};

const SENSITIVE = new Set<ActionName>(["transfer", "approve"]);

type ClosedGrantTable<T> = T & Record<Exclude<keyof T, ActionName>, never>;

export function defineGrants<const T extends GrantTable>(table: ClosedGrantTable<T>): T {
  for (const action of actions) {
    const allowed = table[action];
    if (allowed.length === 0) {
      throw new Error(`grant table has no resources for ${action}`);
    }
    for (const resource of allowed) {
      if (!resources.includes(resource)) {
        throw new Error(`unknown resource ${resource}`);
      }
    }
  }
  return table;
}

export type GrantArgs<A extends ActionName, R extends ResourceName> = {
  readonly table: GrantTable;
  readonly action: A;
  readonly resource: R;
  readonly subject: string;
  readonly objectId: string;
  readonly at: string;
  readonly attrs: Attributes;
  readonly tuples: readonly RelationTuple[];
  readonly allow: (attrs: Attributes) => boolean;
  readonly audit: AuditLog;
};

export function grant<A extends ActionName, R extends ResourceName>(
  args: GrantArgs<A, R>,
): Proof<A, R> | null {
  if (args.subject.trim().length === 0 || args.objectId.trim().length === 0) {
    throw new Error("subject and object are required");
  }
  const allowed = args.table[args.action];
  const listed = allowed.includes(args.resource);
  const related =
    !SENSITIVE.has(args.action) ||
    args.tuples.some(
      (tuple) =>
        tuple.subject === args.subject &&
        tuple.object === args.objectId &&
        (tuple.relation === "owner" || tuple.relation === "approver"),
    );
  const permitted = listed && related && args.allow(args.attrs);
  args.audit.append({
    at: args.at,
    action: args.action,
    resource: args.resource,
    subject: args.subject,
    decision: permitted ? "allow" : "deny",
  });
  if (!permitted) {
    return null;
  }
  return {
    [proofBrand]: true,
    action: args.action,
    resource: args.resource,
    subject: args.subject,
    objectId: args.objectId,
    at: args.at,
  };
}

export function isProof(value: unknown): value is Proof<ActionName, ResourceName> {
  return typeof value === "object" && value !== null && proofBrand in value;
}

export function assertProof<A extends ActionName, R extends ResourceName>(
  value: Proof<A, R>,
  action: A,
  resource: R,
): Proof<A, R> {
  if (!isProof(value) || value.action !== action || value.resource !== resource) {
    throw new Error("missing proof");
  }
  return value;
}

export function transfer(
  proof: Proof<"transfer", "payment">,
  amountMinor: bigint,
  audit: AuditLog,
  at: string,
): { readonly posted: true; readonly amountMinor: bigint } {
  const checked = assertProof(proof, "transfer", "payment");
  if (amountMinor <= 0n) {
    throw new Error("amount must be greater than zero");
  }
  audit.append({
    at,
    action: "transfer",
    resource: "payment",
    subject: checked.subject,
    decision: "allow",
  });
  return { posted: true, amountMinor };
}

export function readAccount(
  proof: Proof<"read", "account">,
  audit: AuditLog,
  at: string,
): { readonly subject: string; readonly objectId: string } {
  const checked = assertProof(proof, "read", "account");
  audit.append({
    at,
    action: "read",
    resource: "account",
    subject: checked.subject,
    decision: "allow",
  });
  return { subject: checked.subject, objectId: checked.objectId };
}
