import { createHash, createHmac } from "node:crypto";

export type Decision = "allow" | "deny";

export type AuditInput = {
  readonly at: string;
  readonly action: string;
  readonly resource: string;
  readonly subject: string;
  readonly decision: Decision;
};

export type AuditEvent = AuditInput & {
  readonly seq: number;
  readonly prev: string;
  readonly hash: string;
  readonly mac: string;
};

export class AuditLog {
  readonly #key: string;
  readonly #events: AuditEvent[] = [];

  constructor(key: string) {
    if (key.length < 16) {
      throw new Error("audit key must be at least 16 characters");
    }
    this.#key = key;
  }

  append(input: AuditInput): AuditEvent {
    const prev = this.#events.at(-1)?.hash ?? "GENESIS";
    const seq = this.#events.length + 1;
    const body = `${seq.toString()}|${input.at}|${input.action}|${input.resource}|${input.subject}|${input.decision}|${prev}`;
    const hash = createHash("sha256").update(body).digest("hex");
    const mac = createHmac("sha256", this.#key).update(hash).digest("hex");
    const event: AuditEvent = { ...input, seq, prev, hash, mac };
    this.#events.push(event);
    return event;
  }

  events(): readonly AuditEvent[] {
    return this.#events;
  }

  verify(): boolean {
    let prev = "GENESIS";
    for (const event of this.#events) {
      const body = `${event.seq.toString()}|${event.at}|${event.action}|${event.resource}|${event.subject}|${event.decision}|${prev}`;
      const hash = createHash("sha256").update(body).digest("hex");
      const mac = createHmac("sha256", this.#key).update(hash).digest("hex");
      if (event.prev !== prev || event.hash !== hash || event.mac !== mac) {
        return false;
      }
      prev = event.hash;
    }
    return true;
  }
}
