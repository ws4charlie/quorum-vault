// The intent an approver signs, read from its canonical bytes. This is the only place that decides what the page shows as "what you approve":
// it never uses the core's JSON version of the intent, because that is what a lying core would change. Layout: internal/signjob Intent.Canonical.
//
//   "qv-intent-v2\n", then ten fields in this order, each a 4-byte big-endian length and the bytes:
//   kind, id, partition, chain, asset, from, to, amount, not_after (decimal seconds), requested_by

const DOMAIN = "qv-intent-v2\n";
const FIELDS = ["kind", "id", "partition", "chain", "asset", "from", "to", "amount", "not_after", "requested_by"];

export function fromHex(h) {
  if (typeof h !== "string" || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error("not hex");
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
}

export function toHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// parseCanonical returns the fields, or throws when the bytes are not exactly one v2 intent.
export function parseCanonical(bytes) {
  const dec = new TextDecoder("utf-8", { fatal: true });
  const dom = new TextEncoder().encode(DOMAIN);
  if (bytes.length < dom.length || !dom.every((c, i) => bytes[i] === c)) throw new Error("not an intent of this version");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = dom.length;
  const out = {};
  for (const name of FIELDS) {
    if (at + 4 > bytes.length) throw new Error("intent is cut short");
    const n = view.getUint32(at);
    at += 4;
    if (at + n > bytes.length) throw new Error("intent is cut short");
    out[name] = dec.decode(bytes.subarray(at, at + n));
    at += n;
  }
  if (at !== bytes.length) throw new Error("intent has extra bytes");
  if (!/^[0-9]+$/.test(out.amount) || !/^[0-9]+$/.test(out.not_after)) throw new Error("intent has a number that is not a number");
  return out;
}

// checkedIntent decides whether the core's answer may be trusted: the hash must be SHA-256 of the canonical bytes, the bytes must be a
// withdrawal, and it must be the withdrawal that was asked for. Anything else throws, and the page shows nothing to approve.
export async function checkedIntent(answer, wantedID) {
  const canonical = fromHex(answer.canonical);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", canonical));
  if (toHex(hash) !== String(answer.hash).toLowerCase()) {
    throw new Error("The hash the core sent is not the hash of the intent it sent. Nothing was signed.");
  }
  const intent = parseCanonical(canonical);
  if (intent.kind !== "withdrawal") throw new Error("This is not a withdrawal (" + intent.kind + "). Nothing was signed.");
  if (intent.id !== wantedID) throw new Error("The core answered with another withdrawal (" + intent.id + "). Nothing was signed.");
  return { intent, hash };
}

// amountText shows base units as a decimal number when the asset's decimals are known, always with the base units next to it.
export function amountText(amount, asset, decimals) {
  const d = decimals && decimals[asset];
  if (!Number.isInteger(d) || d <= 0) return amount + " " + asset + " (base units)";
  const s = amount.padStart(d + 1, "0");
  const whole = s.slice(0, -d);
  const frac = s.slice(-d).replace(/0+$/, "");
  return whole + (frac ? "." + frac : "") + " " + asset + " (" + amount + " base units)";
}

// sentence is the plain words of the intent.
export function sentence(i, decimals) {
  const until = new Date(Number(i.not_after) * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  return "Send " + amountText(i.amount, i.asset, decimals) + " to " + i.to + " on " + i.chain + ", paid from the pool " + i.partition +
    ". Requested by " + i.requested_by + ". Valid until " + until + ".";
}
