// The approval page: sign in (OIDC authorization code with PKCE), show a withdrawal in plain words, approve it with a passkey, enrol a passkey.
// Plain JavaScript, no framework, nothing from another site. The access token lives in this module's memory only: a reload signs in again.
//
// What this page can and cannot promise: it checks that the core's hash is the hash of the canonical intent it shows you, which protects against a
// lying core. It cannot protect against a replaced page, which could show one thing and sign another. See docs/limits.md.
import { checkedIntent, sentence, toHex } from "./intent.js";

const app = document.getElementById("app");
let cfg;
let token = null; // the access token, in memory only
let claims = {};

// ---- small helpers ----
const enc = new TextEncoder();
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

// h builds an element. Text goes in as text, never as HTML, so nothing a server sends can become markup.
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "onclick") e.addEventListener("click", v);
    else if (k === "onsubmit") e.addEventListener("submit", v);
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}
const show = (...nodes) => app.replaceChildren(...nodes);
const fail = (text) => h("p", { class: "bad", role: "alert" }, text);
const note = (text) => h("p", { class: "note" }, text);

// ---- sign in ----
async function discovery() {
  const r = await fetch(cfg.issuer + "/.well-known/openid-configuration", { credentials: "omit" });
  if (!r.ok) throw new Error("the identity provider's discovery answered " + r.status);
  return r.json();
}

// login sends the browser to the identity provider. fresh asks it to authenticate again even if a session exists (the step-up rule).
async function login(returnTo, fresh) {
  const d = await discovery();
  const verifier = b64u(random(32));
  const state = b64u(random(16));
  sessionStorage.setItem("qv.login", JSON.stringify({ verifier, state, returnTo }));
  const q = new URLSearchParams({
    response_type: "code", client_id: cfg.client_id, redirect_uri: location.origin + "/", scope: "openid", state,
    code_challenge: b64u(await sha256(enc.encode(verifier))), code_challenge_method: "S256",
  });
  if (fresh) { q.set("prompt", "login"); q.set("max_age", "0"); }
  location.assign(d.authorization_endpoint + "?" + q);
}

// finishLogin runs when the identity provider sent the browser back with a code.
async function finishLogin(params) {
  const saved = JSON.parse(sessionStorage.getItem("qv.login") || "null");
  sessionStorage.removeItem("qv.login");
  history.replaceState(null, "", location.pathname + (saved ? saved.returnTo : "#/"));
  if (params.get("error")) throw new Error("sign-in failed: " + params.get("error") + " " + (params.get("error_description") || ""));
  if (!saved || params.get("state") !== saved.state) throw new Error("sign-in failed: the answer does not belong to a sign-in this page started");
  const d = await discovery();
  const r = await fetch(d.token_endpoint, {
    method: "POST", credentials: "omit", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: params.get("code"), redirect_uri: location.origin + "/", client_id: cfg.client_id, code_verifier: saved.verifier }),
  });
  const t = await r.json().catch(() => ({}));
  if (!r.ok || !t.access_token) throw new Error("sign-in failed: " + (t.error_description || t.error || r.status));
  token = t.access_token;
  claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
}

// The core is the judge of a token; these claims only tell this page who is signed in and when, to avoid sending a request the core must refuse.
const signedInAs = () => claims.sub;
const loginAge = () => Math.floor(Date.now() / 1000) - (claims.auth_time || 0);

function signInButton(returnTo, text, fresh) {
  return h("button", { id: "signin", onclick: () => login(returnTo, fresh).catch((e) => show(fail(String(e.message || e)))) }, text);
}

// ---- the core ----
async function core(method, path, body) {
  const r = await fetch(cfg.api + path, {
    method, credentials: "omit",
    headers: Object.assign({ Authorization: "Bearer " + token }, body ? { "Content-Type": "application/json" } : {}),
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  return { status: r.status, data, challenge: r.headers.get("WWW-Authenticate") || "" };
}
const needsLogin = (r) => r.status === 401;
const needsStepUp = (r) => r.status === 401 && /insufficient_user_authentication/.test(r.challenge);

// ---- views ----
function home() {
  const id = h("input", { id: "wid", name: "withdrawal", required: "required", autocomplete: "off", size: "40", placeholder: "withdrawal id" });
  show(
    h("h2", {}, "Approve a withdrawal"),
    h("form", { onsubmit: (e) => { e.preventDefault(); location.hash = "#/withdrawals/" + encodeURIComponent(id.value.trim()); } },
      h("label", { for: "wid" }, "Withdrawal id "), id, " ", h("button", { type: "submit" }, "Open")),
    token ? "" : h("p", {}, signInButton("#/", "Sign in")),
  );
}

async function withdrawal(id) {
  if (!token) return show(h("h2", {}, "Withdrawal " + id), h("p", {}, "Sign in to see this withdrawal."), signInButton("#/withdrawals/" + encodeURIComponent(id), "Sign in"));
  show(h("h2", {}, "Withdrawal " + id), note("Loading the intent…"));
  const r = await core("GET", "/v2/withdrawals/" + encodeURIComponent(id) + "/intent");
  if (needsLogin(r)) return login("#/withdrawals/" + encodeURIComponent(id), true);
  if (r.status !== 200) return show(h("h2", {}, "Withdrawal " + id), fail("The core answered " + r.status + ": " + (r.data.error || "")));
  let checked;
  try {
    checked = await checkedIntent(r.data, id);
  } catch (e) {
    return show(h("h2", {}, "Withdrawal " + id), fail("REFUSED. " + e.message)); // no button: there is nothing to approve
  }
  const { intent, hash } = checked;
  const result = h("div", { id: "result", "aria-live": "polite" });
  const button = h("button", { id: "approve", onclick: () => approve(id, hash, button, result) }, "Approve with my security key");
  const mine = intent.requested_by === signedInAs();
  show(
    h("h2", {}, "Withdrawal " + id),
    h("p", { class: "sentence", id: "sentence" }, sentence(intent, cfg.decimals)),
    h("dl", {},
      h("dt", {}, "Amount"), h("dd", {}, intent.amount + " " + intent.asset + " (base units)"),
      h("dt", {}, "To"), h("dd", {}, intent.to),
      h("dt", {}, "Chain"), h("dd", {}, intent.chain),
      h("dt", {}, "Pool"), h("dd", {}, intent.partition),
      h("dt", {}, "Requested by"), h("dd", {}, intent.requested_by),
      h("dt", {}, "Valid until"), h("dd", {}, new Date(Number(intent.not_after) * 1000).toISOString()),
      h("dt", {}, "Hash you sign"), h("dd", {}, h("code", { id: "hash" }, toHex(hash))),
      h("dt", {}, "Approvals needed"), h("dd", {}, String(r.data.approvals_required ?? "?"))),
    note("The page computed this hash from the intent shown here, and it matches the core's."),
    mine ? fail("You requested this withdrawal. You cannot approve it.") : button,
    result,
  );
}

async function approve(id, hash, button, result) {
  const say = (...n) => result.replaceChildren(...n);
  button.disabled = true;
  try {
    if (loginAge() > cfg.max_login_age) return login("#/withdrawals/" + encodeURIComponent(id), true); // a fresh sign-in first, so the key touch is not wasted
    say(note("Touch your security key…"));
    const cred = await navigator.credentials.get({ publicKey: { challenge: hash, rpId: location.hostname, userVerification: "required", timeout: 60000 } });
    const a = cred.response;
    const r = await core("POST", "/v2/withdrawals/" + encodeURIComponent(id) + "/approvals", {
      actor: signedInAs(),
      webauthn: { credential_id: b64u(cred.rawId), authenticator_data: b64u(a.authenticatorData), client_data_json: b64u(a.clientDataJSON), signature: b64u(a.signature) },
    });
    if (needsStepUp(r)) return login("#/withdrawals/" + encodeURIComponent(id), true);
    if (r.status !== 200) {
      say(h("p", { id: "outcome", class: "bad" }, "Not approved. The core answered " + r.status + ": " + (r.data.error || "")));
      if (r.status === 401) button.disabled = false;
      return;
    }
    say(h("p", { id: "outcome", class: "ok" }, "Approval accepted by the core."), h("p", { id: "status" }, "Status: " + (r.data.status || "")));
    follow(id, result);
  } catch (e) {
    say(h("p", { id: "outcome", class: "bad" }, "Not approved: " + (e.name === "NotAllowedError" ? "the key was not used (cancelled or timed out)." : e.message)));
    button.disabled = false;
  }
}

// follow shows the withdrawal's status for a while, so the approver sees whether the signing zone accepted the approval.
async function follow(id, result) {
  const line = result.querySelector("#status");
  for (let i = 0; i < 60 && line.isConnected; i++) {
    await new Promise((ok) => setTimeout(ok, 2000));
    const r = await core("GET", "/v2/withdrawals/" + encodeURIComponent(id));
    if (r.status !== 200) return;
    line.textContent = "Status: " + r.data.status + (r.data.failure_reason ? " (" + r.data.failure_reason + ")" : "");
    if (["confirmed", "failed", "voided", "rejected", "cancelled"].includes(r.data.status)) return;
  }
}

async function enrol() {
  if (!token) return show(h("h2", {}, "Enrol a passkey"), h("p", {}, "Sign in first: the passkey is made for your login name."), signInButton("#/enrol", "Sign in"));
  const out = h("div", { id: "entry" });
  const go = h("button", { id: "create", onclick: () => create(out, go) }, "Create a passkey on this device");
  show(
    h("h2", {}, "Enrol a passkey"),
    h("p", {}, "This makes a passkey for ", h("strong", {}, signedInAs()), " on ", h("strong", {}, location.hostname), ". It does not make you an approver: operators add the entry below to the signing zone."),
    go, out,
  );
}

async function create(out, go) {
  go.disabled = true;
  try {
    const sub = signedInAs();
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: location.hostname, name: "QuorumVault approvals" },
      user: { id: await sha256(enc.encode(sub)), name: sub, displayName: sub },
      challenge: random(32),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none", timeout: 60000,
    } });
    const spki = new Uint8Array(cred.response.getPublicKey());
    const alg = cred.response.getPublicKeyAlgorithm();
    let key, name;
    if (alg === -7 && spki.length === 91) { key = spki.subarray(26); name = "ES256"; } // the 65-byte uncompressed P-256 point ends the SPKI
    else if (alg === -8 && spki.length === 44) { key = spki.subarray(12); name = "EdDSA"; }
    else throw new Error("this authenticator made a key the signing zone does not support (algorithm " + alg + ")");
    const entry = { scheme: "webauthn", alg: name, public_key: toHex(key), credential_id: b64u(cred.rawId), rp_id: location.hostname, origins: [location.origin], identity: sub, enabled: true };
    out.replaceChildren(
      h("p", { class: "ok" }, "Passkey created."),
      h("p", {}, "Send this approver entry to your operators. They sign it into the zone (qv-approvers sign -action enrol -name ", sub, " -approver-file entry.json); until then it approves nothing."),
      h("pre", { id: "entry-json" }, JSON.stringify(entry, null, 2)),
    );
  } catch (e) {
    out.replaceChildren(fail("No passkey was made: " + e.message));
    go.disabled = false;
  }
}

// ---- start ----
function route() {
  const m = location.hash.match(/^#\/withdrawals\/([^/]+)$/);
  const run = m ? () => withdrawal(decodeURIComponent(m[1])) : location.hash === "#/enrol" ? enrol : home;
  document.getElementById("who").textContent = token ? "Signed in as " + signedInAs() : "Not signed in";
  Promise.resolve(run()).catch((e) => show(fail(String(e.message || e))));
}

async function start() {
  const r = await fetch("/config.json", { credentials: "omit" });
  cfg = await r.json();
  const params = new URLSearchParams(location.search);
  if (params.has("code") || params.has("error")) {
    try { await finishLogin(params); } catch (e) { return show(fail(e.message)); }
  }
  addEventListener("hashchange", route);
  route();
}
start().catch((e) => show(fail("The page could not start: " + e.message)));
