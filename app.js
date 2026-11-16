// XEROVIN backend — ONE Vercel Function at https://xerovin.com/api/app
// Handles: the AI chat, visitor analytics, and the admin panel (login + API key box).
//
// Nothing secret is in this file. Secrets live in Vercel -> Settings -> Environment Variables:
//   ADMIN_PASSWORD   your admin password                (required)
//   ADMIN_EMAIL      your admin email                   (required)
//   ADMIN_USERNAME   optional, defaults to ADMIN
//   SESSION_SECRET   optional long random text (signs logins and encrypts the stored API key)
//   TZ_OFFSET_HOURS  optional, hours ahead of UTC for "today" (default 1 = Nigeria)
// plus a free database: Vercel -> Storage -> Upstash Redis (adds KV_REST_API_URL / KV_REST_API_TOKEN by itself).
// Your Gemini API key is NOT an environment variable: you paste it in the admin panel (xerovin.com/#admin).

const crypto = require("crypto");

const ALLOWED_ORIGINS = ["https://xerovin.com", "https://www.xerovin.com"];

const MODELS = [
  { id: "gemini-3.5-flash-lite", levels: { low: "MINIMAL", medium: "MINIMAL", high: "LOW", xhigh: "MEDIUM" } },
  { id: "gemini-3.8-flash", levels: { low: "MINIMAL", medium: "LOW", high: "MEDIUM", xhigh: "HIGH" } },
  { id: "gemini-3.6-flash", levels: { low: "MINIMAL", medium: "LOW", high: "MEDIUM", xhigh: "HIGH" } },
];

const MAX_OUTPUT_TOKENS = 16384;
const MAX_TURNS = 40;
const MAX_TEXT_CHARS = 60000;
const MAX_IMAGE_BASE64_CHARS = 7000000;
const MAX_SYSTEM_CHARS = 4000;
const CHAT_PER_MINUTE = 30;
const KEEP_DAYS = 40;
const LIVE_WINDOW_MS = 70000;
const SESSION_MS = 12 * 60 * 60 * 1000;

// ── small helpers ──────────────────────────────────────────────────────────
const env = (k) => process.env[k] || "";
const SECRET = () => env("SESSION_SECRET") || env("ADMIN_PASSWORD");

const memHits = new Map();
function limited(bucket, max, windowMs = 60000) {
  const now = Date.now();
  const recent = (memHits.get(bucket) || []).filter((t) => now - t < windowMs);
  recent.push(now);
  memHits.set(bucket, recent);
  if (memHits.size > 5000) {
    for (const [k, v] of memHits) if (!v.length || now - v[v.length - 1] > windowMs) memHits.delete(k);
  }
  return recent.length > max;
}

function send(res, status, body, type) {
  res.writeHead(status, { "Content-Type": type || "application/json", "Cache-Control": "no-store" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}
const fail = (res, status, message, extra) => send(res, status, { error: { message, ...(extra || {}) } });
const plain = (res, status, text) => send(res, status, text, "text/plain; charset=utf-8");

function originAllowed(origin, host) {
  if (!origin) return true;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  try {
    if (host && new URL(origin).host === host) return true;
  } catch {
    return false;
  }
  return /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

function clientIp(req) {
  return String(req.headers["x-forwarded-for"] || "unknown").split(",")[0].trim();
}

function dayKey(ms) {
  const off = Number(env("TZ_OFFSET_HOURS") || 1);
  return new Date(ms + (Number.isFinite(off) ? off : 1) * 3600000).toISOString().slice(0, 10);
}

// ── Redis (Upstash REST) ───────────────────────────────────────────────────
function redisConf() {
  const url = env("KV_REST_API_URL") || env("UPSTASH_REDIS_REST_URL");
  const token = env("KV_REST_API_TOKEN") || env("UPSTASH_REDIS_REST_TOKEN");
  return url && token ? { url: url.replace(/\/$/, ""), token } : null;
}

async function redis(cmds) {
  const c = redisConf();
  if (!c) throw new Error("NO_REDIS");
  const r = await fetch(c.url + "/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + c.token, "Content-Type": "application/json" },
    body: JSON.stringify(cmds),
  });
  if (!r.ok) throw new Error("REDIS_" + r.status);
  const j = await r.json();
  return j.map((x) => {
    if (x && x.error) throw new Error("REDIS: " + x.error);
    return x.result;
  });
}

// ── API key storage (encrypted at rest) ────────────────────────────────────
let derived = null;
function aesKey() {
  if (!derived) derived = crypto.scryptSync(SECRET(), "xerovin-key-v1", 32);
  return derived;
}
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", aesKey(), iv);
  const enc = Buffer.concat([c.update(text, "utf8"), c.final()]);
  return [iv, c.getAuthTag(), enc].map((b) => b.toString("base64")).join(".");
}
function decrypt(blob) {
  try {
    const [iv, tag, enc] = String(blob).split(".").map((x) => Buffer.from(x, "base64"));
    const d = crypto.createDecipheriv("aes-256-gcm", aesKey(), iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(enc), d.final()]).toString("utf8");
  } catch {
    return null; // wrong secret or damaged value: treated as "no key"
  }
}

let keyCache = { v: null, t: 0 };
async function getKey() {
  if (Date.now() - keyCache.t < 5000) return keyCache.v;
  const [blob] = await redis([["GET", "cfg:gemini"]]);
  keyCache = { v: blob ? decrypt(blob) : null, t: Date.now() };
  return keyCache.v;
}
const mask = (k) => (k.length > 10 ? k.slice(0, 4) + "…" + k.slice(-4) : "••••");

// ── Gemini ─────────────────────────────────────────────────────────────────
function validate(body) {
  if (!body || typeof body !== "object") return "Bad request.";
  const { contents, system } = body;
  if (!Array.isArray(contents) || contents.length === 0 || contents.length > MAX_TURNS) return "Bad conversation.";
  let chars = 0;
  let image = 0;
  for (const c of contents) {
    if (!c || (c.role !== "user" && c.role !== "model") || !Array.isArray(c.parts) || c.parts.length > 4) {
      return "Bad conversation.";
    }
    for (const p of c.parts) {
      if (p && typeof p.text === "string") chars += p.text.length;
      else if (
        p &&
        p.inlineData &&
        /^image\/(png|jpe?g|webp|gif|heic|heif)$/.test(p.inlineData.mimeType) &&
        typeof p.inlineData.data === "string"
      ) image += p.inlineData.data.length;
      else return "Unsupported content.";
    }
  }
  if (chars > MAX_TEXT_CHARS) return "That message is too long.";
  if (image > MAX_IMAGE_BASE64_CHARS) return "That image is too large.";
  if (system != null && (typeof system !== "string" || system.length > MAX_SYSTEM_CHARS)) return "Bad system prompt.";
  return null;
}

function buildPayload(body, level) {
  const payload = {
    contents: body.contents.map((c) => ({
      role: c.role,
      parts: c.parts.map((p) =>
        typeof p.text === "string"
          ? { text: p.text }
          : { inlineData: { mimeType: p.inlineData.mimeType, data: p.inlineData.data } }
      ),
    })),
    generationConfig: { maxOutputTokens: MAX_OUTPUT_TOKENS },
  };
  if (body.system) payload.systemInstruction = { parts: [{ text: body.system }] };
  if (level) payload.generationConfig.thinkingConfig = { thinkingLevel: level };
  return payload;
}

function callModel(key, model, payload) {
  return fetch(
    "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":streamGenerateContent?alt=sse",
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": key },
      body: JSON.stringify(payload),
    }
  );
}

async function errorMessage(res) {
  try {
    const j = await res.json();
    if (j && j.error && j.error.message) return String(j.error.message);
  } catch {
    // not JSON
  }
  return "Request failed (" + res.status + ").";
}

async function askGemini(key, body) {
  const depth = ["low", "medium", "high", "xhigh"].includes(body.depth) ? body.depth : "medium";
  let failure = { status: 502, message: "The AI service is unavailable right now." };
  for (const m of MODELS) {
    let withThinking = true;
    for (let attempt = 0; attempt < 2; attempt++) {
      let res;
      try {
        res = await callModel(key, m.id, buildPayload(body, withThinking ? m.levels[depth] : null));
      } catch {
        failure = { status: 502, message: "Could not reach Google. Try again in a moment." };
        break;
      }
      if (res.ok) return { res, model: m.id };
      const message = await errorMessage(res);
      failure = { status: res.status, message };
      if (res.status === 400 && withThinking && /think/i.test(message)) {
        withThinking = false;
        continue;
      }
      break;
    }
    if (failure.status === 401 || failure.status === 403) break;
    if (failure.status === 400 && !/model|deprecat|not found|not supported|unsupported/i.test(failure.message)) break;
  }
  return { failure };
}

async function testKey(key) {
  const out = await askGemini(key, {
    system: "Reply with one short word.",
    depth: "low",
    contents: [{ role: "user", parts: [{ text: "Say OK" }] }],
  });
  if (out.failure) return { ok: false, message: out.failure.message };
  try {
    await out.res.text();
  } catch {
    // the call itself worked
  }
  return { ok: true, model: out.model };
}

let statusCache = { sig: "", t: 0, v: null };
async function keyStatus(force) {
  const key = await getKey();
  if (!key) return { connected: false, masked: "", message: "No API key is connected. The AI is switched off." };
  const sig = crypto.createHash("sha256").update(key).digest("hex");
  if (!force && statusCache.sig === sig && Date.now() - statusCache.t < 60000) return statusCache.v;
  const t = await testKey(key);
  const v = t.ok
    ? { connected: true, masked: mask(key), model: t.model, message: "Connected. The AI is working for everyone." }
    : { connected: false, masked: mask(key), message: "Google refused this key: " + t.message };
  statusCache = { sig, t: Date.now(), v };
  return v;
}

// ── admin login ────────────────────────────────────────────────────────────
const h = (s) => crypto.createHash("sha256").update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(h(a), h(b));
const b64u = (b) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function makeToken() {
  const exp = String(Date.now() + SESSION_MS);
  const sig = b64u(crypto.createHmac("sha256", SECRET()).update("admin:" + exp).digest());
  return exp + "." + sig;
}
function tokenOk(req) {
  if (!SECRET()) return false;
  const m = /^Bearer (\d+)\.([A-Za-z0-9_-]+)$/.exec(String(req.headers.authorization || ""));
  if (!m || Number(m[1]) < Date.now()) return false;
  const want = b64u(crypto.createHmac("sha256", SECRET()).update("admin:" + m[1]).digest());
  return same(want, m[2]);
}

async function handleLogin(req, res, body) {
  if (!env("ADMIN_PASSWORD")) return fail(res, 500, "Admin login isn't set up yet. Add ADMIN_PASSWORD in Vercel, then Redeploy.");
  const ip = clientIp(req);
  if (limited("login:" + ip, 8, 15 * 60000)) return fail(res, 429, "Too many attempts. Try again in 15 minutes.");
  const id = String((body && body.id) || "").trim().toLowerCase();
  const pw = String((body && body.password) || "");
  const okId = same(id, env("ADMIN_USERNAME").toLowerCase() || "admin") || (!!env("ADMIN_EMAIL") && same(id, env("ADMIN_EMAIL").toLowerCase()));
  const okPw = same(pw, env("ADMIN_PASSWORD"));
  if (!(okId && okPw)) return fail(res, 401, "Wrong email, username or password.");
  memHits.delete("login:" + ip);
  return send(res, 200, { token: makeToken(), expiresInMs: SESSION_MS });
}

// ── analytics ──────────────────────────────────────────────────────────────
function parseUa(ua) {
  ua = String(ua || "");
  const bot = /bot|crawl|spider|slurp|facebookexternalhit|preview|monitor|lighthouse|headless/i.test(ua);
  let device = "Desktop";
  if (/ipad|tablet|(android(?!.*mobile))/i.test(ua)) device = "Tablet";
  else if (/mobi|iphone|ipod|android/i.test(ua)) device = "Mobile";
  let os = "Other";
  if (/windows/i.test(ua)) os = "Windows";
  else if (/iphone|ipad|ipod/i.test(ua)) os = "iOS";
  else if (/android/i.test(ua)) os = "Android";
  else if (/mac os|macintosh/i.test(ua)) os = "macOS";
  else if (/cros/i.test(ua)) os = "ChromeOS";
  else if (/linux/i.test(ua)) os = "Linux";
  let browser = "Other";
  if (/edg\//i.test(ua)) browser = "Edge";
  else if (/opr\/|opera/i.test(ua)) browser = "Opera";
  else if (/samsungbrowser/i.test(ua)) browser = "Samsung";
  else if (/firefox|fxios/i.test(ua)) browser = "Firefox";
  else if (/chrome|crios/i.test(ua)) browser = "Chrome";
  else if (/safari/i.test(ua)) browser = "Safari";
  return { bot, device, os, browser };
}

async function handleHit(req, res, body, beat) {
  const id = String((body && body.id) || "");
  if (!/^[A-Za-z0-9-]{8,64}$/.test(id)) return send(res, 204, "");
  const ua = parseUa(req.headers["user-agent"]);
  if (ua.bot) return send(res, 204, "");
  if (limited("hit:" + clientIp(req), 90)) return send(res, 204, "");
  const now = Date.now();
  const d = dayKey(now);
  const ttl = KEEP_DAYS * 86400;
  try {
    if (beat) {
      await redis([["ZADD", "live", now, id], ["ZREMRANGEBYSCORE", "live", 0, now - 300000]]);
      return send(res, 204, "");
    }
    const [isNew] = await redis([
      ["PFADD", "vis:" + d, id],
      ["INCR", "pv:" + d],
      ["EXPIRE", "vis:" + d, ttl],
      ["EXPIRE", "pv:" + d, ttl],
      ["ZADD", "live", now, id],
      ["ZREMRANGEBYSCORE", "live", 0, now - 300000],
    ]);
    if (isNew === 1) {
      const cc = String(req.headers["x-vercel-ip-country"] || "").toUpperCase();
      const country = /^[A-Z]{2}$/.test(cc) ? cc : "XX";
      await redis([
        ["HINCRBY", "c:" + d, country, 1],
        ["HINCRBY", "d:" + d, ua.device, 1],
        ["HINCRBY", "o:" + d, ua.os, 1],
        ["HINCRBY", "b:" + d, ua.browser, 1],
        ["EXPIRE", "c:" + d, ttl],
        ["EXPIRE", "d:" + d, ttl],
        ["EXPIRE", "o:" + d, ttl],
        ["EXPIRE", "b:" + d, ttl],
      ]);
    }
  } catch {
    // analytics must never break the site
  }
  return send(res, 204, "");
}

const toObj = (arr) => {
  const o = {};
  if (Array.isArray(arr)) for (let i = 0; i + 1 < arr.length; i += 2) o[arr[i]] = Number(arr[i + 1]) || 0;
  return o;
};
const merge = (list) => {
  const o = {};
  for (const x of list) for (const k in x) o[k] = (o[k] || 0) + x[k];
  return o;
};

async function handleStats(res) {
  const now = Date.now();
  const days = [];
  for (let i = 29; i >= 0; i--) days.push(dayKey(now - i * 86400000)); // oldest -> newest
  const cmds = [];
  for (const d of days) cmds.push(["PFCOUNT", "vis:" + d], ["GET", "pv:" + d], ["GET", "msg:" + d]);
  for (const d of days) cmds.push(["HGETALL", "c:" + d], ["HGETALL", "d:" + d], ["HGETALL", "o:" + d], ["HGETALL", "b:" + d]);
  cmds.push(["PFCOUNT", ...days.map((d) => "vis:" + d)]);
  cmds.push(["PFCOUNT", ...days.slice(-7).map((d) => "vis:" + d)]);
  cmds.push(["ZCOUNT", "live", now - LIVE_WINDOW_MS, "+inf"]);
  const r = await redis(cmds);

  const series = days.map((d, i) => ({
    day: d,
    visitors: Number(r[i * 3]) || 0,
    views: Number(r[i * 3 + 1]) || 0,
    messages: Number(r[i * 3 + 2]) || 0,
  }));
  const base = days.length * 3;
  const hashes = days.map((_, i) => ({
    c: toObj(r[base + i * 4]),
    d: toObj(r[base + i * 4 + 1]),
    o: toObj(r[base + i * 4 + 2]),
    b: toObj(r[base + i * 4 + 3]),
  }));
  const tail = base + days.length * 4;
  const range = (n) => {
    const part = hashes.slice(-n);
    return { countries: merge(part.map((x) => x.c)), devices: merge(part.map((x) => x.d)), os: merge(part.map((x) => x.o)), browsers: merge(part.map((x) => x.b)) };
  };
  const sum = (n, k) => series.slice(-n).reduce((a, x) => a + x[k], 0);
  return send(res, 200, {
    live: Number(r[tail + 2]) || 0,
    series,
    totals: {
      todayVisitors: series[29].visitors,
      todayViews: series[29].views,
      todayMessages: series[29].messages,
      week: { visitors: Number(r[tail + 1]) || 0, views: sum(7, "views"), messages: sum(7, "messages") },
      month: { visitors: Number(r[tail]) || 0, views: sum(30, "views"), messages: sum(30, "messages") },
    },
    breakdown: { today: range(1), week: range(7), month: range(30) },
    generatedAt: now,
  });
}

// ── chat ───────────────────────────────────────────────────────────────────
async function handleChat(req, res, body) {
  if (limited("chat:" + clientIp(req), CHAT_PER_MINUTE)) {
    return fail(res, 429, "Too many requests right now. Wait a moment and try again.");
  }
  const problem = validate(body);
  if (problem) return fail(res, 400, problem);

  let key;
  try {
    key = await getKey();
  } catch (e) {
    if (e.message === "NO_REDIS") return fail(res, 503, "API invalid: the site isn't connected to its database yet.");
    return fail(res, 503, "The AI service is temporarily unavailable. Try again in a moment.");
  }
  if (!key) return fail(res, 503, "API invalid: no API key is connected. The site owner needs to add one.");

  const counted = redis([["INCR", "msg:" + dayKey(Date.now())], ["EXPIRE", "msg:" + dayKey(Date.now()), KEEP_DAYS * 86400]]).catch(() => {});
  const out = await askGemini(key, body);
  if (out.failure) {
    await counted;
    const f = out.failure;
    const keyProblem = f.status === 401 || f.status === 403 || /api key|api_key|access_token_type/i.test(f.message);
    return fail(res, f.status >= 400 ? f.status : 502, keyProblem ? "API invalid: " + f.message : f.message);
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store, no-transform",
    "X-Accel-Buffering": "no",
  });
  const reader = out.res.body.getReader();
  res.on("close", () => reader.cancel().catch(() => {}));
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    res.write(Buffer.from(value));
  }
  await counted;
  res.end();
}

// ── router ─────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  try {
    const url = new URL(req.url, "http://x");
    const action = url.searchParams.get("action") || "";
    let body = req.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch {
        body = null;
      }
    }

    if (req.method === "GET" && !action) {
      return plain(
        res,
        200,
        [
          "XEROVIN API is running.",
          "Database connected: " + (redisConf() ? "yes" : "NO (add Upstash Redis in Vercel -> Storage)"),
          "Admin password set: " + (env("ADMIN_PASSWORD") ? "yes" : "NO (add ADMIN_PASSWORD in Vercel)"),
          "Admin email set: " + (env("ADMIN_EMAIL") ? "yes" : "NO (add ADMIN_EMAIL in Vercel)"),
        ].join("\n")
      );
    }

    // everything below the admin line needs a valid login
    if (action === "login" && req.method === "POST") {
      if (!originAllowed(req.headers.origin || "", req.headers.host)) return fail(res, 403, "Not allowed.");
      return await handleLogin(req, res, body);
    }
    if (["stats", "key", "keyset", "keydel"].includes(action)) {
      if (!tokenOk(req)) return fail(res, 401, "Please sign in again.");
      try {
        if (action === "stats") return await handleStats(res);
        if (action === "key") return send(res, 200, await keyStatus(url.searchParams.get("force") === "1"));
        if (action === "keydel") {
          await redis([["DEL", "cfg:gemini"]]);
          keyCache = { v: null, t: Date.now() };
          statusCache = { sig: "", t: 0, v: null };
          return send(res, 200, await keyStatus(true));
        }
        // keyset
        const k = String((body && body.key) || "").trim();
        if (k.length < 20 || k.length > 300 || /\s/.test(k)) return fail(res, 400, "That doesn't look like an API key. Paste it again, without spaces.");
        const t = await testKey(k);
        if (!t.ok) return fail(res, 400, "Google refused this key: " + t.message, { connected: false });
        await redis([["SET", "cfg:gemini", encrypt(k)]]);
        keyCache = { v: k, t: Date.now() };
        statusCache = { sig: "", t: 0, v: null };
        return send(res, 200, await keyStatus(true));
      } catch (e) {
        if (e.message === "NO_REDIS") return fail(res, 503, "The database isn't connected. In Vercel: Storage -> Create -> Upstash Redis, then Redeploy.", { code: "NO_REDIS" });
        return fail(res, 500, "Something went wrong: " + e.message);
      }
    }

    if (req.method !== "POST") return fail(res, 405, "Method not allowed.");
    if (!originAllowed(req.headers.origin || "", req.headers.host)) return fail(res, 403, "This website isn't allowed to use this service.");
    if (action === "hit") return await handleHit(req, res, body, false);
    if (action === "beat") return await handleHit(req, res, body, true);
    if (action === "chat") return await handleChat(req, res, body);
    return fail(res, 404, "Unknown request.");
  } catch (e) {
    if (!res.headersSent) fail(res, 500, "The service hit an error. Try again.");
    else res.end();
  }
};
