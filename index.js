"use strict";

const crypto = require("crypto");

const CATBOX_URL = "https://catbox.moe/user/api.php";
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB
const MAX_BODY_SIZE = MAX_FILE_SIZE + 1024 * 1024; // multipart overhead
const RATE_LIMIT = 10; // uploads
const RATE_WINDOW_MS = 10 * 60 * 1000; // per 10 minutes per IP
const CATBOX_TIMEOUT_MS = 60 * 1000;
const CATBOX_URL_PATTERN = /^https:\/\/files\.catbox\.moe\/[A-Za-z0-9._-]+$/;

// Best-effort, per-instance rate limit (serverless instances do not share memory).
const hits = new Map();

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

function fail(res, status, error) {
  send(res, status, { success: false, error });
}

function getIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length) {
    return forwarded.split(",")[0].trim();
  }
  return req.headers["x-real-ip"] || (req.socket && req.socket.remoteAddress) || "unknown";
}

function isRateLimited(ip) {
  const now = Date.now();
  for (const [key, list] of hits) {
    const fresh = list.filter((t) => now - t < RATE_WINDOW_MS);
    if (fresh.length) hits.set(key, fresh);
    else hits.delete(key);
  }
  const list = hits.get(ip) || [];
  if (list.length >= RATE_LIMIT) return true;
  list.push(now);
  hits.set(ip, list);
  return false;
}

function normalizeOrigin(value) {
  return String(value || "").trim().replace(/\/+$/, "").toLowerCase();
}

// Returns the origin to echo in CORS headers, "" for no origin header, or null if rejected.
function resolveOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return "";
  const allowed = normalizeOrigin(process.env.ALLOWED_ORIGIN);
  const incoming = normalizeOrigin(origin);
  if (allowed) return incoming === allowed ? origin : null;
  try {
    return new URL(origin).host === req.headers.host ? origin : null;
  } catch (e) {
    return null;
  }
}

function secretsMatch(provided, expected) {
  const a = crypto.createHash("sha256").update(String(provided || "")).digest();
  const b = crypto.createHash("sha256").update(String(expected)).digest();
  return crypto.timingSafeEqual(a, b);
}

function sanitizeFilename(name) {
  let base = String(name || "").split(/[\\/]/).pop();
  base = base.normalize("NFKD").replace(/[^\w.\- ]+/g, "").replace(/\s+/g, "_");
  base = base.replace(/^\.+/, "").replace(/\.{2,}/g, ".");
  if (base.length > 100) {
    const dot = base.lastIndexOf(".");
    const ext = dot > 0 ? base.slice(dot, dot + 11) : "";
    base = base.slice(0, 100 - ext.length) + ext;
  }
  return base || "file";
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > limit) {
      const err = new Error("too large");
      err.code = "TOO_LARGE";
      req.resume();
      return reject(err);
    }
    const chunks = [];
    let total = 0;
    let exceeded = false;
    req.on("data", (chunk) => {
      if (exceeded) return;
      total += chunk.length;
      if (total > limit) {
        exceeded = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (exceeded) {
        const err = new Error("too large");
        err.code = "TOO_LARGE";
        return reject(err);
      }
      resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

module.exports = async function handler(req, res) {
  try {
    const allowedOrigin = resolveOrigin(req);
    if (allowedOrigin === null) {
      return fail(res, 403, "Origin not allowed");
    }
    if (allowedOrigin) {
      res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-upload-secret");
      res.setHeader("Access-Control-Max-Age", "600");
    }

    if (req.method === "OPTIONS") {
      res.statusCode = 204;
      return res.end();
    }
    if (req.method !== "POST") {
      res.setHeader("Allow", "POST, OPTIONS");
      return fail(res, 405, "Method not allowed");
    }

    if (isRateLimited(getIp(req))) {
      res.setHeader("Retry-After", String(Math.ceil(RATE_WINDOW_MS / 1000)));
      return fail(res, 429, "Too many requests");
    }

    const requiredSecret = process.env.UPLOAD_SECRET;
    if (requiredSecret && !secretsMatch(req.headers["x-upload-secret"], requiredSecret)) {
      return fail(res, 401, "Invalid upload secret");
    }

    const contentType = String(req.headers["content-type"] || "");
    if (!/^multipart\/form-data;\s*boundary=/i.test(contentType)) {
      return fail(res, 415, "Content-Type must be multipart/form-data");
    }

    let body;
    try {
      body = await readBody(req, MAX_BODY_SIZE);
    } catch (err) {
      if (err && err.code === "TOO_LARGE") return fail(res, 413, "File is too large");
      return fail(res, 400, "Could not read request");
    }

    let form;
    try {
      form = await new Response(body, { headers: { "content-type": contentType } }).formData();
    } catch (e) {
      return fail(res, 400, "Invalid multipart body");
    }

    const file = form.get("file");
    if (!file || typeof file === "string" || typeof file.arrayBuffer !== "function") {
      return fail(res, 400, "No file provided");
    }
    if (file.size === 0) {
      return fail(res, 400, "File is empty");
    }
    if (file.size > MAX_FILE_SIZE) {
      return fail(res, 413, "File is too large");
    }

    const safeName = sanitizeFilename(file.name);
    const mime = /^[\w.+-]+\/[\w.+-]+$/.test(file.type || "") ? file.type : "application/octet-stream";

    const out = new FormData();
    out.append("reqtype", "fileupload");
    out.append("userhash", "");
    out.append("fileToUpload", new Blob([await file.arrayBuffer()], { type: mime }), safeName);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CATBOX_TIMEOUT_MS);

    let catboxRes;
    let text;
    try {
      catboxRes = await fetch(CATBOX_URL, {
        method: "POST",
        body: out,
        headers: {
          "x-requested-with": "XMLHttpRequest",
          "user-agent": "Mozilla/5.0 (compatible; CatboxUploader/1.0)",
        },
        signal: controller.signal,
      });
      text = (await catboxRes.text()).trim();
    } catch (err) {
      if (err && err.name === "AbortError") {
        return fail(res, 504, "Upload service timed out");
      }
      return fail(res, 502, "Could not reach upload service");
    } finally {
      clearTimeout(timer);
    }

    if (!catboxRes.ok) {
      console.error("Catbox HTTP error:", catboxRes.status, text.slice(0, 120));
      return fail(res, 502, "Upload service returned an error");
    }
    if (!text) {
      return fail(res, 502, "Upload service returned an empty response");
    }
    if (!CATBOX_URL_PATTERN.test(text)) {
      console.error("Catbox returned an unexpected response");
      return fail(res, 502, "Upload service rejected the file");
    }

    return send(res, 200, { success: true, url: text });
  } catch (err) {
    console.error("Unhandled upload error");
    return fail(res, 500, "Internal server error");
  }
};
