import { httpServerHandler } from "cloudflare:node";
import serverModule from "../server.js";

const { app, syncApprovedLeaveDiscordRoles, initMeetingAttendanceScheduler } = serverModule;

const PORT = 3000;
app.listen(PORT);
const handler = httpServerHandler({ port: PORT });

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64urlBytes(value) {
  const raw = String(value || "");
  const base64 = raw.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(raw.length / 4) * 4, "=");
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function verifyToken(token, env, kind) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error("Token invalid.");

  const [encoded, signature] = parts;
  const secret = String(env.SESSION_SECRET || env.B2_APPLICATION_KEY || "change-this-secret");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(encoded)));
  const actual = b64urlBytes(signature);
  if (!equalBytes(expected, actual)) throw new Error("Semnătura tokenului este invalidă.");

  const payload = JSON.parse(decoder.decode(b64urlBytes(encoded)));
  if (!payload.exp || Date.now() > Number(payload.exp)) throw new Error("Token expirat.");

  const objectKey = String(payload.key || "");
  if (kind === "image" && (!objectKey.startsWith("images/") || objectKey.includes(".."))) {
    throw new Error("Cheie imagine invalidă.");
  }
  if (kind === "metadata" && (!objectKey.startsWith("reports/") || !objectKey.endsWith(".json") || objectKey.includes(".."))) {
    throw new Error("Cheie raport invalidă.");
  }
  return payload;
}

async function authorizeB2(env) {
  const id = String(env.B2_KEY_ID || "");
  const key = String(env.B2_APPLICATION_KEY || "");
  if (!id || !key) throw new Error("Lipsesc B2_KEY_ID/B2_APPLICATION_KEY.");

  const r = await fetch("https://api.backblazeb2.com/b2api/v3/b2_authorize_account", {
    headers: { Authorization: `Basic ${btoa(`${id}:${key}`)}` }
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = null; }
  if (!r.ok || !data) throw new Error(`B2 authorize HTTP ${r.status}: ${text.slice(0, 250)}`);
  return data;
}

function storageApi(auth) {
  return auth?.apiInfo?.storageApi || auth?.apiInfo?.storage_api || null;
}

async function bucketId(auth, env) {
  const storage = storageApi(auth);
  const allowed = storage?.allowed || auth?.allowed || {};
  if (allowed.bucketId || allowed.bucket_id) return String(allowed.bucketId || allowed.bucket_id);

  const apiUrl = storage?.apiUrl || storage?.api_url;
  const accountId = auth?.accountId || auth?.account_id;
  const token = auth?.authorizationToken || auth?.authorization_token;
  if (!apiUrl || !accountId || !token) throw new Error("Răspuns B2 authorize incomplet.");

  const r = await fetch(`${apiUrl}/b2api/v3/b2_list_buckets`, {
    method: "POST",
    headers: { Authorization: token, "Content-Type": "application/json" },
    body: JSON.stringify({ accountId, bucketName: String(env.B2_BUCKET || "") })
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = null; }
  if (!r.ok || !data) throw new Error(`B2 list buckets HTTP ${r.status}: ${text.slice(0, 250)}`);
  const found = (data.buckets || []).find(x => String(x.bucketName || "") === String(env.B2_BUCKET || ""));
  if (!found?.bucketId) throw new Error(`Bucketul ${env.B2_BUCKET || ""} nu a fost găsit.`);
  return String(found.bucketId);
}

async function uploadTarget(auth, id) {
  const storage = storageApi(auth);
  const apiUrl = storage?.apiUrl || storage?.api_url;
  const token = auth?.authorizationToken || auth?.authorization_token;
  if (!apiUrl || !token) throw new Error("Răspuns B2 authorize incomplet.");

  const r = await fetch(`${apiUrl}/b2api/v3/b2_get_upload_url`, {
    method: "POST",
    headers: { Authorization: token, "Content-Type": "application/json" },
    body: JSON.stringify({ bucketId: id })
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = null; }
  if (!r.ok || !data?.uploadUrl || !data?.authorizationToken) {
    throw new Error(`B2 get upload URL HTTP ${r.status}: ${text.slice(0, 250)}`);
  }
  return data;
}

async function nativeUpload(env, objectKey, contentType, body) {
  const auth = await authorizeB2(env);
  const id = await bucketId(auth, env);
  const target = await uploadTarget(auth, id);
  const sha1 = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", body)))
    .map(b => b.toString(16).padStart(2, "0")).join("");

  const r = await fetch(target.uploadUrl, {
    method: "POST",
    headers: {
      Authorization: target.authorizationToken,
      "X-Bz-File-Name": encodeURIComponent(objectKey),
      "Content-Type": contentType,
      "Content-Length": String(body.byteLength),
      "X-Bz-Content-Sha1": sha1
    },
    body
  });

  const text = await r.text();
  if (!r.ok) throw new Error(`B2 upload HTTP ${r.status}: ${text.slice(0, 350)}`);
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}
  return data;
}

async function imageUpload(request, env, url) {
  try {
    const payload = await verifyToken(url.searchParams.get("token"), env, "image");
    const contentType = String(request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    if (!["image/jpeg", "image/png", "image/webp"].includes(contentType)) {
      return Response.json({ error: "Tip imagine invalid." }, { status: 400 });
    }
    if (contentType !== String(payload.contentType || "").toLowerCase()) {
      return Response.json({ error: "Tipul imaginii nu corespunde." }, { status: 400 });
    }
    const body = await request.arrayBuffer();
    if (!body.byteLength || body.byteLength !== Number(payload.size || 0)) {
      return Response.json({ error: "Dimensiunea imaginii nu corespunde." }, { status: 400 });
    }
    const data = await nativeUpload(env, String(payload.key), contentType, body);
    return Response.json({ success: true, key: String(payload.key), fileId: data?.fileId || null });
  } catch (e) {
    return Response.json({ error: "Upload imagine eșuat.", details: String(e?.message || e) }, { status: 500 });
  }
}

async function metadataUpload(request, env, url) {
  try {
    const payload = await verifyToken(url.searchParams.get("token"), env, "metadata");
    const body = await request.arrayBuffer();
    if (!body.byteLength || body.byteLength > 2 * 1024 * 1024) {
      return Response.json({ error: "Metadata raport invalidă." }, { status: 400 });
    }

    // Validăm că body-ul este JSON înainte de a-l pune în B2.
    try { JSON.parse(decoder.decode(body)); }
    catch { return Response.json({ error: "Metadata raport nu este JSON valid." }, { status: 400 }); }

    const data = await nativeUpload(env, String(payload.key), "application/json; charset=utf-8", body);
    return Response.json({ success: true, key: String(payload.key), fileId: data?.fileId || null });
  } catch (e) {
    return Response.json({ error: "Salvarea raportului în B2 a eșuat.", details: String(e?.message || e) }, { status: 500 });
  }
}


// ======================================================
// BACKBLAZE B2 — ȘTERGERE BULK RAPOARTE (S3 + SigV4 nativ)
// Evită AWS SDK în Cloudflare Workers și șterge definitiv toate
// versiunile de sub reports/ și images/ în loturi de până la 1000.
// ======================================================
function hex(bytes) {
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

async function hmac(key, value) {
  const raw = typeof key === "string" ? encoder.encode(key) : key;
  const k = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, encoder.encode(value)));
}

function awsEncode(value) {
  return encodeURIComponent(String(value)).replace(/[!'()*]/g, c => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

function xmlDecode(value) {
  return String(value || "")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}

function xmlEscape(value) {
  return String(value || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

async function signedS3Fetch(env, method, canonicalQuery, body = "") {
  const endpoint = new URL(String(env.B2_ENDPOINT || ""));
  const bucket = String(env.B2_BUCKET || "");
  const accessKey = String(env.B2_KEY_ID || "");
  const secret = String(env.B2_APPLICATION_KEY || "");
  const region = String(env.B2_REGION || "");
  if (!bucket || !accessKey || !secret || !region || !endpoint.host) throw new Error("Configurația B2_* este incompletă.");

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const canonicalUri = `/${awsEncode(bucket)}/`;
  const payloadHash = await sha256(body);
  const canonicalHeaders = `host:${endpoint.host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256(canonicalRequest)}`;

  const kDate = await hmac(`AWS4${secret}`, dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, "s3");
  const kSigning = await hmac(kService, "aws4_request");
  const signature = hex(await (async () => {
    const k = await crypto.subtle.importKey("raw", kSigning, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return crypto.subtle.sign("HMAC", k, encoder.encode(stringToSign));
  })());

  const auth = `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  const url = `${endpoint.origin}${canonicalUri}${canonicalQuery ? `?${canonicalQuery}` : ""}`;
  const headers = {
    Authorization: auth,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash
  };
  if (body) headers["Content-Type"] = "application/xml";
  return fetch(url, { method, headers, body: body || undefined });
}

function xmlTag(block, tag) {
  const m = String(block || "").match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`));
  return m ? xmlDecode(m[1]) : "";
}

async function listS3Versions(env, prefix) {
  const all = [];
  let keyMarker = "";
  let versionMarker = "";
  let pages = 0;
  do {
    pages += 1;
    if (pages > 100) throw new Error(`Prea multe pagini B2 pentru ${prefix}.`);
    const q = [
      `prefix=${awsEncode(prefix)}`,
      ...(keyMarker ? [`key-marker=${awsEncode(keyMarker)}`] : []),
      ...(versionMarker ? [`version-id-marker=${awsEncode(versionMarker)}`] : []),
      "versions="
    ].sort().join("&");
    const r = await signedS3Fetch(env, "GET", q);
    const xml = await r.text();
    if (!r.ok) throw new Error(`B2 list versions HTTP ${r.status}: ${xml.slice(0, 350)}`);

    for (const kind of ["Version", "DeleteMarker"]) {
      const re = new RegExp(`<${kind}>([\\s\\S]*?)<\\/${kind}>`, "g");
      let m;
      while ((m = re.exec(xml))) {
        const Key = xmlTag(m[1], "Key");
        const VersionId = xmlTag(m[1], "VersionId");
        if (Key && VersionId && Key.startsWith(prefix)) all.push({ Key, VersionId });
      }
    }
    const truncated = /<IsTruncated>true<\/IsTruncated>/i.test(xml);
    if (!truncated) break;
    keyMarker = xmlTag(xml, "NextKeyMarker");
    versionMarker = xmlTag(xml, "NextVersionIdMarker");
    if (!keyMarker) throw new Error("B2 a returnat listă trunchiată fără NextKeyMarker.");
  } while (true);
  return all;
}

async function deleteS3VersionBatch(env, objects) {
  if (!objects.length) return;
  const body = `<Delete>${objects.map(o => `<Object><Key>${xmlEscape(o.Key)}</Key><VersionId>${xmlEscape(o.VersionId)}</VersionId></Object>`).join("")}<Quiet>true</Quiet></Delete>`;
  const r = await signedS3Fetch(env, "POST", "delete=", body);
  const text = await r.text();
  if (!r.ok || /<Error>/i.test(text)) throw new Error(`B2 bulk delete HTTP ${r.status}: ${text.slice(0, 500)}`);
}

async function deleteAllReportStorage(env) {
  const [reports, images] = await Promise.all([
    listS3Versions(env, "reports/"),
    listS3Versions(env, "images/")
  ]);
  const objects = [...images, ...reports];
  for (let i = 0; i < objects.length; i += 1000) {
    await deleteS3VersionBatch(env, objects.slice(i, i + 1000));
  }

  // Verificare finală: nu declarăm succes dacă mai există versiuni.
  const [remainingReports, remainingImages] = await Promise.all([
    listS3Versions(env, "reports/"),
    listS3Versions(env, "images/")
  ]);
  if (remainingReports.length || remainingImages.length) {
    throw new Error(`Au rămas obiecte în B2: reports=${remainingReports.length}, images=${remainingImages.length}`);
  }
  return {
    deletedReports: reports.filter(x => x.Key.endsWith(".json")).length,
    deletedImages: images.length
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "PUT" && url.pathname === "/api/report-image-upload") {
      return imageUpload(request, env, url);
    }
    if (request.method === "PUT" && url.pathname === "/api/internal/report-metadata-upload") {
      return metadataUpload(request, env, url);
    }

    try {
      const response = await handler.fetch(request, env, ctx);

      // Express validează sesiunea de admin + textul de confirmare. Abia după
      // aceea executăm ștergerea bulk nativă, ca să nu expunem un endpoint B2
      // care poate fi apelat fără autentificare.
      if (request.method === "DELETE" && url.pathname === "/api/admin/reports/all" && response.ok) {
        let gate = null;
        try { gate = await response.clone().json(); } catch {}
        if (gate?.nativeB2Delete === true) {
          try {
            const result = await deleteAllReportStorage(env);
            return Response.json({
              success: true,
              ...result,
              message: "Toate rapoartele și imaginile lor au fost șterse definitiv din Backblaze B2."
            });
          } catch (e) {
            return Response.json({
              error: "Rapoartele nu au putut fi șterse complet din Backblaze B2.",
              details: String(e?.message || e)
            }, { status: 500 });
          }
        }
      }

      if (url.pathname.startsWith("/api/")) {
        const ct = String(response.headers.get("content-type") || "").toLowerCase();
        if (ct.includes("text/html")) {
          const body = await response.text();
          return Response.json({
            error: "API-ul Poliției a returnat HTML în loc de JSON.",
            route: url.pathname,
            status: response.status,
            details: body.replace(/\s+/g, " ").slice(0, 500)
          }, { status: response.ok ? 502 : response.status });
        }
      }
      return response;
    } catch (e) {
      if (url.pathname.startsWith("/api/")) {
        return Response.json({
          error: "Eroare internă în API-ul Poliției.",
          route: url.pathname,
          details: String(e?.message || e || "Eroare necunoscută")
        }, { status: 500 });
      }
      throw e;
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await syncApprovedLeaveDiscordRoles();
      await initMeetingAttendanceScheduler();
    })());
  }
};
