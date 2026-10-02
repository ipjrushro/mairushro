import { httpServerHandler } from "cloudflare:node";
import serverModule from "../server.js";

const { app, syncApprovedLeaveDiscordRoles, initMeetingAttendanceScheduler } = serverModule;

const PORT = 3000;
app.listen(PORT);
const handler = httpServerHandler({ port: PORT });

const textEncoder = new TextEncoder();

function base64UrlToBytes(value) {
  const base64 = String(value || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(String(value || "").length / 4) * 4, "=");

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

async function verifyImageUploadToken(token, env) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error("Token upload invalid.");
  }

  const [encoded, signature] = parts;
  const secret = String(
    env.SESSION_SECRET ||
    env.B2_APPLICATION_KEY ||
    "change-this-secret"
  );

  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const expected = new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      key,
      textEncoder.encode(encoded)
    )
  );

  const actual = base64UrlToBytes(signature);

  if (!bytesEqual(expected, actual)) {
    throw new Error("Token upload invalid.");
  }

  const payload = JSON.parse(
    new TextDecoder().decode(base64UrlToBytes(encoded))
  );

  if (!payload.exp || Date.now() > Number(payload.exp)) {
    throw new Error("Tokenul imaginii a expirat.");
  }

  const contentType = String(payload.contentType || "").toLowerCase();
  const size = Number(payload.size || 0);
  const objectKey = String(payload.key || "");

  if (
    !objectKey.startsWith("images/") ||
    objectKey.includes("..") ||
    !["image/jpeg", "image/png", "image/webp"].includes(contentType) ||
    !Number.isFinite(size) ||
    size < 1 ||
    size > 8 * 1024 * 1024
  ) {
    throw new Error("Date upload invalide.");
  }

  return payload;
}

async function b2Authorize(env) {
  const keyId = String(env.B2_KEY_ID || "");
  const applicationKey = String(env.B2_APPLICATION_KEY || "");

  if (!keyId || !applicationKey) {
    throw new Error("Lipsesc B2_KEY_ID/B2_APPLICATION_KEY.");
  }

  const basic = btoa(`${keyId}:${applicationKey}`);

  const response = await fetch(
    "https://api.backblazeb2.com/b2api/v3/b2_authorize_account",
    {
      method: "GET",
      headers: {
        Authorization: `Basic ${basic}`
      }
    }
  );

  const text = await response.text();
  let data = null;

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = null;
  }

  if (!response.ok || !data) {
    throw new Error(
      `B2 authorize HTTP ${response.status}: ${text.slice(0, 250)}`
    );
  }

  return data;
}

function getStorageApiInfo(auth) {
  return (
    auth?.apiInfo?.storageApi ||
    auth?.apiInfo?.storage_api ||
    null
  );
}

async function resolveBucketId(auth, env) {
  const storage = getStorageApiInfo(auth);
  const allowedBucketId =
    storage?.allowed?.bucketId ||
    storage?.allowed?.bucket_id ||
    auth?.allowed?.bucketId ||
    auth?.allowed?.bucket_id ||
    "";

  if (allowedBucketId) return String(allowedBucketId);

  const apiUrl = storage?.apiUrl || storage?.api_url;
  const accountId = auth?.accountId || auth?.account_id;
  const authToken =
    auth?.authorizationToken ||
    auth?.authorization_token;

  if (!apiUrl || !accountId || !authToken) {
    throw new Error("Răspunsul B2 authorize este incomplet.");
  }

  const response = await fetch(
    `${apiUrl}/b2api/v3/b2_list_buckets`,
    {
      method: "POST",
      headers: {
        Authorization: authToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        accountId,
        bucketName: String(env.B2_BUCKET || "")
      })
    }
  );

  const text = await response.text();
  let data = null;

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = null;
  }

  if (!response.ok || !data) {
    throw new Error(
      `B2 list buckets HTTP ${response.status}: ${text.slice(0, 250)}`
    );
  }

  const bucket = Array.isArray(data.buckets)
    ? data.buckets.find(
        item => String(item.bucketName || "") === String(env.B2_BUCKET || "")
      )
    : null;

  if (!bucket?.bucketId) {
    throw new Error(`Bucketul B2 "${env.B2_BUCKET || ""}" nu a fost găsit.`);
  }

  return String(bucket.bucketId);
}

async function getB2UploadTarget(auth, bucketId) {
  const storage = getStorageApiInfo(auth);
  const apiUrl = storage?.apiUrl || storage?.api_url;
  const authToken =
    auth?.authorizationToken ||
    auth?.authorization_token;

  if (!apiUrl || !authToken) {
    throw new Error("Răspunsul B2 authorize este incomplet.");
  }

  const response = await fetch(
    `${apiUrl}/b2api/v3/b2_get_upload_url`,
    {
      method: "POST",
      headers: {
        Authorization: authToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ bucketId })
    }
  );

  const text = await response.text();
  let data = null;

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = null;
  }

  if (!response.ok || !data?.uploadUrl || !data?.authorizationToken) {
    throw new Error(
      `B2 get upload URL HTTP ${response.status}: ${text.slice(0, 250)}`
    );
  }

  return data;
}

async function uploadImageNative(request, env, url) {
  try {
    const token = url.searchParams.get("token");
    const payload = await verifyImageUploadToken(token, env);

    const requestType = String(
      request.headers.get("content-type") || ""
    )
      .split(";")[0]
      .trim()
      .toLowerCase();

    if (requestType !== String(payload.contentType).toLowerCase()) {
      return Response.json(
        { error: "Tipul imaginii nu corespunde." },
        { status: 400 }
      );
    }

    const body = await request.arrayBuffer();

    if (!body.byteLength) {
      return Response.json(
        { error: "Imaginea este goală." },
        { status: 400 }
      );
    }

    if (body.byteLength !== Number(payload.size)) {
      return Response.json(
        {
          error: "Dimensiunea imaginii nu corespunde.",
          expected: Number(payload.size),
          received: body.byteLength
        },
        { status: 400 }
      );
    }

    // Backblaze Native API: fetch nativ, fără AWS SDK în Workers.
    const auth = await b2Authorize(env);
    const bucketId = await resolveBucketId(auth, env);
    const uploadTarget = await getB2UploadTarget(auth, bucketId);

    const sha1 = Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-1", body))
    )
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");

    const uploadResponse = await fetch(
      uploadTarget.uploadUrl,
      {
        method: "POST",
        headers: {
          Authorization: uploadTarget.authorizationToken,
          "X-Bz-File-Name": encodeURIComponent(String(payload.key)),
          "Content-Type": String(payload.contentType),
          "Content-Length": String(body.byteLength),
          "X-Bz-Content-Sha1": sha1,
          "X-Bz-Info-src_last_modified_millis": String(Date.now())
        },
        body
      }
    );

    const uploadText = await uploadResponse.text();
    let uploadData = null;

    try {
      uploadData = uploadText ? JSON.parse(uploadText) : {};
    } catch {
      uploadData = null;
    }

    if (!uploadResponse.ok) {
      return Response.json(
        {
          error: "Backblaze B2 a refuzat imaginea.",
          details: uploadData?.message || uploadText.slice(0, 350),
          status: uploadResponse.status
        },
        { status: 502 }
      );
    }

    return Response.json({
      success: true,
      key: String(payload.key),
      fileId: uploadData?.fileId || null
    });
  } catch (error) {
    return Response.json(
      {
        error: "Uploadul imaginii a eșuat.",
        details: String(error?.message || error || "Eroare necunoscută")
      },
      { status: 500 }
    );
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // IMPORTANT: interceptăm uploadul înainte să intre în Express.
    // AWS SDK rămâne disponibil pentru restul aplicației, dar pozele rapoartelor
    // sunt urcate în B2 exclusiv cu fetch nativ ca să nu mai blocheze Worker-ul.
    if (
      request.method === "PUT" &&
      url.pathname === "/api/report-image-upload"
    ) {
      return uploadImageNative(request, env, url);
    }

    try {
      const response = await handler.fetch(request, env, ctx);

      if (url.pathname.startsWith("/api/")) {
        const contentType = String(
          response.headers.get("content-type") || ""
        ).toLowerCase();

        if (contentType.includes("text/html")) {
          const body = await response.text();

          return Response.json(
            {
              error: "API-ul Poliției a returnat HTML în loc de JSON.",
              route: url.pathname,
              status: response.status,
              details: body.replace(/\s+/g, " ").slice(0, 500)
            },
            { status: response.ok ? 502 : response.status }
          );
        }
      }

      return response;
    } catch (error) {
      if (url.pathname.startsWith("/api/")) {
        return Response.json(
          {
            error: "Eroare internă în API-ul Poliției.",
            route: url.pathname,
            details: String(
              error?.message ||
              error ||
              "Eroare necunoscută"
            )
          },
          { status: 500 }
        );
      }

      throw error;
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await syncApprovedLeaveDiscordRoles();
      await initMeetingAttendanceScheduler();
    })());
  }
};
