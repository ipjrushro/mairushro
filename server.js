const express = require("express");
// Discord HTTP helper. We intentionally avoid Axios inside Cloudflare Workers:
// Axios can generate Request.cache="default", which Workers rejects with
// "Unsupported cache mode: default". This small compatibility wrapper keeps
// the existing axios.get/post/put/patch/delete call sites working via fetch().
function createHttpError(message, status, data) {
    const error = new Error(message);
    error.response = { status, data };
    return error;
}
async function httpRequest(method, url, data, config = {}) {
    const headers = { ...(config.headers || {}) };
    const init = { method, headers };
    if (data !== undefined && data !== null && method !== "GET" && method !== "HEAD") {
        if (typeof data === "string" || data instanceof Uint8Array || data instanceof ArrayBuffer) {
            init.body = data;
        } else {
            if (!Object.keys(headers).some(k => k.toLowerCase() === "content-type")) {
                headers["Content-Type"] = "application/json";
            }
            init.body = JSON.stringify(data);
        }
    }
    const response = await fetch(url, init);
    const text = await response.text();
    let parsed = null;
    if (text) {
        try { parsed = JSON.parse(text); } catch { parsed = text; }
    }
    if (!response.ok) {
        throw createHttpError(`HTTP ${response.status}`, response.status, parsed);
    }
    return { data: parsed, status: response.status, headers: response.headers };
}
const axios = {
    get: (url, config = {}) => httpRequest("GET", url, null, config),
    post: (url, data, config = {}) => httpRequest("POST", url, data, config),
    put: (url, data, config = {}) => httpRequest("PUT", url, data, config),
    patch: (url, data, config = {}) => httpRequest("PATCH", url, data, config),
    delete: (url, config = {}) => httpRequest("DELETE", url, null, config)
};
const cookieSession = require("cookie-session");
const path = require("path");
// Workers do not provide the CommonJS __dirname global. Static assets live in public/.
const APP_DIR = process.cwd();
const crypto = require("crypto");
const multer = require("multer");
const compression = require("compression");
const { createClient } = require("@supabase/supabase-js");
const {
    S3Client,
    PutObjectCommand,
    PutBucketCorsCommand,
    GetObjectCommand,
    HeadObjectCommand,
    ListObjectsV2Command,
    ListObjectVersionsCommand,
    DeleteObjectsCommand
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// ======================================================
// BANDWIDTH OPTIMIZATION
// Comprimă automat HTML/CSS/JS/JSON înainte de a pleca din Render.
// Fișierele deja mici nu sunt comprimate pentru a evita overhead inutil.
// ======================================================
app.set("etag", "strong");

// Pe Cloudflare Workers NU folosim middleware-ul Node `compression`.
// Workers/Cloudflare gestionează compresia la edge; middleware-ul Node poate
// trimite corp gzip/br corupt către browser, iar JSON.parse vede bytes binari.
if (process.env.CLOUDFLARE_WORKERS !== "1") {
    app.use(
        compression({
            threshold: 1024,
            level: 6
        })
    );
}


const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const GUILD_ID = process.env.DISCORD_GUILD_ID;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

const CALLSIGN_LOG_CHANNEL_ID = "1549734703915991130";
const CALLSIGN_DASHBOARD_URL =
    process.env.CALLSIGN_DASHBOARD_URL ||
    "/dashboard";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const B2_BUCKET = process.env.B2_BUCKET;
const B2_REGION = process.env.B2_REGION;
const B2_ENDPOINT = process.env.B2_ENDPOINT;
const B2_KEY_ID = process.env.B2_KEY_ID;
const B2_APPLICATION_KEY = process.env.B2_APPLICATION_KEY;

const b2 = new S3Client({
    endpoint: B2_ENDPOINT,
    region: B2_REGION,
    forcePathStyle: true,
    requestChecksumCalculation: "WHEN_REQUIRED",
    responseChecksumValidation: "WHEN_REQUIRED",
    credentials: {
        accessKeyId: B2_KEY_ID || "missing-key-id",
        secretAccessKey: B2_APPLICATION_KEY || "missing-application-key"
    }
});

if (
    !B2_BUCKET ||
    !B2_REGION ||
    !B2_ENDPOINT ||
    !B2_KEY_ID ||
    !B2_APPLICATION_KEY
) {
    console.warn(
        "[BACKBLAZE B2] Lipsesc una sau mai multe variabile B2_* din Environment."
    );
}


// ======================================================
// BACKBLAZE B2 CORS — DIRECT BROWSER UPLOAD
// ======================================================
const B2_DIRECT_UPLOAD_ORIGIN =
    process.env.B2_DIRECT_UPLOAD_ORIGIN ||
    "https://example.invalid";

let b2CorsReady = false;
let b2CorsPromise = null;

async function configureB2CorsForDirectUpload() {
    if (
        !B2_BUCKET ||
        !B2_REGION ||
        !B2_ENDPOINT ||
        !B2_KEY_ID ||
        !B2_APPLICATION_KEY
    ) {
        console.warn(
            "[BACKBLAZE B2 CORS] Configurarea CORS a fost omisă: lipsesc variabile B2_*."
        );
        return;
    }

    try {
        await b2.send(
            new PutBucketCorsCommand({
                Bucket: B2_BUCKET,
                CORSConfiguration: {
                    CORSRules: [
                        {
                            ID: "politie-direct-upload",
                            AllowedOrigins: [B2_DIRECT_UPLOAD_ORIGIN],
                            AllowedHeaders: ["*"],
                            AllowedMethods: ["GET", "PUT", "HEAD"],
                            ExposeHeaders: ["ETag"],
                            MaxAgeSeconds: 3600
                        }
                    ]
                }
            })
        );

        b2CorsReady = true;
        console.log(
            `[BACKBLAZE B2 CORS] OK pentru ${B2_DIRECT_UPLOAD_ORIGIN}`
        );
    } catch (error) {
        console.error(
            "[BACKBLAZE B2 CORS] Eroare la configurare:",
            error?.name || error?.message || error
        );
    }
}

async function ensureB2DirectUploadCors() {
    if (b2CorsReady) return;
    if (!b2CorsPromise) {
        b2CorsPromise = configureB2CorsForDirectUpload().finally(() => { b2CorsPromise = null; });
    }
    await b2CorsPromise;
}

const POLICE_ANNOUNCEMENT_CHANNELS = Object.freeze({
    POLITIE: "1528758226961567848",
    COMUNE: "1528758228031246406"
});

// Canale Discord pentru rapoarte operaționale
const RAID_REPORT_CHANNEL_ID = "1541732669409460345";
const TRAINING_REPORT_CHANNEL_ID = "1541879731127976056";

// Discord live logs shown on Police overview
const POLICE_FINE_LOG_CHANNEL_ID = "1528758230191181833";
const POLICE_JAIL_LOG_CHANNEL_ID = "1528758230191181832";
const POLICE_LOG_TIMEZONE = "Europe/Bucharest";
const POLICE_LOG_CACHE_TTL_MS = 60 * 1000;
let policeLogOverviewCache = { expiresAt: 0, data: null };


const VACATION_DAYS_LIMIT = 14;
const MEETING_EXCUSES_LIMIT = 2;

// Roluri Discord pentru concedii / învoiri
const VACATION_DISCORD_ROLE_ID = "1528758226319966341";
const MEETING_EXCUSE_DISCORD_ROLE_ID = "1528758226319966340";
const MEETING_EXCUSE_DURATION_MS = 24 * 60 * 60 * 1000;
const LEAVE_ROLE_SYNC_INTERVAL_MS = 5 * 60 * 1000;

const TESTER_DIICOT_ROLE_ID = "1528758226407919637";
const CANDIDATE_TEST_LOG_CHANNEL_ID = "1528758227628462270";
const LEAVE_RESET_USER_ID = "1315733546312142921";

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.warn(
        "[SUPABASE] Lipsesc SUPABASE_URL sau SUPABASE_SERVICE_KEY."
    );
}

const supabase = createClient(
    SUPABASE_URL || "https://example.supabase.co",
    SUPABASE_SERVICE_KEY || "missing-key",
    {
        auth: {
            persistSession: false,
            autoRefreshToken: false
        }
    }
);


// ======================================================
// GRADE POLITIA ROMANA
// ======================================================

// Numele vechi DIICOT_ROLES este păstrat intern pentru compatibilitate
// cu restul aplicației, dar lista conține exclusiv gradele Poliției.
const DIICOT_ROLES = [
    { id: "1528758226437275791", name: "RESPONSABIL GUVERNAMENTALE", level: 15 },
    { id: "1528758226437275788", name: "CHESTOR GENERAL", level: 14 },
    { id: "1528758226437275787", name: "CHESTOR PRINCIPAL", level: 13 },
    { id: "1528758226437275786", name: "CHESTOR SECUNDAR", level: 12 },
    { id: "1528758226428891368", name: "COMISAR ȘEF", level: 11 },
    { id: "1528758226428891366", name: "COMISAR", level: 10 },
    { id: "1528758226428891365", name: "SUB COMISAR", level: 9 },
    { id: "1528758226428891364", name: "INSPECTOR PRINCIPAL", level: 8 },
    { id: "1528758226428891363", name: "INSPECTOR", level: 7 },
    { id: "1528758226428891362", name: "SUB INSPECTOR", level: 6 },
    { id: "1528758226428891361", name: "AGENT ȘEF PRINCIPAL", level: 5 },
    { id: "1528758226428891360", name: "AGENT ȘEF ADJUNCT", level: 4 },
    { id: "1528758226428891359", name: "AGENT PRINCIPAL", level: 3 },
    { id: "1528758226420633752", name: "AGENT", level: 2 },
    { id: "1528758226420633750", name: "CADET", level: 1 }
];


// ======================================================
// ORGANIZATORI RAZIE / ANTRENAMENT
// Autorul raportului este primul organizator.
// În formular se selectează încă o persoană eligibilă.
// ======================================================

const REPORT_ORGANIZER_DEPARTMENTS = {
    DIICOT: [
        { id: "1528758226416435211", name: "SUB INSPECTOR DIICOT", weight: 1 },
        { id: "1528758226416435213", name: "INSPECTOR DIICOT", weight: 2 },
        { id: "1528758226416435214", name: "INSPECTOR PRINCIPAL DIICOT", weight: 3 },
        { id: "1528758226416435215", name: "SUB COMISAR DIICOT", weight: 4 },
        { id: "1528758226416435216", name: "COMISAR DIICOT", weight: 5 },
        { id: "1528758226416435217", name: "COMISAR ȘEF DIICOT", weight: 6 },
        { id: "1528758226416435219", name: "COORDONATOR DIICOT", weight: 7 },
        { id: "1528758226420633744", name: "PROCUROR DIICOT", weight: 8 },
        { id: "1528758226420633745", name: "PROCUROR ȘEF ADJUNCT DIICOT", weight: 9 },
        { id: "1528758226420633746", name: "PROCUROR ȘEF DIICOT", weight: 10 }
    ],

    POLITIE: [
        { id: "1528758226428891362", name: "SUB INSPECTOR", weight: 1 },
        { id: "1528758226428891363", name: "INSPECTOR", weight: 2 },
        { id: "1528758226428891364", name: "INSPECTOR PRINCIPAL", weight: 3 },
        { id: "1528758226428891365", name: "SUB COMISAR", weight: 4 },
        { id: "1528758226428891366", name: "COMISAR", weight: 5 },
        { id: "1528758226428891368", name: "COMISAR ȘEF", weight: 6 },
        { id: "1528758226437275786", name: "CHESTOR SECUNDAR", weight: 7 },
        { id: "1528758226437275787", name: "CHESTOR PRINCIPAL", weight: 8 },
        { id: "1528758226437275788", name: "CHESTOR GENERAL", weight: 9 },
        { id: "1528758226437275791", name: "RESPONSABIL GUVERNAMENTALE", weight: 10 }
    ]
};


function getReportOrganizerRank(roles = [], department = "") {
    const key = String(department || "").trim().toUpperCase();
    const allowed = REPORT_ORGANIZER_DEPARTMENTS[key];

    if (!Array.isArray(allowed)) {
        return null;
    }

    const roleSet = new Set(
        Array.isArray(roles)
            ? roles.map(String)
            : []
    );

    return (
        [...allowed]
            .sort((a, b) => Number(b.weight) - Number(a.weight))
            .find(role => roleSet.has(String(role.id))) ||
        null
    );
}


function discordMemberAvatar(user = {}) {
    if (user.avatar) {
        return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`;
    }

    let fallback = 0;

    try {
        fallback =
            Number(
                BigInt(user.id || "0") >> 22n
            ) % 6;
    } catch {
        fallback = 0;
    }

    return `https://cdn.discordapp.com/embed/avatars/${fallback}.png`;
}



// ======================================================
// DISCORD API CACHE / RATE-LIMIT PROTECTION
// Evită zeci de request-uri identice către Discord.
// ======================================================

const DISCORD_MEMBER_CACHE_TTL_MS = 5 * 60 * 1000;
const DISCORD_GUILD_CACHE_TTL_MS = 5 * 60 * 1000;

const discordMemberCache =
    new Map();

const discordMemberInflight =
    new Map();

let discordGuildMembersCache = {
    members: [],
    expiresAt: 0
};

let discordGuildMembersInflight =
    null;


function getDiscordRetryAfterMs(error) {
    const retryAfterBody =
        Number(
            error?.response?.data?.retry_after
        );

    if (
        Number.isFinite(retryAfterBody) &&
        retryAfterBody > 0
    ) {
        return Math.ceil(
            retryAfterBody * 1000
        );
    }

    const retryAfterHeader =
        Number(
            error?.response?.headers?.["retry-after"]
        );

    if (
        Number.isFinite(retryAfterHeader) &&
        retryAfterHeader > 0
    ) {
        return Math.ceil(
            retryAfterHeader * 1000
        );
    }

    return 0;
}


function isDiscordRateLimited(error) {
    return (
        Number(
            error?.response?.status
        ) === 429 ||
        String(
            error?.response?.data?.message ||
            ""
        )
            .toLowerCase()
            .includes(
                "rate limit"
            )
    );
}


async function getDiscordMemberCached(
    userId,
    {
        force = false
    } = {}
) {
    const id =
        String(
            userId ||
            ""
        ).trim();

    if (!id) {
        throw new Error(
            "Discord user ID invalid."
        );
    }

    const now =
        Date.now();

    const cached =
        discordMemberCache.get(
            id
        );

    if (
        !force &&
        cached &&
        cached.expiresAt >
            now
    ) {
        return cached.member;
    }

    if (
        discordMemberInflight.has(
            id
        )
    ) {
        return discordMemberInflight.get(
            id
        );
    }

    const promise =
        (async () => {
            try {
                // Cloudflare Workers: folosim fetch nativ. Axios poate ajunge
                // la Request.cache="default", care nu este suportat de Workers.
                const response = await fetch(
                    `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${id}`,
                    {
                        headers: {
                            Authorization: `Bot ${BOT_TOKEN}`
                        }
                    }
                );

                if (!response.ok) {
                    const details = await response.text();
                    const error = new Error(
                        `Discord member request failed (${response.status}): ${details}`
                    );
                    error.response = {
                        status: response.status,
                        data: (() => {
                            try { return JSON.parse(details); }
                            catch { return { message: details }; }
                        })(),
                        headers: {
                            "retry-after": response.headers.get("retry-after")
                        }
                    };
                    throw error;
                }

                const member = await response.json();

                discordMemberCache.set(
                    id,
                    {
                        member,
                        expiresAt:
                            Date.now() +
                            DISCORD_MEMBER_CACHE_TTL_MS
                    }
                );

                return member;
            }
            catch (error) {
                // Dacă Discord ne limitează temporar, folosim copia veche
                // în loc să stricăm tot dashboard-ul.
                if (
                    isDiscordRateLimited(
                        error
                    ) &&
                    cached?.member
                ) {
                    console.warn(
                        `[Discord Cache] Rate limit pentru ${id}; folosesc datele din cache.`
                    );

                    return cached.member;
                }

                throw error;
            }
            finally {
                discordMemberInflight.delete(
                    id
                );
            }
        })();

    discordMemberInflight.set(
        id,
        promise
    );

    return promise;
}


async function getGuildMembersCached({ force = false } = {}) {
    const now = Date.now();

    if (!force && discordGuildMembersCache.members.length &&
        discordGuildMembersCache.expiresAt > now) {
        return discordGuildMembersCache.members;
    }

    if (discordGuildMembersInflight) return discordGuildMembersInflight;

    discordGuildMembersInflight = (async () => {
        const oldMembers = discordGuildMembersCache.members;
        try {
            const allMembers = [];
            let after = "0";
            let pages = 0;

            while (pages < 50) {
                pages += 1;
                const url = new URL(`https://discord.com/api/v10/guilds/${GUILD_ID}/members`);
                url.searchParams.set("limit", "1000");
                url.searchParams.set("after", after);

                const response = await fetch(url.toString(), {
                    method: "GET",
                    headers: {
                        Authorization: `Bot ${BOT_TOKEN}`,
                        Accept: "application/json"
                    }
                });

                if (!response.ok) {
                    const details = await response.text();
                    const error = new Error(`Discord members HTTP ${response.status}: ${details.slice(0,300)}`);
                    error.response = {
                        status: response.status,
                        data: (() => { try { return JSON.parse(details); } catch { return {message:details}; } })(),
                        headers: {"retry-after": response.headers.get("retry-after")}
                    };
                    throw error;
                }

                const data = await response.json();
                const page = Array.isArray(data) ? data : [];
                if (!page.length) break;

                allMembers.push(...page);

                for (const member of page) {
                    const id = String(member?.user?.id || "");
                    if (id) {
                        discordMemberCache.set(id, {
                            member,
                            expiresAt: Date.now() + DISCORD_MEMBER_CACHE_TTL_MS
                        });
                    }
                }

                if (page.length < 1000) break;
                const lastId = page[page.length - 1]?.user?.id;
                if (!lastId) break;
                after = String(lastId);
            }

            discordGuildMembersCache = {
                members: allMembers,
                expiresAt: Date.now() + DISCORD_GUILD_CACHE_TTL_MS
            };
            console.log(`[Discord Cache] Guild members refresh: ${allMembers.length} membri.`);
            return allMembers;
        } catch (error) {
            if (isDiscordRateLimited(error) && oldMembers.length) {
                console.warn("[Discord Cache] Discord rate limited; folosesc lista veche din cache.");
                return oldMembers;
            }
            throw error;
        } finally {
            discordGuildMembersInflight = null;
        }
    })();

    return discordGuildMembersInflight;
}




// ======================================================
// ELIGIBILITATE UP — CERINȚE PE GRAD
// ======================================================

const PROMOTION_REQUIREMENTS = {
    1: {
        nextRank: "AGENT",
        reports: 15,
        raids: 0,
        trainings: 0,
        minDays: 3,
        dutyHours: 15,
        manual: [
            "Omologări",
            "Prezență la razii",
            "Cunoașterea elementară a regulamentului"
        ]
    },

    2: {
        nextRank: "AGENT PRINCIPAL",
        reports: 25,
        raids: 0,
        trainings: 0,
        minDays: 7,
        dutyHours: 15,
        manual: []
    },

    3: {
        nextRank: "AGENT ȘEF ADJUNCT",
        reports: 30,
        raids: 0,
        trainings: 0,
        minDays: 7,
        dutyHours: 15,
        manual: [
            "Activitate constantă",
            "Anunțuri la CNN"
        ]
    },

    4: {
        nextRank: "AGENT ȘEF PRINCIPAL",
        reports: 40,
        raids: 0,
        trainings: 0,
        minDays: 10,
        dutyHours: 15,
        manual: [
            "Activitate excelentă, fără abateri"
        ]
    },

    5: {
        nextRank: "SUB INSPECTOR",
        reports: 45,
        raids: 0,
        trainings: 0,
        minDays: 14,
        dutyHours: 15,
        manual: [
            "Pregătirea cadeților"
        ]
    },

    6: {
        nextRank: "INSPECTOR",
        reports: 60,
        raids: 0,
        trainings: 0,
        minDays: 20,
        dutyHours: 15,
        manual: [
            "Implicare în coordonare"
        ]
    }
};


// ======================================================
// PONTAJ POLITIE — BACKBLAZE B2
// Botul scrie câte un JSON per utilizator în pontaj/users/<discordId>.json.
// Site-ul citește sesiunile și numără doar timpul suprapus perioadei
// gradului curent, astfel orele vechi nu se refolosesc la următorul UP.
// ======================================================
const DUTY_B2_PREFIX = "pontaj/users/";

async function b2BodyToString(body) {
    if (!body) return "";
    if (typeof body.transformToString === "function") {
        return await body.transformToString();
    }
    const chunks = [];
    for await (const chunk of body) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks).toString("utf8");
}

function dutyB2Key(userId) {
    return `${DUTY_B2_PREFIX}${String(userId).replace(/\D/g, "")}.json`;
}

async function readDutyRecord(userId) {
    try {
        const result = await b2.send(new GetObjectCommand({
            Bucket: B2_BUCKET,
            Key: dutyB2Key(userId)
        }));
        const raw = await b2BodyToString(result.Body);
        const parsed = JSON.parse(raw || "{}");
        return {
            userId: String(userId),
            active: Boolean(parsed.active),
            activeSince: Number(parsed.activeSince || 0) || null,
            sessions: Array.isArray(parsed.sessions) ? parsed.sessions : []
        };
    } catch (error) {
        const status = Number(error?.$metadata?.httpStatusCode || error?.statusCode || 0);
        const name = String(error?.name || "");
        if (status === 404 || name === "NoSuchKey" || name === "NotFound") {
            return { userId: String(userId), active: false, activeSince: null, sessions: [] };
        }
        console.error("Duty B2 Read Error:", error?.message || error);
        return { userId: String(userId), active: false, activeSince: null, sessions: [] };
    }
}

function calculateDutyMsSince(record, sinceMs) {
    const since = Number(sinceMs || 0);
    const now = Date.now();
    let total = 0;

    for (const session of (record?.sessions || [])) {
        const start = Number(session.start || session.startTime || 0);
        const end = Number(session.end || session.endTime || 0);
        if (!start || !end || end <= start) continue;

        const effectiveStart = Math.max(start, since);
        const effectiveEnd = Math.min(end, now);
        if (effectiveEnd > effectiveStart) total += effectiveEnd - effectiveStart;
    }

    if (record?.active && Number(record.activeSince || 0)) {
        const effectiveStart = Math.max(Number(record.activeSince), since);
        if (now > effectiveStart) total += now - effectiveStart;
    }

    return total;
}

function formatDutyDuration(ms) {
    const safe = Math.max(0, Number(ms || 0));
    const hours = Math.floor(safe / 3600000);
    const minutes = Math.floor((safe % 3600000) / 60000);
    return `${hours}h ${minutes}m`;
}


async function ensureRankProgressRow(
    userId,
    rank
) {
    const fallback = {
        user_id:
            String(userId),

        rank_role_id:
            rank?.id ||
            "",

        rank_name:
            rank?.name ||
            "",

        rank_since:
            new Date().toISOString()
    };

    if (!supabase || !rank?.id) {
        return fallback;
    }

    try {
        const {
            data,
            error
        } =
            await supabase
                .from("rank_progress")
                .select("*")
                .eq(
                    "user_id",
                    String(userId)
                )
                .maybeSingle();

        if (error) {
            throw error;
        }

        if (
            !data ||
            String(data.rank_role_id || "") !==
                String(rank.id)
        ) {
            const row = {
                user_id:
                    String(userId),

                rank_role_id:
                    String(rank.id),

                rank_name:
                    String(rank.name),

                rank_since:
                    new Date().toISOString(),

                updated_at:
                    new Date().toISOString()
            };

            const {
                data:
                    saved,

                error:
                    saveError
            } =
                await supabase
                    .from("rank_progress")
                    .upsert(
                        row,
                        {
                            onConflict:
                                "user_id"
                        }
                    )
                    .select("*")
                    .single();

            if (saveError) {
                throw saveError;
            }

            return saved;
        }

        return data;

    } catch (error) {
        console.error(
            "Rank Progress Error:",
            error.message ||
            error
        );

        return fallback;
    }
}


async function resetRankProgressNow(
    userId,
    rank
) {
    if (!supabase || !rank?.id) {
        return;
    }

    try {
        const now =
            new Date().toISOString();

        const {
            error
        } =
            await supabase
                .from("rank_progress")
                .upsert(
                    {
                        user_id:
                            String(userId),

                        rank_role_id:
                            String(rank.id),

                        rank_name:
                            String(rank.name),

                        rank_since:
                            now,

                        updated_at:
                            now
                    },
                    {
                        onConflict:
                            "user_id"
                    }
                );

        if (error) {
            throw error;
        }

    } catch (error) {
        console.error(
            "Rank Progress Reset Error:",
            error.message ||
            error
        );
    }
}


function getReportTimestamp(report) {
    const value =
        report?.createdAt ||
        report?.created_at ||
        null;

    const time =
        value
            ? new Date(value).getTime()
            : NaN;

    return Number.isFinite(time)
        ? time
        : 0;
}


async function buildPromotionEligibility(
    userId,
    rank,
    ownReports = []
) {
    const requirement =
        PROMOTION_REQUIREMENTS[
            Number(rank?.level || 0)
        ] ||
        null;

    const tracker =
        await ensureRankProgressRow(
            userId,
            rank
        );

    const rankSinceISO =
        tracker?.rank_since ||
        new Date().toISOString();

    const rankSinceTime =
        new Date(
            rankSinceISO
        ).getTime();

    const validSince =
        Number.isFinite(rankSinceTime)
            ? rankSinceTime
            : Date.now();

    // Numărăm inclusiv ziua intrării în grad:
    // în prima zi afișăm 1, apoi 2, 3 etc.
    const daysInRank =
        Math.max(
            1,
            Math.floor(
                (
                    Date.now() -
                    validSince
                ) /
                86400000
            ) + 1
        );

    if (!requirement) {
        return {
            tracked:
                true,

            meritOnly:
                Number(rank?.level || 0) >= 7,

            currentRank:
                rank?.name ||
                "-",

            nextRank:
                null,

            rankSince:
                rankSinceISO,

            daysInRank,

            requirements:
                null,

            progress: {
                reports: 0,
                raids: 0,
                trainings: 0,
                dutyMs: 0,
                dutyHours: 0,
                dutyFormatted: "0h 0m",
                dutyActive: false
            },

            numericEligible:
                false,

            manualCriteria:
                [
                    "Promovarea se acordă strict pe încredere și merit."
                ]
        };
    }

    // Pentru progresul RAPOARTE folosim toate rapoartele existente ale
    // utilizatorului. rank_progress poate fi creat abia la prima accesare,
    // iar filtrarea după rank_since făcea rapoartele deja existente să apară 0.
    const reportsSinceRank =
        Array.isArray(ownReports)
            ? ownReports
            : [];

    let raids = 0;
    let trainings = 0;

    if (
        Number(requirement.raids || 0) > 0 ||
        Number(requirement.trainings || 0) > 0
    ) {
        try {
            const allReports =
                await listB2Reports();

            const userIdString =
                String(userId);

            const involvedReports =
                allReports.filter(
                    report => {
                        if (
                            getReportTimestamp(
                                report
                            ) < validSince
                        ) {
                            return false;
                        }

                        const isAuthor =
                            String(
                                report.authorId ||
                                ""
                            ) ===
                            userIdString;

                        const isCoOrganizer =
                            String(
                                report.coOrganizer?.id ||
                                ""
                            ) ===
                            userIdString;

                        return (
                            isAuthor ||
                            isCoOrganizer
                        );
                    }
                );

            raids =
                involvedReports.filter(
                    report =>
                        report.type ===
                        "RAZIE"
                ).length;

            trainings =
                involvedReports.filter(
                    report =>
                        report.type ===
                        "ANTRENAMENT"
                ).length;

        } catch (error) {
            console.error(
                "Promotion Activity Count Error:",
                error.message ||
                error
            );
        }
    }

    const dutyRecord = await readDutyRecord(userId);
    const dutyMs = calculateDutyMsSince(dutyRecord, validSince);
    const dutyHours = dutyMs / 3600000;

    const progress = {
        reports:
            reportsSinceRank.length,

        raids,

        trainings,
        dutyMs,
        dutyHours,
        dutyFormatted: formatDutyDuration(dutyMs),
        dutyActive: Boolean(dutyRecord?.active)
    };

    const numericEligible =
        progress.reports >=
            Number(requirement.reports || 0) &&
        raids >=
            Number(requirement.raids || 0) &&
        trainings >=
            Number(requirement.trainings || 0) &&
        dutyHours >=
            Number(requirement.dutyHours || 0) &&
        daysInRank >=
            Number(requirement.minDays || 0);

    return {
        tracked:
            true,

        meritOnly:
            false,

        currentRank:
            rank?.name ||
            "-",

        nextRank:
            requirement.nextRank,

        rankSince:
            rankSinceISO,

        daysInRank,

        requirements: {
            reports:
                Number(
                    requirement.reports ||
                    0
                ),

            raids:
                Number(
                    requirement.raids ||
                    0
                ),

            trainings:
                Number(
                    requirement.trainings ||
                    0
                ),

            minDays:
                Number(
                    requirement.minDays ||
                    0
                ),

            dutyHours:
                Number(
                    requirement.dutyHours ||
                    0
                )
        },

        progress,

        numericEligible,

        manualCriteria:
            Array.isArray(
                requirement.manual
            )
                ? requirement.manual
                : []
    };
}



const DIICOT_ROLE_BY_ID =
    new Map(
        DIICOT_ROLES.map(
            role => [
                String(role.id),
                role
            ]
        )
    );


function resolveHighestDIICOTRoleSafe(roles = []) {
    const ids =
        Array.isArray(roles)
            ? roles.map(String)
            : [];

    let best = null;

    for (const roleId of ids) {
        const match =
            DIICOT_ROLE_BY_ID.get(
                String(roleId)
            );

        if (
            match &&
            (
                !best ||
                Number(match.level) >
                Number(best.level)
            )
        ) {
            best =
                match;
        }
    }

    return best;
}


function getHighestDIICOTRole(roles = []) {
    return resolveHighestDIICOTRoleSafe(
        roles
    );
}


// ======================================================
// HELPERS ACȚIUNI CONDUCERE
// ======================================================

function getDIICOTRoleByLevel(level) {
    return (
        DIICOT_ROLES.find(
            role =>
                Number(role.level) ===
                Number(level)
        ) || null
    );
}


function normalizeCallsign(value) {
    const raw = String(value || "")
        .trim()
        .toUpperCase()
        .replace(/^\[/, "")
        .replace(/\]$/, "")
        .replace(/^(?:P-|D-)/, "")
        .trim();

    if (!/^\d{1,3}$/.test(raw)) return null;

    const number = Number(raw);
    if (!Number.isInteger(number)) return null;

    // Acceptăm exclusiv sloturile/call-sign-urile definite pentru Poliție.
    const rank = getDocsRankForSlot(number);
    if (!rank || Number(rank.level) < 0) return null;

    return String(number).padStart(3, "0");
}


function removeExistingCallsign(name) {
    return String(name || "")
        .replace(/^\s*\[(?:D-|P-)?\d{1,3}\]\s*/i, "")
        .trim();
}


function buildCallsignNickname(
    callsign,
    currentName
) {

    const cleanName =
        removeExistingCallsign(
            currentName
        );

    return `[${callsign}] ${cleanName}`.trim();
}


// ======================================================
// EXPRESS
// ======================================================

app.set("trust proxy", 1);

app.use(
    express.json()
);

app.use(
    express.urlencoded({
        extended: true
    })
);


// ======================================================
// SESSION
// ======================================================

app.use(
    cookieSession({
        name: "diicot_session",

        keys: [
            process.env.SESSION_SECRET ||
            "change-this-secret"
        ],

        maxAge:
            24 *
            60 *
            60 *
            1000,

        httpOnly: true,

        sameSite: "lax",

        secure:
            process.env.NODE_ENV ===
            "production"
    })
);


// ======================================================
// FIȘIERE STATICE
// Logo-ul DIICOT poate rămâne în /uploads
// Rapoartele și pozele rapoartelor merg în Backblaze B2.
// ======================================================

const uploadsDirectory =
    path.join(
        APP_DIR,
        "uploads"
    );

app.use(
    "/uploads",
    express.static(
        uploadsDirectory,
        {
            maxAge: "7d",
            immutable: true,
            etag: true,
            lastModified: true
        }
    )
);


// ======================================================
// COADA RAPOARTE - PROTECTIE PENTRU TRAFIC SIMULTAN
// Proceseaza maximum 2 trimiteri de rapoarte simultan.
// Restul asteapta in coada, in loc sa incarce serverul deodata.
// ======================================================
const REPORT_UPLOAD_CONCURRENCY = 2;
const REPORT_UPLOAD_QUEUE_LIMIT = 100;
let activeReportUploads = 0;
const reportUploadQueue = [];

function releaseReportUploadSlot() {
    activeReportUploads = Math.max(0, activeReportUploads - 1);
    const next = reportUploadQueue.shift();
    if (next) {
        activeReportUploads += 1;
        next();
    }
}

function reportUploadSlotGuard(req, res, next) {
    const enter = () => {
        let released = false;
        const releaseOnce = () => {
            if (released) return;
            released = true;
            releaseReportUploadSlot();
        };
        res.once("finish", releaseOnce);
        res.once("close", releaseOnce);
        next();
    };

    if (activeReportUploads < REPORT_UPLOAD_CONCURRENCY) {
        activeReportUploads += 1;
        return enter();
    }

    if (reportUploadQueue.length >= REPORT_UPLOAD_QUEUE_LIMIT) {
        return res.status(503).json({
            error: "Sunt prea multe rapoarte trimise simultan. Incearca din nou in cateva secunde."
        });
    }

    reportUploadQueue.push(enter);
}

// ======================================================
// MULTER - MEMORIE
// Nu mai salvăm pozele rapoartelor pe discul Render.
// ======================================================

const upload =
    multer({
        storage:
            multer.memoryStorage(),

        limits: {
            fileSize:
                8 *
                1024 *
                1024,

            files: 5
        },

        fileFilter(
            req,
            file,
            callback
        ) {

            const allowed = [
                "image/jpeg",
                "image/png",
                "image/webp"
            ];

            if (
                allowed.includes(
                    file.mimetype
                )
            ) {

                return callback(
                    null,
                    true
                );
            }

            callback(
                new Error(
                    "Sunt acceptate doar imagini JPG, PNG și WEBP."
                )
            );
        }
    });


// ======================================================
// HELPERS GENERALE
// ======================================================

function formatRomanianDate(date) {

    return new Date(date)
        .toLocaleString(
            "ro-RO",
            {
                timeZone:
                    "Europe/Bucharest",

                day:
                    "2-digit",

                month:
                    "2-digit",

                year:
                    "numeric",

                hour:
                    "2-digit",

                minute:
                    "2-digit"
            }
        );
}


function formatDateOnlyRO(value) {

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return "-";
    }

    return date
        .toLocaleDateString(
            "ro-RO",
            {
                timeZone:
                    "Europe/Bucharest",

                day:
                    "2-digit",

                month:
                    "2-digit",

                year:
                    "numeric"
            }
        );
}


function parseDateOnly(value) {

    value =
        String(
            value || ""
        );

    if (
        !/^\d{4}-\d{2}-\d{2}$/
            .test(value)
    ) {

        return null;
    }

    const [
        year,
        month,
        day
    ] =
        value
            .split("-")
            .map(Number);

    const date =
        new Date(
            year,
            month - 1,
            day
        );

    if (
        date.getFullYear() !==
            year ||
        date.getMonth() !==
            month - 1 ||
        date.getDate() !==
            day
    ) {

        return null;
    }

    return date;
}


function inclusiveDays(
    start,
    end
) {

    const difference =
        end.getTime() -
        start.getTime();

    return (
        Math.floor(
            difference /
            86400000
        ) + 1
    );
}


function getExtensionFromMime(
    mimetype
) {

    if (
        mimetype ===
        "image/png"
    ) {

        return "png";
    }

    if (
        mimetype ===
        "image/webp"
    ) {

        return "webp";
    }

    return "jpg";
}


// ======================================================
// SUPABASE HELPERS
// ======================================================

function ensureSupabase(
    res
) {

    if (
        !SUPABASE_URL ||
        !SUPABASE_SERVICE_KEY
    ) {

        res
            .status(503)
            .json({
                error:
                    "Supabase nu este configurat pe server."
            });

        return false;
    }

    return true;
}


// ======================================================
// BACKBLAZE B2 - RAPOARTE
// Rapoartele sunt fișiere JSON în B2, iar dovezile foto
// sunt obiecte separate în același bucket privat.
// ======================================================

function ensureB2(res) {
    if (
        !B2_BUCKET ||
        !B2_REGION ||
        !B2_ENDPOINT ||
        !B2_KEY_ID ||
        !B2_APPLICATION_KEY
    ) {
        res.status(503).json({
            error:
                "Backblaze B2 nu este configurat complet pe server."
        });

        return false;
    }

    return true;
}

const B2_SIGNED_URL_TTL_SECONDS = 60 * 60; // 1 oră

function getB2ImageKey(image = {}) {
    const directKey = String(
        image?.key ||
        image?.path ||
        ""
    ).trim();

    if (directKey.startsWith("images/")) {
        return directKey;
    }

    // Compatibilitate cu rapoartele vechi care au URL-ul proxy Render salvat.
    const oldUrl = String(image?.url || "");
    const prefix = "/api/report-files/";

    if (oldUrl.startsWith(prefix)) {
        try {
            const decoded = decodeURIComponent(
                oldUrl.slice(prefix.length)
            );

            if (decoded.startsWith("images/") && !decoded.includes("..")) {
                return decoded;
            }
        } catch {
            return "";
        }
    }

    return "";
}

async function getB2DirectSignedUrl(key) {
    const cleanKey = String(key || "").trim();

    if (!cleanKey.startsWith("images/") || cleanKey.includes("..")) {
        return null;
    }

    return getSignedUrl(
        b2,
        new GetObjectCommand({
            Bucket: B2_BUCKET,
            Key: cleanKey
        }),
        {
            expiresIn: B2_SIGNED_URL_TTL_SECONDS
        }
    );
}

async function withDirectB2ImageUrls(report) {
    const mapped = mapB2Report(report);

    if (!mapped) {
        return null;
    }

    mapped.images = await Promise.all(
        (mapped.images || []).map(async image => {
            const key = getB2ImageKey(image);

            if (!key) {
                return { ...image };
            }

            return {
                ...image,
                key,
                path: key,
                provider: "b2",
                // Browserul descarcă direct din Backblaze B2.
                // Traficul imaginii NU mai trece prin Render.
                url: await getB2DirectSignedUrl(key)
            };
        })
    );

    return mapped;
}

async function withDirectB2ImageUrlsMany(reports = []) {
    return Promise.all(
        (Array.isArray(reports) ? reports : [])
            .map(report => withDirectB2ImageUrls(report))
    );
}

function mapB2Report(report) {
    if (!report) {
        return null;
    }

    const createdAt =
        report.createdAt ||
        report.created_at ||
        new Date().toISOString();

    return {
        id:
            report.id,

        authorId:
            report.authorId ||
            report.author_id,

        authorName:
            report.authorName ||
            report.author_name,

        authorUsername:
            report.authorUsername ||
            report.author_username,

        authorRank:
            report.authorRank ||
            report.author_rank,

        authorRankLevel:
            Number(
                report.authorRankLevel ??
                report.author_rank_level ??
                0
            ),

        type:
            report.type,

        title:
            report.title,

        description:
            report.description,

        coOrganizer:
            report.coOrganizer ||
            report.co_organizer ||
            null,

        images:
            Array.isArray(report.images)
                ? report.images
                : [],

        createdAt,

        createdAtFormatted:
            formatRomanianDate(createdAt)
    };
}

async function b2BodyToString(body) {
    if (!body) {
        return "";
    }

    if (typeof body.transformToString === "function") {
        return body.transformToString("utf-8");
    }

    const chunks = [];

    for await (const chunk of body) {
        chunks.push(Buffer.from(chunk));
    }

    return Buffer.concat(chunks).toString("utf-8");
}

async function listB2ObjectKeys(prefix) {
    const keys = [];
    let continuationToken;

    do {
        const response = await b2.send(
            new ListObjectsV2Command({
                Bucket: B2_BUCKET,
                Prefix: prefix,
                ContinuationToken: continuationToken
            })
        );

        for (const object of response.Contents || []) {
            if (object.Key) {
                keys.push(object.Key);
            }
        }

        continuationToken =
            response.IsTruncated
                ? response.NextContinuationToken
                : undefined;

    } while (continuationToken);

    return keys;
}

async function readB2JSON(key) {
    const response = await b2.send(
        new GetObjectCommand({
            Bucket: B2_BUCKET,
            Key: key
        })
    );

    const text = await b2BodyToString(response.Body);
    return JSON.parse(text);
}

// ======================================================
// CACHE RAPOARTE BACKBLAZE B2
// Evită descărcarea tuturor fișierelor JSON la fiecare accesare.
// Cache-ul este global pe instanța Render și este actualizat imediat
// când se postează un raport nou.
// ======================================================

const B2_REPORT_CACHE_TTL_MS =
    6 * 60 * 60 * 1000; // 6 ore

let b2ReportCache = {
    reports: [],
    loadedAt: 0
};

let b2ReportCacheRefreshPromise = null;

function sortB2Reports(reports) {
    reports.sort(
        (a, b) =>
            new Date(b.createdAt).getTime() -
            new Date(a.createdAt).getTime()
    );

    return reports;
}

function isB2ReportCacheFresh() {
    return (
        Array.isArray(b2ReportCache.reports) &&
        b2ReportCache.loadedAt > 0 &&
        Date.now() - b2ReportCache.loadedAt <
            B2_REPORT_CACHE_TTL_MS
    );
}

function addReportToB2Cache(report) {
    if (!b2ReportCache.loadedAt) {
        return;
    }

    const mapped = mapB2Report(report);

    b2ReportCache.reports =
        b2ReportCache.reports.filter(
            existing =>
                String(existing.id) !==
                String(mapped.id)
        );

    b2ReportCache.reports.push(mapped);
    sortB2Reports(b2ReportCache.reports);

    // Tocmai am actualizat cache-ul cu raportul nou,
    // deci îl considerăm din nou proaspăt.
    b2ReportCache.loadedAt = Date.now();
}

function clearB2ReportCache() {
    b2ReportCache = {
        reports: [],
        loadedAt: 0
    };
}

async function loadAllB2ReportsFromStorage() {
    const keys = (await listB2ObjectKeys("reports/"))
        .filter(key => key.endsWith(".json"));

    const reports = [];

    // Loturi mici ca să nu trimitem foarte multe request-uri simultan.
    const batchSize = 6;

    for (
        let index = 0;
        index < keys.length;
        index += batchSize
    ) {
        const batch =
            keys.slice(
                index,
                index + batchSize
            );

        const rows =
            await Promise.all(
                batch.map(
                    async key => {
                        try {
                            return mapB2Report(
                                await readB2JSON(
                                    key
                                )
                            );
                        }
                        catch (error) {
                            console.error(
                                "B2 report read error:",
                                key,
                                error.message
                            );

                            return null;
                        }
                    }
                )
            );

        reports.push(
            ...rows.filter(Boolean)
        );
    }

    return sortB2Reports(reports);
}

async function getAllB2ReportsCached() {
    if (isB2ReportCacheFresh()) {
        return b2ReportCache.reports;
    }

    // Dacă mai există deja un refresh pornit, toate request-urile
    // așteaptă același Promise în loc să descarce aceleași JSON-uri iar.
    if (b2ReportCacheRefreshPromise) {
        return b2ReportCacheRefreshPromise;
    }

    b2ReportCacheRefreshPromise =
        (async () => {
            try {
                const reports =
                    await loadAllB2ReportsFromStorage();

                b2ReportCache = {
                    reports,
                    loadedAt: Date.now()
                };

                console.log(
                    `[B2 CACHE] ${reports.length} rapoarte încărcate în cache pentru 6 ore.`
                );

                return reports;
            }
            catch (error) {
                // Dacă B2 atinge iar cap-ul, folosim copia veche din memorie
                // în loc să stricăm pagina, dacă avem una disponibilă.
                if (
                    Array.isArray(
                        b2ReportCache.reports
                    ) &&
                    b2ReportCache.loadedAt > 0
                ) {
                    console.warn(
                        "[B2 CACHE] B2 indisponibil/cap depășit. Folosesc cache-ul existent.",
                        error.message
                    );

                    return b2ReportCache.reports;
                }

                throw error;
            }
            finally {
                b2ReportCacheRefreshPromise =
                    null;
            }
        })();

    return b2ReportCacheRefreshPromise;
}

async function listB2Reports(authorId = null) {
    const allReports =
        await getAllB2ReportsCached();

    if (!authorId) {
        return allReports;
    }

    const authorIdString =
        String(authorId);

    return allReports.filter(
        report =>
            String(
                report.authorId ||
                ""
            ) === authorIdString
    );
}

async function listB2ObjectVersions(prefix) {
    const objects = [];
    let keyMarker;
    let versionIdMarker;

    do {
        const response = await b2.send(
            new ListObjectVersionsCommand({
                Bucket: B2_BUCKET,
                Prefix: prefix,
                KeyMarker: keyMarker,
                VersionIdMarker: versionIdMarker
            })
        );

        for (const version of response.Versions || []) {
            if (version.Key && version.VersionId) {
                objects.push({
                    Key: version.Key,
                    VersionId: version.VersionId
                });
            }
        }

        for (const marker of response.DeleteMarkers || []) {
            if (marker.Key && marker.VersionId) {
                objects.push({
                    Key: marker.Key,
                    VersionId: marker.VersionId
                });
            }
        }

        if (response.IsTruncated) {
            keyMarker = response.NextKeyMarker;
            versionIdMarker = response.NextVersionIdMarker;
        } else {
            keyMarker = undefined;
            versionIdMarker = undefined;
        }
    } while (keyMarker);

    return objects;
}

async function deleteB2Objects(objects) {
    const unique = [];
    const seen = new Set();

    for (const object of objects || []) {
        if (!object || !object.Key) continue;
        const item = { Key: String(object.Key) };
        if (object.VersionId) item.VersionId = String(object.VersionId);
        const signature = `${item.Key}::${item.VersionId || ""}`;
        if (seen.has(signature)) continue;
        seen.add(signature);
        unique.push(item);
    }

    for (let index = 0; index < unique.length; index += 1000) {
        const batch = unique.slice(index, index + 1000);
        if (!batch.length) continue;

        const response = await b2.send(
            new DeleteObjectsCommand({
                Bucket: B2_BUCKET,
                Delete: { Objects: batch, Quiet: false }
            })
        );

        if (response.Errors && response.Errors.length) {
            throw new Error(
                `B2 delete error: ${response.Errors.map(e => `${e.Key || "?"}: ${e.Code || "Error"} ${e.Message || ""}`).join(" | ")}`
            );
        }
    }
}

async function deleteB2Keys(keys) {
    await deleteB2Objects(
        Array.from(new Set((keys || []).map(String).filter(Boolean)))
            .map(Key => ({ Key }))
    );
}



function mapTestCategory(row) {
    if (!row) return null;

    return {
        id: row.id,
        name: row.name,
        position: Number(row.position || 0)
    };
}


function mapTestQuestion(row) {
    if (!row) return null;

    return {
        id: row.id,
        categoryId: row.category_id,
        question: row.question,
        answer: row.answer,
        position: Number(row.position || 0)
    };
}


function mapTestHistory(row) {
    if (!row) return null;

    return {
        id: row.id,
        candidateName: row.candidate_name,
        candidateDiscord: row.candidate_discord,
        department: row.department,
        testerId: row.tester_id,
        testerName: row.tester_name,
        testerRank: row.tester_rank,
        mistakes: Number(row.mistakes || 0),
        threshold: Number(row.threshold || 0),
        verdict: row.verdict,
        createdAt: row.created_at
    };
}


function mapBlacklist(row) {

    if (!row) {
        return null;
    }

    return {
        id:
            row.id,

        discordId:
            row.discord_id,

        name:
            row.name,

        username:
            row.username,

        avatar:
            row.avatar,

        reason:
            row.reason,

        durationType:
            row.duration_type,

        expiresAt:
            row.expires_at,

        expiresAtFormatted:
            row.duration_type ===
            "PERMANENT"

                ? "Permanent"

                : row.expires_at

                    ? formatRomanianDate(
                        row.expires_at
                    )

                    : "-",

        status:
            row.status,

        createdAt:
            row.created_at,

        createdAtFormatted:
            formatRomanianDate(
                row.created_at
            ),

        addedById:
            row.added_by_id,

        addedByName:
            row.added_by_name,

        addedByUsername:
            row.added_by_username,

        addedByRank:
            row.added_by_rank,

        deactivatedAt:
            row.deactivated_at,

        deactivatedAtFormatted:
            row.deactivated_at

                ? formatRomanianDate(
                    row.deactivated_at
                )

                : null,

        deactivatedById:
            row.deactivated_by_id,

        deactivatedByName:
            row.deactivated_by_name,

        deactivatedReason:
            row.deactivated_reason,

        updatedAt:
            row.updated_at,

        updatedById:
            row.updated_by_id,

        updatedByName:
            row.updated_by_name
    };
}


function mapLeaveRequest(row) {

    if (!row) {
        return null;
    }

    const request = {
        id:
            row.id,

        authorId:
            row.author_id,

        authorName:
            row.author_name,

        authorUsername:
            row.author_username,

        authorRank:
            row.author_rank,

        type:
            row.type,

        startDate:
            row.start_date,

        endDate:
            row.end_date,

        startDateFormatted:
            formatDateOnlyRO(
                `${row.start_date}T12:00:00`
            ),

        endDateFormatted:
            formatDateOnlyRO(
                `${row.end_date}T12:00:00`
            ),

        days:
            Number(
                row.days || 1
            ),

        reason:
            row.reason,

        status:
            row.status,

        evaluatorId:
            row.evaluator_id,

        evaluatorName:
            row.evaluator_name,

        evaluatorRank:
            row.evaluator_rank,

        decisionNote:
            row.decision_note,

        decidedAt:
            row.decided_at,

        decidedAtFormatted:
            row.decided_at

                ? formatRomanianDate(
                    row.decided_at
                )

                : null,

        cancelledAt:
            row.cancelled_at,

        cancelledAtFormatted:
            row.cancelled_at

                ? formatRomanianDate(
                    row.cancelled_at
                )

                : null,

        createdAt:
            row.created_at,

        createdAtFormatted:
            formatRomanianDate(
                row.created_at
            )
    };

    return normalizeLeaveRequest(
        request
    );
}




function getDocsRankForSlot(number) {
    const slot = Number(number);
    if (slot === 0) return { name: "RESPONSABIL GUVERNAMENTALE", level: 15 };
    if (slot === 1) return { name: "CHESTOR GENERAL", level: 14 };
    if (slot === 2) return { name: "CHESTOR PRINCIPAL", level: 13 };
    if (slot === 3) return { name: "CHESTOR SECUNDAR", level: 12 };
    if (slot >= 4 && slot <= 5) return { name: "COMISAR ȘEF", level: 11 };
    if (slot >= 6 && slot <= 7) return { name: "COMISAR", level: 10 };
    if (slot >= 8 && slot <= 9) return { name: "SUB COMISAR", level: 9 };
    if (slot >= 11 && slot <= 14) return { name: "INSPECTOR PRINCIPAL", level: 8 };
    if (slot >= 100 && slot <= 103) return { name: "INSPECTOR", level: 7 };
    if (slot >= 150 && slot <= 152) return { name: "SUB INSPECTOR", level: 6 };
    if (slot >= 200 && slot <= 205) return { name: "AGENT ȘEF PRINCIPAL", level: 5 };
    if (slot >= 300 && slot <= 308) return { name: "AGENT ȘEF ADJUNCT", level: 4 };
    if (slot >= 400 && slot <= 409) return { name: "AGENT PRINCIPAL", level: 3 };
    if (slot >= 500 && slot <= 515) return { name: "AGENT", level: 2 };
    if (slot >= 600 && slot <= 660) return { name: "CADET", level: 1 };
    return { name: "", level: -1 };
}

function getAllPoliceDocsCallsigns() {
    const values = [0,1,2,3];
    const ranges = [[4,5],[6,7],[8,9],[11,14],[100,103],[150,152],[200,205],[300,308],[400,409],[500,515],[600,660]];
    for (const [a,b] of ranges) for (let n=a;n<=b;n++) values.push(n);
    return values;
}

const POLICE_DOCS_RANK_NAMES = new Set(
    DIICOT_ROLES.map(role => String(role.name || "").toUpperCase())
);

const GOVERNMENT_RESPONSIBLE_IDS = new Set([
    "927528327156203560",
    "803998303230230538"
]);

function isPoliceDocsRow(row) {
    if (!row || !normalizePoliceCallsign(row.callsign)) return false;

    const rank = String(row.rank || "").trim().toUpperCase();
    return POLICE_DOCS_RANK_NAMES.has(rank) && !rank.includes("DIICOT");
}

function normalizePoliceCallsign(value) {
    const raw = String(value || "").trim().toUpperCase();
    const match = raw.match(/(?:\[)?(?:D-|P-)?(\d{1,3})(?:\])?/);
    if (!match) return null;
    const number = Number(match[1]);
    const rank = getDocsRankForSlot(number);
    if (rank.level < 0) return null;
    return { number, callsign: String(number).padStart(3, "0"), rank };
}

function mapDocsRow(row) {

    if (!row) {
        return null;
    }

    return {
        id:
            row.id,

        discordId:
            row.discord_id,

        rank:
            row.rank,

        rankLevel:
            Number(
                row.rank_level ||
                0
            ),

        fullName:
            row.full_name,

        internalId:
            row.internal_id,

        callsign:
            row.callsign,

        active:
            Boolean(
                row.active
            ),

        lastPromotion:
            row.last_promotion,

        joinedAt:
            row.joined_at,

        certFtp:
            Boolean(
                row.cert_ftp
            ),

        certRadio:
            Boolean(
                row.cert_radio
            ),

        certAc: Boolean(row.cert_ac),
        certHs: Boolean(row.cert_hs),
        certAir: Boolean(row.cert_air),
        certMoto: Boolean(row.cert_moto),

        roles:
            row.roles,

        notes:
            row.notes,

        penaltyPoints:
            Number(
                row.penalty_points ||
                0
            ),

        discord:
            row.discord,

        position:
            Number(
                row.position ||
                0
            ),

        updatedAt:
            row.updated_at,

        updatedByName:
            row.updated_by_name
    };
}


// ======================================================
// DISCORD — ROLURI CONCEDIU / ÎNVOIRE
// ======================================================

function getLeaveDiscordRoleId(type) {
    return String(type || "").toUpperCase() === "VACATION"
        ? VACATION_DISCORD_ROLE_ID
        : String(type || "").toUpperCase() === "MEETING_EXCUSE"
            ? MEETING_EXCUSE_DISCORD_ROLE_ID
            : null;
}

async function setDiscordMemberRole(userId, roleId, enabled) {
    if (!BOT_TOKEN || !GUILD_ID || !userId || !roleId) {
        throw new Error("Discord nu este configurat complet pentru rolurile de concediu/învoire.");
    }

    const url = `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${String(userId)}/roles/${String(roleId)}`;
    const config = { headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" }, timeout: 12000 };

    if (enabled) {
        await axios.put(url, {}, config);
    } else {
        await axios.delete(url, config);
    }

    // Membrul s-a schimbat; nu păstrăm în cache rolurile vechi.
    discordMemberCache.delete(String(userId));
}

function getLeaveExpirationMs(request) {
    if (!request) return 0;

    if (request.type === "MEETING_EXCUSE") {
        const approvedAt = new Date(request.decided_at || request.created_at || 0).getTime();
        return Number.isFinite(approvedAt) ? approvedAt + MEETING_EXCUSE_DURATION_MS : 0;
    }

    if (request.type === "VACATION") {
        // Rolul rămâne inclusiv în ultima zi de concediu.
        // Folosim miezul nopții zilei următoare; o diferență DST de o oră nu poate
        // elimina rolul înainte de sfârșitul datei calendaristice din România.
        const match = String(request.end_date || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
        if (!match) return 0;
        const nextDayUtc = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]) + 1, 0, 0, 0);
        return nextDayUtc;
    }

    return 0;
}

function isLeaveRequestActiveNow(request, now = Date.now()) {
    if (!request || request.status !== "APPROVED") return false;
    const expiresAt = getLeaveExpirationMs(request);
    return expiresAt > now;
}

async function syncApprovedLeaveDiscordRoles() {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !BOT_TOKEN || !GUILD_ID) return;

    try {
        const { data, error } = await supabase
            .from("leave_requests")
            .select("id, author_id, type, status, end_date, decided_at, created_at")
            .eq("status", "APPROVED")
            .in("type", ["VACATION", "MEETING_EXCUSE"]);

        if (error) throw error;

        const now = Date.now();
        const grouped = new Map();

        for (const row of data || []) {
            const key = `${row.author_id}:${row.type}`;
            if (!grouped.has(key)) grouped.set(key, []);
            grouped.get(key).push(row);
        }

        for (const [key, requests] of grouped.entries()) {
            const [userId, type] = key.split(":");
            const roleId = getLeaveDiscordRoleId(type);
            if (!roleId) continue;

            const shouldHaveRole = requests.some(row => isLeaveRequestActiveNow(row, now));

            try {
                await setDiscordMemberRole(userId, roleId, shouldHaveRole);
            } catch (error) {
                // 404 = membrul nu mai este pe server; nu blocăm restul sincronizării.
                console.error(`[Leave Role Sync] ${userId} / ${type}:`, error?.response?.data || error?.message || error);
            }
        }
    } catch (error) {
        console.error("Leave Role Sync Error:", error?.message || error);
    }
}

function initLeaveRoleScheduler() {
    // Sincronizare la pornire + periodic. Astfel funcționează și după restart/deploy Render.
    setTimeout(() => syncApprovedLeaveDiscordRoles(), 5000);
    const timer = setInterval(() => syncApprovedLeaveDiscordRoles(), LEAVE_ROLE_SYNC_INTERVAL_MS);
    if (typeof timer.unref === "function") timer.unref();
}

// ======================================================
// CONCEDII HELPERS
// ======================================================

async function getLeaveResetAt() {
    const { data, error } = await supabase
        .from("leave_allowance_resets")
        .select("reset_at")
        .eq("id", "global")
        .maybeSingle();

    if (error) {
        // Dacă tabela nu a fost creată încă, lăsăm eroarea să ajungă în log/API.
        throw error;
    }

    return data?.reset_at || null;
}

async function getLeaveUsage(userId) {
    const resetAt = await getLeaveResetAt();

    let query = supabase
        .from("leave_requests")
        .select("type, days")
        .eq("author_id", String(userId))
        .eq("status", "APPROVED");

    // Cererile aprobate înainte de ultima resetare rămân în istoric,
    // dar nu mai consumă din noul sold de 14 zile / 2 învoiri.
    if (resetAt) {
        query = query.gte("created_at", resetAt);
    }

    const { data, error } = await query;

    if (error) {
        throw error;
    }

    const approved = data || [];

    const vacationUsed = approved
        .filter(request => request.type === "VACATION")
        .reduce((total, request) => total + Number(request.days || 0), 0);

    const meetingExcusesUsed = approved
        .filter(request => request.type === "MEETING_EXCUSE")
        .length;

    return {
        vacationUsed,
        vacationRemaining: Math.max(0, VACATION_DAYS_LIMIT - vacationUsed),
        meetingExcusesUsed,
        meetingExcusesRemaining: Math.max(0, MEETING_EXCUSES_LIMIT - meetingExcusesUsed),
        lastResetAt: resetAt
    };
}

function normalizeLeaveRequest(
    request
) {

    let statusLabel =
        "ANULAT";

    if (
        request.status ===
        "PENDING"
    ) {

        statusLabel =
            "ÎN AȘTEPTARE";
    }

    if (
        request.status ===
        "APPROVED"
    ) {

        statusLabel =
            "APROBAT";
    }

    if (
        request.status ===
        "REJECTED"
    ) {

        statusLabel =
            "RESPINS";
    }

    return {
        ...request,

        typeLabel:
            request.type ===
            "VACATION"

                ? "CONCEDIU"

                : "ÎNVOIRE ȘEDINȚĂ",

        statusLabel
    };
}


// ======================================================
// BLACKLIST HELPERS
// ======================================================

async function updateBlacklistStatuses() {

    const now =
        new Date()
            .toISOString();

    const {
        error
    } =
        await supabase
            .from(
                "blacklist"
            )
            .update({
                status:
                    "INACTIVE",

                deactivated_reason:
                    "EXPIRED",

                deactivated_at:
                    now,

                updated_at:
                    now
            })
            .eq(
                "status",
                "ACTIVE"
            )
            .eq(
                "duration_type",
                "TEMPORARY"
            )
            .not(
                "expires_at",
                "is",
                null
            )
            .lte(
                "expires_at",
                now
            );

    if (error) {

        console.error(
            "Blacklist expiry update:",
            error.message
        );
    }
}


async function getDiscordUserBasic(
    discordId
) {

    if (!BOT_TOKEN) {
        return null;
    }

    try {

        const response =
            await axios.get(

                `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${discordId}`,

                {
                    headers: {

                        Authorization:
                            `Bot ${BOT_TOKEN}`
                    }
                }
            );

        const member =
            response.data;

        return {
            id:
                discordId,

            username:
                member.user?.username ||
                null,

            displayName:
                member.nick ||
                member.user?.global_name ||
                member.user?.username ||
                null,

            avatar:
                member.user?.avatar

                    ? `https://cdn.discordapp.com/avatars/${discordId}/${member.user.avatar}.png?size=128`

                    : "https://cdn.discordapp.com/embed/avatars/0.png"
        };

    }

    catch (error) {

        if (
            error.response?.status !==
            404
        ) {

            console.error(
                "Discord member error:",
                error.response?.data ||
                error.message
            );
        }

        return null;
    }
}


// ======================================================
// AUTH MIDDLEWARE
// ======================================================

function requireAuth(
    req,
    res,
    next
) {

    if (
        !req.session?.user
    ) {

        return res
            .status(401)
            .json({
                error:
                    "Trebuie să fii autentificat."
            });
    }

    next();
}


// Acces complet: COMISAR ȘEF+ și cele două persoane desemnate.
const POLICE_FULL_ACCESS_IDS = new Set([
    "803998303230230538",
    "927528327156203560",
    "1315733546312142921"
]);

function hasPoliceFullAccess(user) {
    if (!user) return false;
    return Number(user.rankLevel || 0) >= 11 ||
        POLICE_FULL_ACCESS_IDS.has(String(user.id || ""));
}

function hasDocsEditAccess(user) {
    return hasPoliceFullAccess(user);
}

function requireDocsEditor(req, res, next) {
    if (!req.session?.user) {
        return res.status(401).json({ error: "Trebuie să fii autentificat." });
    }
    if (!hasDocsEditAccess(req.session.user)) {
        return res.status(403).json({ error: "Nu ai acces la editarea DOCS." });
    }
    next();
}

function requireAdmin(
    req,
    res,
    next
) {

    if (
        !req.session?.user
    ) {

        return res
            .status(401)
            .json({
                error:
                    "Trebuie să fii autentificat."
            });
    }

    if (!hasPoliceFullAccess(req.session.user)) {

        return res
            .status(403)
            .json({
                error:
                    "Nu ai acces la această secțiune."
            });
    }

    next();
}


function requireSanctionManager(
    req,
    res,
    next
) {

    if (
        !req.session?.user
    ) {
        return res
            .status(401)
            .json({
                error:
                    "Trebuie să fii autentificat."
            });
    }

    // SUB COMISAR+ (rankLevel 7+) poate vedea, aplica și retrage sancțiuni.
    if (
        !hasPoliceFullAccess(req.session.user) &&
        Number(
            req.session.user.rankLevel ||
            0
        ) < 7
    ) {
        return res
            .status(403)
            .json({
                error:
                    "Doar SUB COMISAR+ poate gestiona sancțiunile."
            });
    }

    next();
}


function hasTesterAccess(
    user
) {

    if (!user) {
        return false;
    }

    const roles =
        Array.isArray(
            user.roles
        )
            ? user.roles.map(String)
            : [];

    return (
        hasPoliceFullAccess(user) ||
        roles.includes(
            TESTER_DIICOT_ROLE_ID
        )
    );
}


function requireTester(
    req,
    res,
    next
) {

    if (
        !req.session?.user
    ) {

        return res
            .status(401)
            .json({
                error:
                    "Trebuie să fii autentificat."
            });
    }

    if (
        !hasTesterAccess(
            req.session.user
        )
    ) {

        return res
            .status(403)
            .json({
                error:
                    "Doar Tester sau Conducerea Poliției poate accesa testele."
            });
    }

    next();
}



// ======================================================
// PAGINI
// ======================================================

app.get(
    "/",

    (
        req,
        res
    ) => {

        res.set(
            "Cache-Control",
            "public, max-age=300, must-revalidate"
        );

        if (process.env.CLOUDFLARE_WORKERS === "1") {
            return res.redirect(302, "/index.html");
        }

        res.sendFile(
            path.join(
                APP_DIR,
                "index.html"
            ),
            {
                maxAge: "5m",
                cacheControl: true,
                lastModified: true
            }
        );
    }
);


app.get(
    "/dashboard",

    (
        req,
        res
    ) => {

        if (
            !req.session?.user
        ) {

            return res.redirect(
                "/"
            );
        }

        res.set(
            "Cache-Control",
            "private, max-age=300, must-revalidate"
        );

        return res.redirect("/dashboard.html");
    }
);


app.get(
    "/style.css",

    (
        req,
        res
    ) => {

        res.set(
            "Cache-Control",
            "public, max-age=86400, must-revalidate"
        );

        if (process.env.CLOUDFLARE_WORKERS === "1") {
            return res.status(404).end();
        }

        res.sendFile(
            path.join(
                APP_DIR,
                "style.css"
            ),
            {
                maxAge: "1d",
                cacheControl: true,
                lastModified: true
            }
        );
    }
);


// ======================================================
// DISCORD LOGIN
// ======================================================

app.get(
    "/auth/discord",

    (
        req,
        res
    ) => {

        const missingDiscordEnv = [
            ["DISCORD_CLIENT_ID", CLIENT_ID],
            ["DISCORD_CLIENT_SECRET", CLIENT_SECRET],
            ["DISCORD_REDIRECT_URI", REDIRECT_URI],
            ["DISCORD_GUILD_ID", GUILD_ID]
        ]
            .filter(([, value]) => !String(value || "").trim())
            .map(([name]) => name);

        if (missingDiscordEnv.length) {
            console.error(
                "[DISCORD CONFIG] Lipsesc variabilele:",
                missingDiscordEnv.join(", ")
            );

            return res
                .status(500)
                .send(
                    `Configurarea Discord este incompletă. Lipsesc: ${missingDiscordEnv.join(", ")}`
                );
        }

        const state =
            crypto
                .randomBytes(24)
                .toString("hex");

        req.session.oauthState =
            state;

        const params =
            new URLSearchParams({

                client_id:
                    CLIENT_ID,

                redirect_uri:
                    REDIRECT_URI,

                response_type:
                    "code",

                scope:
                    "identify guilds guilds.members.read",

                state
            });

        res.redirect(
            "https://discord.com/oauth2/authorize?" +
            params.toString()
        );
    }
);


// ======================================================
// CALLBACK DISCORD
// ======================================================

app.get(
    "/auth/discord/callback",

    async (
        req,
        res
    ) => {

        const {
            code,
            state
        } =
            req.query;

        if (!code) {

            return res.redirect(
                "/?error=no_code"
            );
        }

        if (
            !state ||
            !req.session.oauthState ||
            state !==
            req.session.oauthState
        ) {

            return res.redirect(
                "/?error=invalid_state"
            );
        }

        delete req.session.oauthState;

        try {

            const params =
                new URLSearchParams({

                    client_id:
                        CLIENT_ID,

                    client_secret:
                        CLIENT_SECRET,

                    grant_type:
                        "authorization_code",

                    code,

                    redirect_uri:
                        REDIRECT_URI
                });

            // Cloudflare Workers: folosim fetch nativ pentru OAuth Discord.
            // Axios poate seta Request.cache="default", mod nesuportat de Workers.
            const tokenResponse = await fetch(
                "https://discord.com/api/oauth2/token",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    body: params.toString()
                }
            );

            if (!tokenResponse.ok) {
                const details = await tokenResponse.text();
                throw new Error(`Discord token exchange failed (${tokenResponse.status}): ${details}`);
            }

            const tokenData = await tokenResponse.json();
            const accessToken = tokenData.access_token;

            if (!accessToken) {
                throw new Error("Discord token exchange did not return an access token");
            }

            const userResponse = await fetch(
                "https://discord.com/api/users/@me",
                {
                    headers: {
                        Authorization: `Bearer ${accessToken}`
                    }
                }
            );

            if (!userResponse.ok) {
                const details = await userResponse.text();
                throw new Error(`Discord user request failed (${userResponse.status}): ${details}`);
            }

            const discordUser = await userResponse.json();

            // Apartenența la serverul MAI NU mai este obligatorie pentru login.
            // Orice cont Discord se poate autentifica în HUB pentru aplicații.
            // Dacă utilizatorul este membru MAI, îi citim rolurile și gradul.
            let member = null;
            let roles = [];
            let isGuildMember = false;

            const memberResponse = await fetch(
                `https://discord.com/api/users/@me/guilds/${GUILD_ID}/member`,
                {
                    headers: {
                        Authorization: `Bearer ${accessToken}`
                    }
                }
            );

            if (memberResponse.ok) {
                member = await memberResponse.json();
                isGuildMember = true;
                roles = Array.isArray(member?.roles)
                    ? member.roles.map(String)
                    : [];
            } else if (memberResponse.status !== 404) {
                // 404 = utilizatorul nu este pe serverul MAI; login-ul rămâne valid.
                const details = await memberResponse.text();
                console.warn(
                    `[Discord OAuth] Guild member lookup ${memberResponse.status}: ${details}`
                );
            }

            const rank =
                getHighestDIICOTRole(
                    roles
                );

            let savedProfile =
                null;

            if (
                SUPABASE_URL &&
                SUPABASE_SERVICE_KEY
            ) {

                const {
                    data,
                    error
                } =
                    await supabase
                        .from(
                            "user_profiles"
                        )
                        .select(
                            "*"
                        )
                        .eq(
                            "user_id",
                            discordUser.id
                        )
                        .maybeSingle();

                if (!error) {
                    savedProfile =
                        data;
                }
            }

            req.session.user = {

                id:
                    discordUser.id,

                username:
                    discordUser.username,

                globalName:
                    discordUser.global_name ||
                    discordUser.username,

                displayName:
                    savedProfile?.display_name ||
                    member?.nick ||
                    discordUser.global_name ||
                    discordUser.username,

                avatar:
                    discordUser.avatar,

                roles,

                rank:
                    rank
                        ? rank.name
                        : "CIVIL",

                rankLevel:
                    rank
                        ? rank.level
                        : 0,

                rankRoleId:
                    rank
                        ? rank.id
                        : null,

                guildId:
                    GUILD_ID,

                isGuildMember
            };

            // După autentificarea Discord intrăm direct
            // în Centrul de Comandă.
            res.redirect(
    "/"
);

        }

        catch (error) {

            console.error(
                "Discord OAuth Error:",
                error.response?.data ||
                error.message
            );

            res.redirect(
                "/?error=discord"
            );
        }
    }
);


// ======================================================
// API ME
// ======================================================

app.get(
    "/api/me",

    async (
        req,
        res
    ) => {

        if (
            !req.session?.user
        ) {

            return res
                .status(401)
                .json({
                    loggedIn:
                        false
                });
        }

        /*
         * Refresh LIVE din Discord.
         * Astfel, dacă îi dai cuiva rolul Tester DIICOT după ce s-a logat,
         * site-ul îl vede fără să depindă de rolurile vechi salvate în sesiune.
         */
        if (
            BOT_TOKEN &&
            GUILD_ID &&
            req.session.user.id
        ) {

            try {

                const member =
                    await getDiscordMemberCached(
                        req.session.user.id
                    );

                const roles =
                    Array.isArray(
                        member.roles
                    )
                        ? member.roles.map(String)
                        : [];

                const rank =
                    getHighestDIICOTRole(
                        roles
                    );

                req.session.user.roles =
                    roles;

                req.session.user.rank =
                    rank
                        ? rank.name
                        : "CIVIL";

                req.session.user.rankLevel =
                    rank
                        ? rank.level
                        : 0;

                req.session.user.rankRoleId =
                    rank
                        ? rank.id
                        : null;

                req.session.user.displayName =
                    member.nick ||
                    member.user?.global_name ||
                    member.user?.username ||
                    req.session.user.displayName ||
                    req.session.user.username;

            }
            catch (error) {

                if (
                    isDiscordRateLimited(
                        error
                    )
                ) {
                    console.warn(
                        "[Discord] /api/me este temporar rate-limited; sesiunea existentă rămâne activă."
                    );
                }
                else {
                    console.error(
                        "API ME Discord Refresh Error:",
                        error.response?.data ||
                        error.message
                    );
                }
            }
        }

        const roles =
            Array.isArray(
                req.session.user.roles
            )
                ? req.session.user.roles.map(String)
                : [];

        const isAdmin =
            hasPoliceFullAccess(
                req.session.user
            );

        const isTester =
            roles.includes(
                "1528758226407919637"
            );

        // HUB MAI: detectăm separat gradul din Poliție și gradul din DIICOT.
        // DIICOT_ROLES este lista Poliției (nume istoric păstrat pentru compatibilitate).
        const policeMatch = hubHighestRole(roles, DIICOT_ROLES);
        const diicotMatch = hubHighestRole(roles, HUB_DIICOT_ROLES);
        const policeRank = policeMatch ? policeMatch.name : "";
        const diicotRank = diicotMatch ? diicotMatch.name : "";

        // `rank` rămâne pentru compatibilitate cu dashboard-ul Poliției.
        // Identitatea HUB folosește separat policeRank / diicotRank.
        req.session.user.rank = policeRank || "CIVIL";
        req.session.user.rankLevel = policeMatch ? Number(policeMatch.level || 0) : 0;
        req.session.user.rankRoleId = policeMatch ? policeMatch.id : null;

        res.json({
            loggedIn: true,

            // Date plate pentru HUB (plus obiectul user pentru compatibilitate).
            id: req.session.user.id,
            username: req.session.user.username,
            global_name: req.session.user.globalName || req.session.user.displayName || req.session.user.username,
            displayName: req.session.user.displayName || req.session.user.globalName || req.session.user.username,
            avatar: req.session.user.avatar,
            roles,
            rank: req.session.user.rank || "CIVIL",
            isGuildMember: !!req.session.user.isGuildMember,

            police: !!policeRank,
            isPolice: !!policeRank,
            policeRank,
            diicot: !!diicotRank,
            isDiicot: !!diicotRank,
            diicotRank,
            department: policeRank && diicotRank ? "BOTH" : policeRank ? "POLITIE" : diicotRank ? "DIICOT" : "CIVIL",
            departments: {
                police: policeRank ? { active: true, rank: policeRank } : false,
                diicot: diicotRank ? { active: true, rank: diicotRank } : false
            },
            access: {
                police: !!policeRank,
                diicot: !!diicotRank
            },

            user: req.session.user,

            permissions: {
                admin: isAdmin,
                tester: isTester,
                testManagement: isAdmin || isTester
            }
        });
    }
);


// ======================================================
// PROFILUL MEU
// ======================================================

app.get(
    "/api/profile",

    requireAuth,

    async (
        req,
        res
    ) => {

        try {

            const userId =
                String(
                    req.session.user.id
                );

            let username =
                req.session.user.username;

            let avatar =
                req.session.user.avatar;

            let displayName =
                req.session.user.displayName;

            let discordMember =
                null;

            if (BOT_TOKEN) {

                try {

                    const response =
                        await axios.get(

                            `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                            {
                                headers: {

                                    Authorization:
                                        `Bot ${BOT_TOKEN}`
                                }
                            }
                        );

                    discordMember =
                        response.data;

                    username =
                        discordMember.user?.username ||
                        username;

                    avatar =
                        discordMember.user?.avatar ||
                        avatar;

                    const roles =
                        Array.isArray(
                            discordMember.roles
                        )

                            ? discordMember.roles
                                .map(String)

                            : [];

                    const rank =
                        getHighestDIICOTRole(
                            roles
                        );

                    req.session.user.roles =
                        roles;

                    req.session.user.rank =
                        rank
                            ? rank.name
                            : "MEMBRU POLIȚIE";

                    req.session.user.rankLevel =
                        rank
                            ? rank.level
                            : 0;

                    req.session.user.rankRoleId =
                        rank
                            ? rank.id
                            : null;

                }

                catch (error) {

                    console.error(
                        "Profile Discord Error:",
                        error.response?.data ||
                        error.message
                    );
                }
            }


            // Profilul de bază trebuie să funcționeze chiar dacă Supabase
            // este neconfigurat sau indisponibil temporar.
            let profileRow = null;

            if (supabase) {
                try {
                    const {
                        data,
                        error
                    } =
                        await supabase
                            .from("user_profiles")
                            .select("*")
                            .eq("user_id", userId)
                            .maybeSingle();

                    if (error) throw error;
                    profileRow = data;
                } catch (error) {
                    console.error(
                        "Profile Supabase Fallback:",
                        error.message || error
                    );
                }
            }


            if (
                profileRow?.display_name
            ) {

                displayName =
                    profileRow
                        .display_name;

            }

            else if (
                discordMember
            ) {

                displayName =
                    discordMember.nick ||
                    discordMember.user?.global_name ||
                    username;
            }


            req.session.user.displayName =
                displayName;

            req.session.user.username =
                username;

            req.session.user.avatar =
                avatar;

            let myReports = [];

            try {
                myReports =
                    await listB2Reports(
                        userId
                    );
            } catch (error) {
                console.error(
                    "Profile Reports Fallback:",
                    error.message || error
                );
            }


            const reportsWithImages =
                myReports.filter(
                    report =>
                        Array.isArray(
                            report.images
                        ) &&
                        report.images.length >
                        0
                ).length;


            const sessionRank = {
                id:
                    req.session.user.rankRoleId,

                name:
                    req.session.user.rank || "MEMBRU POLIȚIE",

                level:
                    Number(req.session.user.rankLevel || 0)
            };

            let promotionEligibility = null;

            try {
                promotionEligibility =
                    await buildPromotionEligibility(
                        userId,
                        sessionRank,
                        myReports
                    );
            } catch (error) {
                console.error(
                    "Profile Promotion Fallback:",
                    error.message || error
                );

                promotionEligibility = {
                    tracked: false,
                    meritOnly: sessionRank.level >= 7,
                    currentRank: sessionRank.name,
                    nextRank: null,
                    rankSince: null,
                    daysInRank: 0,
                    requirements: null,
                    progress: {
                        reports: myReports.length,
                        raids: 0,
                        trainings: 0
                    },
                    numericEligible: false,
                    manualCriteria: [
                        "Progresul va fi disponibil după reconectarea serviciului."
                    ]
                };
            }


            res.json({

                success:
                    true,

                profile: {

                    id:
                        userId,

                    username,

                    displayName,

                    // Trimitem URL complet. Dashboard-ul acceptă și hash,
                    // însă URL-ul evită avatarul gol din pagina de profil.
                    avatar:
                        discordMember?.user
                            ? discordMemberAvatar(discordMember.user)
                            : discordMemberAvatar({ id: userId, avatar }),

                    rank:
                        req.session.user.rank,

                    rankLevel:
                        req.session.user.rankLevel,

                    duties:
                        Array.isArray(
                            profileRow?.duties
                        )

                            ? profileRow.duties
                            : [],

                    promotionEligibility,

                    statistics: {

                        totalReports:
                            myReports.length,

                        reportsWithImages,

                        lastActivity:
                            myReports.length

                                ? myReports[0]
                                    .createdAtFormatted

                                : "-"
                    },

                    recentActivity:
                        myReports
                            .slice(
                                0,
                                5
                            )
                            .map(
                                report => ({

                                    id:
                                        report.id,

                                    type:
                                        report.type,

                                    title:
                                        report.title,

                                    createdAtFormatted:
                                        report
                                            .createdAtFormatted
                                })
                            )
                }
            });

        }

        catch (error) {

            console.error(
                "Profile Supabase Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Profilul nu a putut fi încărcat."
                });
        }
    }
);


// ======================================================
// EDITARE PROFILUL MEU
// ======================================================

app.patch(
    "/api/profile",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const userId =
                String(
                    req.session.user.id
                );


            const nickname =
                String(
                    req.body.nickname ||
                    ""
                ).trim();


            const duties =
                Array.isArray(
                    req.body.duties
                )

                    ? req.body.duties
                        .map(
                            value =>
                                String(
                                    value ||
                                    ""
                                ).trim()
                        )
                        .filter(Boolean)

                    : [];


            if (
                nickname.length < 2 ||
                nickname.length > 32
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Numele trebuie să aibă între 2 și 32 de caractere."
                    });
            }


            if (
                duties.length > 8
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Poți avea maximum 8 atribuții."
                    });
            }


            if (
                duties.some(
                    duty =>
                        duty.length < 2 ||
                        duty.length > 80
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Fiecare atribuție trebuie să aibă între 2 și 80 de caractere."
                    });
            }


            const {
                error:
                    profileError
            } =
                await supabase
                    .from(
                        "user_profiles"
                    )
                    .upsert(
                        {
                            user_id:
                                userId,

                            display_name:
                                nickname,

                            duties,

                            updated_at:
                                new Date()
                                    .toISOString()
                        },
                        {
                            onConflict:
                                "user_id"
                        }
                    );


            if (profileError) {

                throw profileError;
            }


            req.session.user.displayName =
                nickname;


            let discordSynced =
                false;


            if (BOT_TOKEN) {

                try {

                    await axios.patch(

                        `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                        {
                            nick:
                                nickname
                        },

                        {
                            headers: {

                                Authorization:
                                    `Bot ${BOT_TOKEN}`,

                                "Content-Type":
                                    "application/json"
                            }
                        }
                    );


                    discordSynced =
                        true;

                }

                catch (error) {

                    console.error(
                        "Nickname Discord Error:",
                        error.response?.data ||
                        error.message
                    );
                }
            }


            res.json({

                success:
                    true,

                discordSynced,

                profile: {

                    displayName:
                        nickname,

                    duties
                }
            });

        }

        catch (error) {

            console.error(
                "Profile Save Supabase Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Profilul nu a putut fi salvat."
                });
        }
    }
);


// ======================================================
// RAPOARTE - BACKBLAZE B2
// Metadata: reports/<discordId>/<reportId>.json
// Imagini:  images/<reportId>/<fisier>
// ======================================================

const DIRECT_UPLOAD_TTL_SECONDS = 15 * 60;
const DIRECT_UPLOAD_MAX_FILES = 5;
const DIRECT_UPLOAD_MAX_FILE_SIZE = 8 * 1024 * 1024;
const DIRECT_UPLOAD_ALLOWED_TYPES = new Set([
    "image/jpeg",
    "image/png",
    "image/webp"
]);

function getDirectUploadTokenSecret() {
    return String(
        process.env.SESSION_SECRET ||
        B2_APPLICATION_KEY ||
        "change-this-secret"
    );
}

function signDirectUploadManifest(payload) {
    const encoded = Buffer
        .from(JSON.stringify(payload), "utf8")
        .toString("base64url");

    const signature = crypto
        .createHmac("sha256", getDirectUploadTokenSecret())
        .update(encoded)
        .digest("base64url");

    return `${encoded}.${signature}`;
}

function verifyDirectUploadManifest(token, userId) {
    const [encoded, signature, ...extra] = String(token || "").split(".");

    if (!encoded || !signature || extra.length) {
        throw new Error("Manifestul de upload este invalid.");
    }

    const expected = crypto
        .createHmac("sha256", getDirectUploadTokenSecret())
        .update(encoded)
        .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        throw new Error("Manifestul de upload nu este valid.");
    }

    const payload = JSON.parse(
        Buffer.from(encoded, "base64url").toString("utf8")
    );

    if (String(payload.userId || "") !== String(userId || "")) {
        throw new Error("Manifestul de upload aparține altui utilizator.");
    }

    if (!payload.exp || Date.now() > Number(payload.exp)) {
        throw new Error("Linkurile de upload au expirat. Încearcă din nou.");
    }

    if (!/^[0-9a-f-]{36}$/i.test(String(payload.reportId || ""))) {
        throw new Error("ID-ul raportului din manifest este invalid.");
    }

    const images = Array.isArray(payload.images) ? payload.images : [];

    if (images.length > DIRECT_UPLOAD_MAX_FILES) {
        throw new Error("Manifestul conține prea multe imagini.");
    }

    for (const image of images) {
        const key = String(image?.key || "");
        const expectedPrefix = `images/${payload.reportId}/`;

        if (
            !key.startsWith(expectedPrefix) ||
            key.includes("..") ||
            !DIRECT_UPLOAD_ALLOWED_TYPES.has(String(image?.contentType || "")) ||
            Number(image?.size || 0) < 1 ||
            Number(image?.size || 0) > DIRECT_UPLOAD_MAX_FILE_SIZE
        ) {
            throw new Error("Manifestul conține o imagine invalidă.");
        }
    }

    return payload;
}

// Token scurt pentru uploadul unei singure imagini prin același Worker.
// Astfel browserul NU mai face PUT direct către Backblaze și nu mai depinde de CORS B2.
function signReportImageProxyToken(payload) {
    const encoded = Buffer
        .from(JSON.stringify(payload), "utf8")
        .toString("base64url");

    const signature = crypto
        .createHmac("sha256", getDirectUploadTokenSecret())
        .update(encoded)
        .digest("base64url");

    return `${encoded}.${signature}`;
}

function verifyReportImageProxyToken(token, userId) {
    const [encoded, signature, ...extra] = String(token || "").split(".");

    if (!encoded || !signature || extra.length) {
        throw new Error("Tokenul imaginii este invalid.");
    }

    const expected = crypto
        .createHmac("sha256", getDirectUploadTokenSecret())
        .update(encoded)
        .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        throw new Error("Tokenul imaginii nu este valid.");
    }

    const payload = JSON.parse(
        Buffer.from(encoded, "base64url").toString("utf8")
    );

    if (String(payload.userId || "") !== String(userId || "")) {
        throw new Error("Tokenul imaginii aparține altui utilizator.");
    }

    if (!payload.exp || Date.now() > Number(payload.exp)) {
        throw new Error("Tokenul imaginii a expirat.");
    }

    const key = String(payload.key || "");
    const contentType = String(payload.contentType || "");
    const size = Number(payload.size || 0);

    if (
        !key.startsWith("images/") ||
        key.includes("..") ||
        !DIRECT_UPLOAD_ALLOWED_TYPES.has(contentType) ||
        !Number.isFinite(size) ||
        size < 1 ||
        size > DIRECT_UPLOAD_MAX_FILE_SIZE
    ) {
        throw new Error("Datele imaginii sunt invalide.");
    }

    return payload;
}

// Upload same-origin: Browser -> Worker -> Backblaze.
// Fișierul este trimis individual (max 8 MB), apoi Worker-ul îl pune în bucketul privat.
app.put(
    "/api/report-image-upload",
    requireAuth,
    express.raw({
        type: ["image/jpeg", "image/png", "image/webp"],
        limit: DIRECT_UPLOAD_MAX_FILE_SIZE
    }),
    async (req, res) => {
        if (!ensureB2(res)) return;

        let payload;

        try {
            payload = verifyReportImageProxyToken(
                req.query?.token,
                req.session.user.id
            );
        } catch (error) {
            return res.status(400).json({
                error: error.message || "Token upload invalid."
            });
        }

        const body = req.body;

        if (!Buffer.isBuffer(body) || body.length < 1) {
            return res.status(400).json({
                error: "Imaginea nu a fost primită."
            });
        }

        if (body.length !== Number(payload.size)) {
            return res.status(400).json({
                error: "Dimensiunea imaginii nu corespunde."
            });
        }

        const requestType = String(req.get("content-type") || "")
            .split(";")[0]
            .trim()
            .toLowerCase();

        if (requestType !== String(payload.contentType).toLowerCase()) {
            return res.status(400).json({
                error: "Tipul imaginii nu corespunde."
            });
        }

        try {
            await b2.send(
                new PutObjectCommand({
                    Bucket: B2_BUCKET,
                    Key: payload.key,
                    Body: body,
                    ContentType: payload.contentType,
                    CacheControl: "private, max-age=3600"
                })
            );

            return res.json({
                success: true,
                key: payload.key
            });
        } catch (error) {
            console.error("B2 image proxy upload error:", error);
            return res.status(502).json({
                error: "Imaginea nu a putut fi salvată în Backblaze B2."
            });
        }
    }
);

// Browserul cere URL-uri de upload same-origin, apoi trimite fiecare poză
// prin Worker către B2. Nu este necesar CORS pe bucketul Backblaze.
app.post(
    "/api/report-upload-urls",
    requireAuth,
    async (req, res) => {
        if (!ensureB2(res)) {
            return;
        }

        // IMPORTANT:
        // Nu configurăm bucket CORS în timpul requestului pe Cloudflare Workers.
        // PutBucketCors este o operație de administrare și poate bloca runtime-ul
        // Workers ("code had hung and would never generate a response").
        // Pe Node/Render păstrăm comportamentul existent.
        if (process.env.CLOUDFLARE_WORKERS !== "1") {
            try {
                await ensureB2DirectUploadCors();
            } catch (corsError) {
                console.error("B2 direct upload CORS error:", corsError?.message || corsError);
                return res.status(502).json({ error: "Uploadul direct B2 nu a putut fi configurat (CORS)." });
            }
        }

        const files = Array.isArray(req.body?.files) ? req.body.files : [];

        if (files.length > DIRECT_UPLOAD_MAX_FILES) {
            return res.status(400).json({
                error: "Poți încărca maximum 5 imagini."
            });
        }

        for (const file of files) {
            const contentType = String(file?.type || "");
            const size = Number(file?.size || 0);

            if (!DIRECT_UPLOAD_ALLOWED_TYPES.has(contentType)) {
                return res.status(400).json({
                    error: "Sunt acceptate doar imagini JPG, PNG și WEBP."
                });
            }

            if (!Number.isFinite(size) || size < 1 || size > DIRECT_UPLOAD_MAX_FILE_SIZE) {
                return res.status(400).json({
                    error: "Fiecare imagine trebuie să aibă maximum 8 MB."
                });
            }
        }

        const reportId = crypto.randomUUID();
        const images = [];
        const uploads = [];

        for (const file of files) {
            const contentType = String(file.type);
            const extension = getExtensionFromMime(contentType);
            const filename = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}.${extension}`;
            const key = `images/${reportId}/${filename}`;

            const imageUploadToken = signReportImageProxyToken({
                userId: String(req.session.user.id),
                key,
                contentType,
                size: Number(file.size),
                exp: Date.now() + DIRECT_UPLOAD_TTL_SECONDS * 1000
            });

            const uploadUrl =
                `/api/report-image-upload?token=${encodeURIComponent(imageUploadToken)}`;

            images.push({
                filename,
                key,
                path: key,
                provider: "b2",
                contentType,
                size: Number(file.size)
            });

            uploads.push({
                key,
                uploadUrl,
                contentType
            });
        }

        const uploadManifestToken = signDirectUploadManifest({
            userId: String(req.session.user.id),
            reportId,
            images,
            exp: Date.now() + DIRECT_UPLOAD_TTL_SECONDS * 1000
        });

        return res.json({
            reportId,
            uploads,
            uploadManifestToken
        });
    }
);


// ======================================================
// IMAGINI RAPOARTE
// ======================================================
// Nu mai există rută proxy /api/report-files/*.
// URL-urile semnate sunt generate la răspunsul API, iar browserul
// descarcă imaginile direct din Backblaze B2.


// ======================================================
// RAPOARTE — MEMBRI ELIGIBILI PENTRU RAZII / ANTRENAMENTE
// ======================================================

app.get(
    "/api/report-organizers",
    requireAuth,
    async (req, res) => {
        if (!BOT_TOKEN || !GUILD_ID) {
            return res.status(503).json({
                error: "Botul Discord nu este configurat complet."
            });
        }

        try {
            const members =
                await getGuildMembersCached();

            const currentUserId =
                String(req.session.user.id);

            const result = {
                DIICOT: [],
                POLITIE: []
            };

            for (const member of members) {
                const user = member.user || {};

                if (
                    !user.id ||
                    String(user.id) === currentUserId ||
                    user.bot
                ) {
                    continue;
                }

                const roles =
                    Array.isArray(member.roles)
                        ? member.roles.map(String)
                        : [];

                for (const department of ["DIICOT", "POLITIE"]) {
                    const rank =
                        getReportOrganizerRank(
                            roles,
                            department
                        );

                    if (!rank) {
                        continue;
                    }

                    result[department].push({
                        id: String(user.id),
                        username:
                            user.username ||
                            "Necunoscut",
                        displayName:
                            member.nick ||
                            user.global_name ||
                            user.username ||
                            "Necunoscut",
                        avatar:
                            discordMemberAvatar(user),
                        department,
                        rank:
                            rank.name,
                        rankRoleId:
                            rank.id,
                        weight:
                            Number(rank.weight || 0)
                    });
                }
            }

            for (const department of ["DIICOT", "POLITIE"]) {
                result[department].sort((a, b) => {
                    if (b.weight !== a.weight) {
                        return b.weight - a.weight;
                    }

                    return String(a.displayName)
                        .localeCompare(
                            String(b.displayName),
                            "ro"
                        );
                });
            }

            return res.json(result);

        } catch (error) {
            console.error(
                "Report Organizers Discord Error:",
                error.response?.data ||
                error.message
            );

            return res.status(500).json({
                error:
                    "Lista organizatorilor nu a putut fi încărcată din Discord."
            });
        }
    }
);


// ======================================================
// DISCORD - NOTIFICARE RAZIE / ANTRENAMENT
// ======================================================

async function sendOperationalReportToDiscord(report) {
    if (!BOT_TOKEN) {
        throw new Error("DISCORD_BOT_TOKEN nu este configurat.");
    }

    const channelId =
        report.type === "RAZIE"
            ? RAID_REPORT_CHANNEL_ID
            : report.type === "ANTRENAMENT"
                ? TRAINING_REPORT_CHANNEL_ID
                : null;

    if (!channelId) {
        return { sent: false, skipped: true };
    }

    const typeLabel = report.type === "RAZIE" ? "RAZIE" : "ANTRENAMENT";
    const color = report.type === "RAZIE" ? 0xD9A11E : 0x3498DB;
    const authorMention = report.authorId
        ? `<@${report.authorId}>`
        : (report.authorName || "Necunoscut");

    const coOrganizer = report.coOrganizer || null;
    const secondOrganizer = coOrganizer?.id
        ? `<@${coOrganizer.id}>\n${coOrganizer.rank || "-"} • ${coOrganizer.department || "-"}`
        : "Neselectat";

    const reportImages = Array.isArray(report.images)
        ? report.images.slice(0, 5)
        : [];

    // Discord descarcă imaginile direct din Backblaze folosind URL-uri GET semnate.
    // Render trimite către Discord doar JSON-ul cu URL-urile, nu fișierele.
    const imageEmbeds = [];

    for (const image of reportImages) {
        const key = getB2ImageKey(image);
        if (!key) continue;

        const url = await getB2DirectSignedUrl(key);
        if (!url) continue;

        imageEmbeds.push({
            color,
            image: { url }
        });
    }

    const mainEmbed = {
        title: report.type === "RAZIE"
            ? "📋 RAZIE POSTATĂ"
            : "🎯 ANTRENAMENT POSTAT",
        description: `**${String(report.title || "Raport operațional").slice(0, 200)}**`,
        color,
        fields: [
            { name: "TIP ACTIVITATE", value: typeLabel, inline: true },
            {
                name: "DOVEZI",
                value: `${reportImages.length} ${reportImages.length === 1 ? "imagine" : "imagini"}`,
                inline: true
            },
            {
                name: "ORGANIZATOR 1",
                value: `${authorMention}\n${report.authorRank || "Membru Poliție"}`,
                inline: false
            },
            { name: "ORGANIZATOR 2", value: secondOrganizer, inline: false }
        ],
        footer: { text: "Poliția Română • Centru de Comandă • Rush România" },
        timestamp: report.createdAt || new Date().toISOString()
    };

    const payload = {
        embeds: [mainEmbed, ...imageEmbeds],
        allowed_mentions: { parse: [] }
    };

    const response = await axios.post(
        `https://discord.com/api/v10/channels/${channelId}/messages`,
        payload,
        {
            headers: {
                Authorization: `Bot ${BOT_TOKEN}`,
                "Content-Type": "application/json"
            }
        }
    );

    return {
        sent: true,
        skipped: false,
        channelId,
        imageCount: imageEmbeds.length,
        messageId: response.data?.id || null
    };
}


// ======================================================
// RAPOARTE - POSTARE
// ======================================================

// ======================================================
// POLICE OVERVIEW — DISCORD AMENZI + JAIL
// Reads only the two configured log channels and deduplicates paired logs.
// ======================================================
function discordLogText(message = {}) {
    const parts = [];
    if (message.content) parts.push(String(message.content));
    for (const embed of (Array.isArray(message.embeds) ? message.embeds : [])) {
        if (embed.title) parts.push(String(embed.title));
        if (embed.description) parts.push(String(embed.description));
        for (const field of (Array.isArray(embed.fields) ? embed.fields : [])) {
            if (field.name) parts.push(String(field.name));
            if (field.value) parts.push(String(field.value));
        }
    }
    return parts.join("\
").trim();
}

function bucharestDayKey(value) {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return "";
    const parts = new Intl.DateTimeFormat("en-CA", {
        timeZone: POLICE_LOG_TIMEZONE, year: "numeric", month: "2-digit", day: "2-digit"
    }).formatToParts(d);
    const get = type => parts.find(p => p.type === type)?.value || "";
    return `${get("year")}-${get("month")}-${get("day")}`;
}

function moneyNumber(raw) {
    const digits = String(raw || "").replace(/[^0-9]/g, "");
    return Number(digits || 0);
}

async function fetchDiscordChannelMessages(channelId, maxPages = 5) {
    const all = [];
    let before = null;
    for (let page = 0; page < maxPages; page += 1) {
        const response = await axios.get(`https://discord.com/api/v10/channels/${channelId}/messages`, {
            params: { limit: 100, ...(before ? { before } : {}) },
            headers: { Authorization: `Bot ${BOT_TOKEN}` },
            timeout: 12000
        });
        const batch = Array.isArray(response.data) ? response.data : [];
        all.push(...batch);
        if (batch.length < 100) break;
        before = batch[batch.length - 1]?.id;
        if (!before) break;
        const oldest = batch[batch.length - 1]?.timestamp;
        const today = bucharestDayKey(new Date());
        if (oldest && bucharestDayKey(oldest) < today) break;
    }
    return all;
}

function parseFineLog(message) {
    const text = discordLogText(message);
    // Ignore the paired "a contribuit la reward" entry. Count only the actual fine.
    if (!/i-a\s+dat\s+amenda/i.test(text)) return null;
    const amountMatch = text.match(/amenda\s+(?:in|în)\s+valoare\s+de\s+([0-9.,]+)\s*\$/i);
    const officerMatch = text.match(/^\s*\[([^\]]+)\]\s*([^\n]+?)\s*\([^)]*\)\s+i-a\s+dat\s+amenda/i);
    const targetMatch = text.match(/\$\s+lui\s+([^\n.]+?)(?:\s*\([^)]*\))?\s*(?:\.|Motiv:|$)/i);
    return {
        id: String(message.id || ""),
        kind: "fine",
        timestamp: message.timestamp || message.edited_timestamp || null,
        amount: moneyNumber(amountMatch?.[1]),
        officer: officerMatch ? `[${officerMatch[1]}] ${officerMatch[2].trim()}` : "Agent necunoscut",
        target: targetMatch?.[1]?.trim() || "Persoană sancționată",
        text
    };
}

function parseJailLog(message) {
    const text = discordLogText(message);
    // Bail logs are deliberately excluded.
    if (/platit\s+cautiune|plătit\s+cauțiune/i.test(text)) return null;
    if (!/l-a\s+inchis\s+pe|l-a\s+închis\s+pe/i.test(text)) return null;
    const minutesMatch = text.match(/pentru\s+(\d+)\s+minute/i);
    const officerMatch = text.match(/^\s*\[([^\]]+)\]\s*([^\n]+?)\s*\([^)]*\)\s+l-a/i);
    const targetMatch = text.match(/l-a\s+(?:inchis|închis)\s+pe\s+([^\n]+?)\s*\([^)]*\)\s+pentru/i);
    return {
        id: String(message.id || ""),
        kind: "jail",
        timestamp: message.timestamp || message.edited_timestamp || null,
        minutes: Number(minutesMatch?.[1] || 0),
        officer: officerMatch ? `[${officerMatch[1]}] ${officerMatch[2].trim()}` : "Agent necunoscut",
        target: targetMatch?.[1]?.trim() || "Persoană încarcerată",
        text
    };
}

app.get("/api/police-log-overview", requireAuth, async (req, res) => {
    try {
        if (policeLogOverviewCache.data && policeLogOverviewCache.expiresAt > Date.now()) {
            return res.json(policeLogOverviewCache.data);
        }
        if (!BOT_TOKEN) return res.status(503).json({ error: "DISCORD_BOT_TOKEN nu este configurat." });

        const [fineMessages, jailMessages] = await Promise.all([
            fetchDiscordChannelMessages(POLICE_FINE_LOG_CHANNEL_ID),
            fetchDiscordChannelMessages(POLICE_JAIL_LOG_CHANNEL_ID)
        ]);
        const today = bucharestDayKey(new Date());
        const fines = fineMessages.map(parseFineLog).filter(Boolean).filter(x => bucharestDayKey(x.timestamp) === today);
        const jails = jailMessages.map(parseJailLog).filter(Boolean).filter(x => bucharestDayKey(x.timestamp) === today);
        const recent = [...fines, ...jails]
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 12);

        const payload = {
            date: today,
            timezone: POLICE_LOG_TIMEZONE,
            stats: {
                fines: fines.length,
                fineValue: fines.reduce((sum, x) => sum + Number(x.amount || 0), 0),
                jailed: jails.length,
                jailMinutes: jails.reduce((sum, x) => sum + Number(x.minutes || 0), 0)
            },
            recent
        };
        policeLogOverviewCache = { data: payload, expiresAt: Date.now() + POLICE_LOG_CACHE_TTL_MS };
        res.json(payload);
    } catch (error) {
        console.error("Police Log Overview Error:", error?.response?.data || error?.message || error);
        res.status(502).json({ error: "Nu am putut citi logurile Discord. Verifică accesul botului la canalele Amenzi și Jail." });
    }
});

app.post(
    "/api/reports",
    requireAuth,
    reportUploadSlotGuard,
    async (req, res) => {
        if (!ensureB2(res)) {
            return;
        }

        let uploadManifest;

        try {
            uploadManifest = verifyDirectUploadManifest(
                req.body.uploadManifestToken,
                req.session.user.id
            );
        }
        catch (error) {
            return res.status(400).json({
                error: error.message || "Manifestul de upload este invalid."
            });
        }

        const uploadedImages = Array.isArray(uploadManifest.images)
            ? uploadManifest.images.map(image => ({
                filename: image.filename,
                key: image.key,
                path: image.key,
                provider: "b2"
            }))
            : [];

        const type =
            String(
                req.body.type ||
                ""
            ).trim();

        const title =
            String(
                req.body.title ||
                ""
            ).trim();

        const coOrganizerId =
            String(
                req.body.coOrganizerId ||
                ""
            ).trim();

        const coOrganizerDepartment =
            String(
                req.body.coOrganizerDepartment ||
                ""
            )
                .trim()
                .toUpperCase();

        const rawDetails =
            req.body.details && typeof req.body.details === "object"
                ? req.body.details
                : {};

        const cleanDetail = (key, max = 1500) =>
            String(rawDetails[key] || "").trim().slice(0, max);

        let details = null;
        let description = "";

        const allowedTypes = [
            "RAZIE",
            "ANTRENAMENT",
            "DOVADA RAZIE",
            "DOVADA ANTRENAMENT",
            "REGRUPARE",
            "PERCHEZITIE",
            "BULETINE VAMA",
            "OMOLOGARI",
            "SANCTIUNI"
        ];

        if (!allowedTypes.includes(type)) {
            return res.status(400).json({
                error:
                    "Tipul raportului nu este valid."
            });
        }

        if (type === "BULETINE VAMA") {
            details = {
                holderName: cleanDetail("holderName", 120),
                cnp: cleanDetail("cnp", 30),
                document: cleanDetail("document")
            };
            if (!details.holderName || !details.cnp || !details.document) {
                return res.status(400).json({ error: "Completează toate datele buletinului vamal." });
            }
            description = `Titular: ${details.holderName}\nCNP: ${details.cnp}\nBuletin vamal: ${details.document}`;
        }

        if (type === "OMOLOGARI") {
            details = {
                ownerName: cleanDetail("ownerName", 120),
                homologationAgent: cleanDetail("homologationAgent", 120),
                cnp: cleanDetail("cnp", 30),
                modifications: cleanDetail("modifications"),
                costPerModification: "500.000 $"
            };
            if (!details.ownerName || !details.homologationAgent || !details.cnp || !details.modifications) {
                return res.status(400).json({ error: "Completează toate datele omologării." });
            }
            description = `Nume: ${details.ownerName}\nOmologare efectuată de: ${details.homologationAgent}\nCNP: ${details.cnp}\nModificări: ${details.modifications}\nCost/modificare: 500.000 $`;
        }

        if (type === "SANCTIUNI") {
            details = {
                agentName: cleanDetail("agentName", 120),
                suspectName: cleanDetail("suspectName", 120),
                fineReason: cleanDetail("fineReason", 1000),
                fineAmount: cleanDetail("fineAmount", 50),
                jailReason: cleanDetail("jailReason", 1000),
                jailDuration: cleanDetail("jailDuration", 50)
            };
            if (Object.values(details).some(value => !value)) {
                return res.status(400).json({ error: "Completează toate datele sancțiunii." });
            }
            description = `Agent: ${details.agentName}\nSuspect: ${details.suspectName}\nMotiv amendă: ${details.fineReason}\nAmendă: ${details.fineAmount}\nMotiv închisoare: ${details.jailReason}\nÎnchisoare: ${details.jailDuration}`;
        }

        // RAZIE / ANTRENAMENT normale pot fi postate doar de SUB INSPECTOR DIICOT+.
        // Gradele mici (Agent Stagiar / Operativ / Principal) folosesc variantele DOVADĂ.
        const authorRankLevel =
            Number(
                req.session.user.rankLevel ||
                0
            );

        const isOrganizerReport =
            type === "RAZIE" ||
            type === "ANTRENAMENT";

        const isParticipationProof =
            type === "DOVADA RAZIE" ||
            type === "DOVADA ANTRENAMENT";

        if (
            isOrganizerReport &&
            authorRankLevel < 4
        ) {
            return res.status(403).json({
                error:
                    "RAZIE și ANTRENAMENT pot fi postate doar de la SUB INSPECTOR în sus. Pentru participare folosește DOVADĂ RAZIE / DOVADĂ ANTRENAMENT."
            });
        }
        if (
            isParticipationProof &&
            uploadedImages.length < 1
        ) {
            return res.status(400).json({
                error:
                    "Pentru DOVADĂ RAZIE / DOVADĂ ANTRENAMENT trebuie să încarci cel puțin o poză."
            });
        }

        if (
            ["BULETINE VAMA", "SANCTIUNI"].includes(type) &&
            uploadedImages.length < 1
        ) {
            return res.status(400).json({
                error: "Pentru acest tip de raport trebuie să încarci cel puțin o poză."
            });
        }

        if (
            title.length < 2 ||
            title.length > 120
        ) {
            return res.status(400).json({
                error:
                    "Titlul trebuie să aibă între 2 și 120 de caractere."
            });
        }

        const needsCoOrganizer =
            type === "RAZIE" ||
            type === "ANTRENAMENT";

        let coOrganizer = null;

        if (needsCoOrganizer) {
            if (
                !coOrganizerId ||
                !["DIICOT", "POLITIE"].includes(
                    coOrganizerDepartment
                )
            ) {
                return res.status(400).json({
                    error:
                        "Pentru RAZIE și ANTRENAMENT trebuie să selectezi al doilea organizator din DIICOT sau POLIȚIE."
                });
            }

            if (
                coOrganizerId ===
                String(req.session.user.id)
            ) {
                return res.status(400).json({
                    error:
                        "Nu te poți selecta pe tine ca al doilea organizator."
                });
            }

            if (!BOT_TOKEN || !GUILD_ID) {
                return res.status(503).json({
                    error:
                        "Botul Discord nu este configurat pentru verificarea organizatorului."
                });
            }

            try {
                const member =
                    await getDiscordMemberCached(
                        coOrganizerId
                    ) || {};

                const user =
                    member.user ||
                    {};

                const roles =
                    Array.isArray(member.roles)
                        ? member.roles.map(String)
                        : [];

                const organizerRank =
                    getReportOrganizerRank(
                        roles,
                        coOrganizerDepartment
                    );

                if (!organizerRank) {
                    return res.status(400).json({
                        error:
                            `Persoana selectată nu mai are un grad eligibil de Sub Inspector+ în ${coOrganizerDepartment === "POLITIE" ? "POLIȚIE" : "DIICOT"}.`
                    });
                }

                coOrganizer = {
                    id:
                        String(user.id),
                    username:
                        user.username ||
                        "Necunoscut",
                    displayName:
                        member.nick ||
                        user.global_name ||
                        user.username ||
                        "Necunoscut",
                    avatar:
                        discordMemberAvatar(user),
                    department:
                        coOrganizerDepartment,
                    rank:
                        organizerRank.name,
                    rankRoleId:
                        organizerRank.id
                };

            } catch (error) {
                console.error(
                    "Report Co-Organizer Validation Error:",
                    error.response?.data ||
                    error.message
                );

                return res.status(400).json({
                    error:
                        "Al doilea organizator nu a putut fi verificat pe Discord."
                });
            }
        }

        const reportId =
            String(uploadManifest.reportId);

        const authorId =
            String(
                req.session.user.id
            );

        const metadataKey =
            `reports/${authorId}/${reportId}.json`;

        try {
            const now =
                new Date().toISOString();

            const report = {
                id:
                    reportId,

                authorId,

                authorName:
                    req.session.user.displayName ||
                    req.session.user.username,

                authorUsername:
                    req.session.user.username,

                authorRank:
                    req.session.user.rank,

                authorRankLevel:
                    Number(
                        req.session.user.rankLevel ||
                        0
                    ),

                type,
                title,
                description,

                details,

                coOrganizer:
                    coOrganizer,

                images:
                    uploadedImages,
                createdAt:
                    now
            };

            await b2.send(
                new PutObjectCommand({
                    Bucket: B2_BUCKET,
                    Key: metadataKey,
                    Body:
                        JSON.stringify(
                            report,
                            null,
                            2
                        ),
                    ContentType:
                        "application/json; charset=utf-8",
                    CacheControl:
                        "no-store"
                })
            );

            // Raportul apare imediat pe site fără recitire din B2.
            addReportToB2Cache(report);

            let discordNotification = {
                sent: false,
                skipped: true
            };

            if (
                type === "RAZIE" ||
                type === "ANTRENAMENT"
            ) {
                try {
                    discordNotification =
                        await sendOperationalReportToDiscord(
                            report
                        );
                }
                catch (discordError) {
                    console.error(
                        "Discord Operational Report Notification Error:",
                        discordError.response?.data ||
                        discordError.message
                    );

                    discordNotification = {
                        sent: false,
                        skipped: false,
                        error:
                            "Raportul a fost salvat, dar notificarea Discord nu a putut fi trimisă."
                    };
                }
            }

            return res.status(201).json({
                success: true,
                message:
                    discordNotification.sent
                        ? "Raportul a fost postat și trimis pe Discord."
                        : "Raportul a fost postat în Backblaze B2.",
                discordNotification,
                report:
                    await withDirectB2ImageUrls(report)
            });
        }
        catch (error) {
            console.error(
                "Report Backblaze B2 Error:",
                error
            );

            const cleanupKeys = [
                ...uploadedImages.map(
                    image =>
                        image.key ||
                        image.path
                ),
                metadataKey
            ].filter(Boolean);

            try {
                await deleteB2Keys(
                    cleanupKeys
                );
            }
            catch (cleanupError) {
                console.error(
                    "B2 report cleanup error:",
                    cleanupError.message
                );
            }

            return res.status(500).json({
                error:
                    "Raportul nu a putut fi salvat în Backblaze B2."
            });
        }
    }
);


// ======================================================
// RAPOARTELE MELE
// ======================================================

app.get(
    "/api/reports/my",
    requireAuth,
    async (req, res) => {
        if (!ensureB2(res)) {
            return;
        }

        try {
            const reports =
                await listB2Reports(
                    req.session.user.id
                );

            const reportsForClient =
                await withDirectB2ImageUrlsMany(reports);

            res.json({
                reports: reportsForClient
            });
        }
        catch (error) {
            console.error(
                "My Reports Backblaze B2 Error:",
                error
            );

            res.status(500).json({
                error:
                    "Rapoartele nu au putut fi încărcate."
            });
        }
    }
);


// ======================================================
// TOATE RAPOARTELE - ADMIN
// ======================================================

app.get(
    "/api/admin/reports",
    requireAdmin,
    async (req, res) => {
        if (!ensureB2(res)) {
            return;
        }

        try {
            const reports =
                await listB2Reports();

            const reportsForClient =
                await withDirectB2ImageUrlsMany(reports);

            res.json({
                success: true,
                total:
                    reports.length,
                reports: reportsForClient
            });
        }
        catch (error) {
            console.error(
                "Admin Reports Backblaze B2 Error:",
                error
            );

            res.status(500).json({
                error:
                    "Rapoartele nu au putut fi încărcate."
            });
        }
    }
);


// ======================================================
// ȘTERGERE GLOBALĂ RAPOARTE - ADMIN
// Șterge atât JSON-urile rapoartelor, cât și imaginile B2.
// Restul datelor din Supabase nu este atins.
// ======================================================

app.delete(
    "/api/admin/reports/all",
    requireAdmin,
    async (req, res) => {
        if (!ensureB2(res)) {
            return;
        }

        if (
            String(
                req.body?.confirmation ||
                ""
            ) !== "STERGE RAPOARTELE"
        ) {
            return res.status(400).json({
                error:
                    "Confirmarea pentru ștergere este invalidă."
            });
        }

        try {
            // B2 păstrează versiuni. Le enumerăm și le ștergem explicit
            // cu VersionId, inclusiv eventualele delete markers.
            const reportVersions = await listB2ObjectVersions("reports/");
            const imageVersions = await listB2ObjectVersions("images/");

            await deleteB2Objects([
                ...imageVersions,
                ...reportVersions
            ]);

            // Verificare finală: ruta nu raportează succes dacă au rămas
            // versiuni/markere sub prefixele de rapoarte.
            const remainingReports = await listB2ObjectVersions("reports/");
            const remainingImages = await listB2ObjectVersions("images/");

            if (remainingReports.length || remainingImages.length) {
                throw new Error(
                    `Au rămas obiecte în B2: reports=${remainingReports.length}, images=${remainingImages.length}`
                );
            }

            clearB2ReportCache();

            console.log(
                `[B2] Ștergere globală completă: ${reportVersions.length} versiuni rapoarte, ${imageVersions.length} versiuni imagini.`
            );

            return res.json({
                success: true,
                deletedReports: reportVersions.filter(
                    item => item.Key.endsWith(".json")
                ).length,
                deletedImages: imageVersions.length,
                message:
                    "Toate rapoartele și toate versiunile imaginilor au fost șterse definitiv din Backblaze B2."
            });
        }
        catch (error) {
            console.error(
                "Delete All Reports B2 Error:",
                error
            );

            return res.status(500).json({
                error:
                    "Rapoartele nu au putut fi șterse complet din Backblaze B2."
            });
        }
    }
);



// ======================================================
// EVENIMENTE + CENTRU NOTIFICĂRI
// ======================================================

app.get("/api/events", requireAuth, async (req, res) => {
    if (!ensureSupabase(res)) return;
    try {
        const { data, error } = await supabase.from("events").select("*").order("event_at", { ascending: true });
        if (error) throw error;
        return res.json({
            events: (data || []).map(row => ({
                id: row.id,
                title: row.title,
                eventAt: row.event_at,
                type: row.type,
                description: row.description || "",
                createdById: row.created_by_id || "",
                createdByName: row.created_by_name || "",
                createdByRank: row.created_by_rank || "",
                createdAt: row.created_at
            }))
        });
    } catch (error) {
        console.error("Events List Error:", error);
        return res.status(500).json({ error: "Evenimentele nu au putut fi încărcate." });
    }
});

app.post("/api/admin/events", requireAdmin, async (req, res) => {
    if (!ensureSupabase(res)) return;
    try {
        const title = String(req.body?.title || "").trim().slice(0, 100);
        const eventAt = String(req.body?.eventAt || "").trim();
        const type = String(req.body?.type || "ALTUL").trim().toUpperCase();
        const description = String(req.body?.description || "").trim().slice(0, 500);
        const allowed = new Set(["SEDINTA","BRIEFING","RAZIE","ANTRENAMENT","ALTUL"]);
        const parsed = new Date(eventAt);

        if (title.length < 2) return res.status(400).json({ error: "Titlul evenimentului este prea scurt." });
        if (Number.isNaN(parsed.getTime())) return res.status(400).json({ error: "Data și ora evenimentului sunt invalide." });
        if (!allowed.has(type)) return res.status(400).json({ error: "Tip de eveniment invalid." });

        const row = {
            id: crypto.randomUUID(),
            title,
            event_at: parsed.toISOString(),
            type,
            description,
            created_by_id: String(req.session.user.id),
            created_by_name: req.session.user.displayName || req.session.user.username || "",
            created_by_rank: req.session.user.rank || ""
        };

        const { data, error } = await supabase.from("events").insert(row).select("*").single();
        if (error) throw error;

        return res.status(201).json({
            success: true,
            event: {
                id: data.id,
                title: data.title,
                eventAt: data.event_at,
                type: data.type,
                description: data.description || "",
                createdByName: data.created_by_name || "",
                createdAt: data.created_at
            }
        });
    } catch (error) {
        console.error("Event Create Error:", error);
        return res.status(500).json({ error: "Evenimentul nu a putut fi postat." });
    }
});

async function deleteAdminEvent(req, res) {
    if (!ensureSupabase(res)) return;

    try {
        const id = String(req.params.id || "").trim();

        if (!id) {
            return res.status(400).json({
                error: "ID-ul evenimentului lipsește."
            });
        }

        const { data: existing, error: findError } =
            await supabase
                .from("events")
                .select("id,title")
                .eq("id", id)
                .maybeSingle();

        if (findError) throw findError;

        if (!existing) {
            return res.status(404).json({
                error: "Evenimentul nu mai există."
            });
        }

        const { data: deleted, error: deleteError } =
            await supabase
                .from("events")
                .delete()
                .eq("id", id)
                .select("id");

        if (deleteError) throw deleteError;

        if (!deleted || !deleted.length) {
            return res.status(500).json({
                error: "Supabase nu a confirmat ștergerea evenimentului."
            });
        }

        return res.json({
            success: true,
            deletedId: id
        });

    } catch (error) {
        console.error("Event Delete Error:", error);

        return res.status(500).json({
            error:
                error?.message ||
                "Evenimentul nu a putut fi șters."
        });
    }
}

app.delete(
    "/api/admin/events/:id",
    requireAdmin,
    deleteAdminEvent
);

app.post(
    "/api/admin/events/:id/delete",
    requireAdmin,
    deleteAdminEvent
);

app.get("/api/notifications", requireAuth, async (req, res) => {
    if (!ensureSupabase(res)) return;
    try {
        const userId = String(req.session.user.id);
        const oldLimit = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
        const notifications = [];

        const [eventsResult, complaintsResult, announcementsResult] = await Promise.all([
            supabase.from("events").select("id,title,event_at,type,description,created_at").gte("event_at", oldLimit).order("event_at", { ascending: true }).limit(30),
            supabase.from("complaints").select("id,author_name,reason,status,created_at").eq("target_id", userId).order("created_at", { ascending: false }).limit(30),
            supabase.from("site_announcements").select("id,title,message,author_name,author_rank,created_at").order("created_at", { ascending: false }).limit(30)
        ]);

        if (!eventsResult.error) {
            for (const row of eventsResult.data || []) {
                const dt = new Date(row.event_at);
                const when = Number.isNaN(dt.getTime()) ? "" : dt.toLocaleString("ro-RO", { day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit" });
                notifications.push({
                    id: `event:${row.id}`,
                    type: "EVENT",
                    title: row.type === "SEDINTA" ? `Ședință: ${row.title}` : `Eveniment: ${row.title}`,
                    message: `${when}${row.description ? ` • ${row.description}` : ""}`,
                    createdAt: row.created_at || row.event_at
                });
            }
        } else console.error("Notification Events Error:", eventsResult.error);

        if (!complaintsResult.error) {
            for (const row of complaintsResult.data || []) {
                notifications.push({
                    id: `complaint:${row.id}`,
                    type: "COMPLAINT",
                    title: "Reclamație pe numele tău",
                    message: `${row.author_name ? `Trimisă de ${row.author_name}. ` : ""}${row.reason || "A fost înregistrată o reclamație."}`,
                    createdAt: row.created_at
                });
            }
        } else console.error("Notification Complaints Error:", complaintsResult.error);

        if (!announcementsResult.error) {
            for (const row of announcementsResult.data || []) {
                notifications.push({
                    id: `announcement:${row.id}`,
                    type: "ANNOUNCEMENT",
                    title: row.title || "Anunț conducere",
                    message: `${row.message || ""}${row.author_name ? ` • ${row.author_name}` : ""}`,
                    createdAt: row.created_at
                });
            }
        } else console.error("Notification Announcements Error:", announcementsResult.error);

        notifications.sort((a,b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());
        return res.json({ notifications: notifications.slice(0,60) });
    } catch (error) {
        console.error("Notifications Error:", error);
        return res.status(500).json({ error: "Notificările nu au putut fi încărcate." });
    }
});


// ======================================================
// CONDUCERE - ANUNȚURI DISCORD
// ======================================================

app.post(
    "/api/leadership/announcement",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (!BOT_TOKEN) {

            return res
                .status(500)
                .json({
                    error:
                        "Botul Discord nu este configurat."
                });
        }


        const title =
            String(
                req.body.title ||
                ""
            ).trim();


        const message =
            String(
                req.body.message ||
                ""
            ).trim();

        const destination =
            String(req.body.destination || "POLITIE")
                .trim()
                .toUpperCase();

        const channelId =
            POLICE_ANNOUNCEMENT_CHANNELS[destination];

        if (!channelId) {
            return res.status(400).json({
                error: "Canalul de anunț selectat nu este valid."
            });
        }


        if (
            title.length < 2 ||
            title.length > 120
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Titlul trebuie să aibă între 2 și 120 de caractere."
                });
        }


        if (
            message.length < 2 ||
            message.length > 4000
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Mesajul trebuie să aibă între 2 și 4000 de caractere."
                });
        }


        const authorName =
            req.session.user.displayName ||
            req.session.user.username ||
            "Conducerea Poliției Române";


        const authorRank =
            req.session.user.rank ||
            "CONDUCERE POLIȚIA ROMÂNĂ";


        const avatarURL =
            req.session.user.avatar

                ? `https://cdn.discordapp.com/avatars/${req.session.user.id}/${req.session.user.avatar}.png?size=128`

                : null;


        const embed = {

            title:
                `📢 ${title}`,

            description:
                message,

            color:
                0xFFC400,

            author: {

                name:
                    `${authorName} • ${authorRank}`,

                ...(
                    avatarURL

                        ? {
                            icon_url:
                                avatarURL
                        }

                        : {}
                )
            },

            fields: [
                {
                    name:
                        "STRUCTURĂ",

                    value:
                        destination === "COMUNE"
                            ? "ANUNȚURI COMUNE"
                            : "POLIȚIA ROMÂNĂ",

                    inline:
                        false
                }
            ],

            footer: {

                text:
                    destination === "COMUNE"
                        ? "Poliția Română • Anunț comun • Comunicat oficial"
                        : "Poliția Română • Comunicat oficial"
            },

            timestamp:
                new Date()
                    .toISOString()
        };


        try {

            const response =
                await axios.post(

                    `https://discord.com/api/v10/channels/${channelId}/messages`,

                    {
                        embeds: [
                            embed
                        ],

                        allowed_mentions: {
                            parse: []
                        }
                    },

                    {
                        headers: {

                            Authorization:
                                `Bot ${BOT_TOKEN}`,

                            "Content-Type":
                                "application/json"
                        }
                    }
                );


            let notificationSaved =
                false;

            try {

                if (supabase) {

                    const {
                        error:
                            saveAnnouncementError
                    } =
                        await supabase
                            .from(
                                "site_announcements"
                            )
                            .insert({
                                id:
                                    crypto.randomUUID(),

                                title,

                                message,

                                author_id:
                                    String(
                                        req.session.user.id
                                    ),

                                author_name:
                                    authorName,

                                author_rank:
                                    authorRank,

                                discord_message_id:
                                    String(
                                        response.data.id ||
                                        ""
                                    )
                            });

                    if (
                        saveAnnouncementError
                    ) {
                        throw saveAnnouncementError;
                    }

                    notificationSaved =
                        true;
                }

            }

            catch (
                saveError
            ) {

                console.error(
                    "Announcement Notification Save Error:",
                    saveError
                );
            }


            res.json({

                success:
                    true,

                message:
                    destination === "COMUNE"
                        ? "Anunțul comun a fost trimis pe Discord."
                        : "Anunțul Poliției a fost trimis pe Discord.",

                destination,

                channelId,

                discordMessageId:
                    response.data.id,

                notificationSaved
            });

        }

        catch (error) {

            console.error(
                "Discord Announcement Error:",
                error.response?.data ||
                error.message
            );


            if (
                error.response?.status ===
                403
            ) {

                return res
                    .status(403)
                    .json({
                        error:
                            "Botul nu are permisiunea să trimită mesaje sau embed-uri în canal."
                    });
            }


            if (
                error.response?.status ===
                404
            ) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Canalul Discord nu a fost găsit."
                    });
            }


            res
                .status(500)
                .json({
                    error:
                        "Anunțul nu a putut fi trimis."
                });
        }
    }
);


// ======================================================
// CONCEDII / ÎNVOIRI - DATELE MELE
// ======================================================

app.get(
    "/api/leave/me",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }


        try {

            const userId =
                String(
                    req.session.user.id
                );


            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "leave_requests"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "author_id",
                        userId
                    )
                    .order(
                        "created_at",
                        {
                            ascending:
                                false
                        }
                    );


            if (error) {

                throw error;
            }


            const usage =
                await getLeaveUsage(
                    userId
                );


            res.json({

                success:
                    true,

                limits: {

                    vacationDays:
                        VACATION_DAYS_LIMIT,

                    meetingExcuses:
                        MEETING_EXCUSES_LIMIT
                },

                usage,

                requests:
                    (
                        data ||
                        []
                    )
                        .map(
                            mapLeaveRequest
                        )
            });

        }

        catch (error) {

            console.error(
                "Leave Me Supabase Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Cererile nu au putut fi încărcate."
                });
        }
    }
);


// ======================================================
// CONCEDII / ÎNVOIRI - CERERE NOUĂ
// ======================================================

app.post(
    "/api/leave",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }


        try {

            const type =
                String(
                    req.body.type ||
                    ""
                )
                    .trim()
                    .toUpperCase();


            const startDateRaw =
                String(
                    req.body.startDate ||
                    ""
                ).trim();


            const endDateRaw =
                String(
                    req.body.endDate ||
                    ""
                ).trim();


            const reason =
                String(
                    req.body.reason ||
                    ""
                ).trim();


            if (
                ![
                    "VACATION",
                    "MEETING_EXCUSE"
                ].includes(
                    type
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Tipul cererii nu este valid."
                    });
            }


            if (
                reason.length < 3 ||
                reason.length > 1000
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Motivul trebuie să aibă între 3 și 1000 de caractere."
                    });
            }


            const start =
                parseDateOnly(
                    startDateRaw
                );


            const end =
                parseDateOnly(
                    endDateRaw
                );


            if (
                !start ||
                !end
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Selectează o dată de început și o dată de sfârșit valide."
                    });
            }


            if (
                end < start
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Data de sfârșit nu poate fi înaintea datei de început."
                    });
            }


            const days =
                inclusiveDays(
                    start,
                    end
                );


            const userId =
                String(
                    req.session.user.id
                );


            const usage =
                await getLeaveUsage(
                    userId
                );


            if (
                type ===
                    "VACATION" &&
                days >
                    usage
                        .vacationRemaining
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            `Mai ai doar ${usage.vacationRemaining} zile de concediu disponibile.`
                    });
            }


            if (
                type ===
                    "MEETING_EXCUSE" &&
                usage
                    .meetingExcusesRemaining <=
                    0
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Nu mai ai învoiri de ședință disponibile."
                    });
            }


            const {
                data:
                    duplicate,

                error:
                    duplicateError
            } =
                await supabase
                    .from(
                        "leave_requests"
                    )
                    .select(
                        "id"
                    )
                    .eq(
                        "author_id",
                        userId
                    )
                    .eq(
                        "status",
                        "PENDING"
                    )
                    .eq(
                        "type",
                        type
                    )
                    .eq(
                        "start_date",
                        startDateRaw
                    )
                    .eq(
                        "end_date",
                        endDateRaw
                    )
                    .limit(1);


            if (
                duplicateError
            ) {

                throw duplicateError;
            }


            if (
                duplicate?.length
            ) {

                return res
                    .status(409)
                    .json({
                        error:
                            "Ai deja o cerere în așteptare pentru același interval."
                    });
            }


            const now =
                new Date();


            const row = {

                id:
                    crypto.randomUUID(),

                author_id:
                    userId,

                author_name:
                    req.session.user.displayName ||
                    req.session.user.username,

                author_username:
                    req.session.user.username,

                author_rank:
                    req.session.user.rank,

                type,

                start_date:
                    startDateRaw,

                end_date:
                    endDateRaw,

                days,

                reason,

                status:
                    "PENDING",

                evaluator_id:
                    null,

                evaluator_name:
                    null,

                evaluator_rank:
                    null,

                decision_note:
                    null,

                decided_at:
                    null,

                cancelled_at:
                    null,

                created_at:
                    now.toISOString()
            };


            const {
                data:
                    inserted,

                error:
                    insertError
            } =
                await supabase
                    .from(
                        "leave_requests"
                    )
                    .insert(
                        row
                    )
                    .select()
                    .single();


            if (
                insertError
            ) {

                throw insertError;
            }


            res
                .status(201)
                .json({

                    success:
                        true,

                    message:
                        "Cererea a fost trimisă spre evaluare.",

                    request:
                        mapLeaveRequest(
                            inserted
                        ),

                    usage:
                        await getLeaveUsage(
                            userId
                        )
                });

        }

        catch (error) {

            console.error(
                "Leave Create Supabase Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Cererea nu a putut fi salvată."
                });
        }
    }
);


// ======================================================
// CONCEDII / ÎNVOIRI - ANULARE CERERE
// ======================================================

app.patch(
    "/api/leave/:id/cancel",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const requestId =
                String(
                    req.params.id ||
                    ""
                ).trim();

            const userId =
                String(
                    req.session.user.id
                );

            const {
                data:
                    existing,

                error:
                    findError
            } =
                await supabase
                    .from(
                        "leave_requests"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "id",
                        requestId
                    )
                    .eq(
                        "author_id",
                        userId
                    )
                    .maybeSingle();


            if (findError) {
                throw findError;
            }


            if (!existing) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Cererea nu a fost găsită."
                    });
            }


            if (
                existing.status !==
                "PENDING"
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Doar cererile aflate în așteptare pot fi anulate."
                    });
            }


            const now =
                new Date()
                    .toISOString();


            const {
                data:
                    updated,

                error:
                    updateError
            } =
                await supabase
                    .from(
                        "leave_requests"
                    )
                    .update({

                        status:
                            "CANCELLED",

                        cancelled_at:
                            now

                    })
                    .eq(
                        "id",
                        requestId
                    )
                    .eq(
                        "author_id",
                        userId
                    )
                    .select()
                    .single();


            if (updateError) {
                throw updateError;
            }


            res.json({

                success:
                    true,

                message:
                    "Cererea a fost anulată.",

                request:
                    mapLeaveRequest(
                        updated
                    ),

                usage:
                    await getLeaveUsage(
                        userId
                    )
            });

        }

        catch (error) {

            console.error(
                "Leave Cancel Supabase Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Cererea nu a putut fi anulată."
                });
        }
    }
);


// ======================================================
// CONCEDII / ÎNVOIRI - RESETARE SOLDURI
// Acces EXCLUSIV pentru userul configurat mai sus.
// Istoricul NU se șterge; resetarea stabilește un nou punct de calcul.
// ======================================================

app.post(
    "/api/leave/reset-allowances",
    requireAuth,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        const actorId = String(req.session.user?.id || "");

        if (actorId !== LEAVE_RESET_USER_ID) {
            return res.status(403).json({
                error: "Nu ai permisiunea să resetezi zilele de concediu și învoirile."
            });
        }

        try {
            const resetAt = new Date().toISOString();

            const { error } = await supabase
                .from("leave_allowance_resets")
                .upsert(
                    {
                        id: "global",
                        reset_at: resetAt,
                        reset_by_id: actorId,
                        reset_by_name:
                            req.session.user?.displayName ||
                            req.session.user?.username ||
                            "DIICOT"
                    },
                    { onConflict: "id" }
                );

            if (error) throw error;

            return res.json({
                success: true,
                message: "Soldurile au fost resetate la 14/14 zile de concediu și 2/2 învoiri.",
                resetAt
            });
        }
        catch (error) {
            console.error("Leave Allowance Reset Error:", error);
            return res.status(500).json({
                error: "Resetarea nu a putut fi salvată. Verifică tabela leave_allowance_resets în Supabase."
            });
        }
    }
);


// ======================================================
// CONCEDII / ÎNVOIRI - ADMINISTRARE
// ======================================================

app.get(
    "/api/admin/leave",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "leave_requests"
                    )
                    .select(
                        "*"
                    )
                    .order(
                        "created_at",
                        {
                            ascending:
                                false
                        }
                    );


            if (error) {
                throw error;
            }


            res.json({

                success:
                    true,

                requests:
                    (
                        data ||
                        []
                    )
                        .map(
                            mapLeaveRequest
                        )
            });

        }

        catch (error) {

            console.error(
                "Admin Leave Supabase Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Cererile nu au putut fi încărcate."
                });
        }
    }
);


// ======================================================
// CONCEDII / ÎNVOIRI - DECIZIE ADMIN
// ======================================================

app.patch(
    "/api/admin/leave/:id/decision",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const requestId =
                String(
                    req.params.id ||
                    ""
                ).trim();


            const decision =
                String(
                    req.body.decision ||
                    ""
                )
                    .trim()
                    .toUpperCase();


            const decisionNote =
                String(
                    req.body.note ||
                    req.body.decisionNote ||
                    ""
                ).trim();


            if (
                ![
                    "APPROVED",
                    "REJECTED"
                ].includes(
                    decision
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Decizia trebuie să fie APPROVED sau REJECTED."
                    });
            }


            if (
                decisionNote.length >
                1000
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Nota deciziei poate avea maximum 1000 de caractere."
                    });
            }


            const {
                data:
                    existing,

                error:
                    findError
            } =
                await supabase
                    .from(
                        "leave_requests"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "id",
                        requestId
                    )
                    .maybeSingle();


            if (findError) {
                throw findError;
            }


            if (!existing) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Cererea nu a fost găsită."
                    });
            }


            if (
                existing.status !==
                "PENDING"
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Această cerere a fost deja procesată."
                    });
            }


            if (
                String(
                    existing.author_id
                ) ===
                String(
                    req.session.user.id
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Nu îți poți aproba sau respinge propria cerere."
                    });
            }


            if (
                decision ===
                "APPROVED"
            ) {

                const usage =
                    await getLeaveUsage(
                        existing.author_id
                    );


                if (
                    existing.type ===
                        "VACATION" &&
                    Number(
                        existing.days ||
                        0
                    ) >
                        usage
                            .vacationRemaining
                ) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Membrul nu mai are suficiente zile de concediu disponibile."
                        });
                }


                if (
                    existing.type ===
                        "MEETING_EXCUSE" &&
                    usage
                        .meetingExcusesRemaining <=
                        0
                ) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Membrul nu mai are învoiri de ședință disponibile."
                        });
                }
            }


            const now =
                new Date()
                    .toISOString();


            const {
                data:
                    updated,

                error:
                    updateError
            } =
                await supabase
                    .from(
                        "leave_requests"
                    )
                    .update({

                        status:
                            decision,

                        evaluator_id:
                            String(
                                req.session.user.id
                            ),

                        evaluator_name:
                            req.session.user.displayName ||
                            req.session.user.username,

                        evaluator_rank:
                            req.session.user.rank,

                        decision_note:
                            decisionNote ||
                            null,

                        decided_at:
                            now

                    })
                    .eq(
                        "id",
                        requestId
                    )
                    .select()
                    .single();


            if (updateError) {
                throw updateError;
            }


            // Discord: rol + mesaj privat după ce decizia a fost salvată.
            // O eroare Discord nu anulează decizia deja salvată în Supabase.
            const leaveDiscordWarnings = [];
            const leaveRoleId = getLeaveDiscordRoleId(existing.type);
            const memberId = String(existing.author_id);
            const evaluatorName = req.session.user.displayName || req.session.user.username;

            if (decision === "APPROVED" && leaveRoleId) {
                try {
                    await setDiscordMemberRole(memberId, leaveRoleId, true);
                } catch (discordRoleError) {
                    console.error("Leave Discord Role Add Error:", discordRoleError?.response?.data || discordRoleError?.message || discordRoleError);
                    leaveDiscordWarnings.push("Cererea a fost aprobată, dar rolul Discord nu a putut fi adăugat.");
                }
            }

            try {
                if (decision === "APPROVED") {
                    const typeLabel = existing.type === "VACATION" ? "concediu" : "învoire";
                    const durationText = existing.type === "MEETING_EXCUSE"
                        ? "Învoirea este valabilă 24 de ore de la aprobare."
                        : `Concediul este aprobat pentru perioada ${formatDateOnlyRO(`${existing.start_date}T12:00:00`)} - ${formatDateOnlyRO(`${existing.end_date}T12:00:00`)}.`;
                    await sendDiscordDM(
                        memberId,
                        `✅ CERERE ${typeLabel.toUpperCase()} APROBATĂ\n\nCererea ta de ${typeLabel} a fost acceptată.\n${durationText}${decisionNote ? `\nObservație: **${decisionNote}**` : ""}\n\nAprobată de: **${evaluatorName}**`
                    );
                } else {
                    const typeLabel = existing.type === "VACATION" ? "concediu" : "învoire";
                    await sendDiscordDM(
                        memberId,
                        `❌ CERERE ${typeLabel.toUpperCase()} RESPINSĂ\n\nCererea ta de ${typeLabel} a fost respinsă.${decisionNote ? `\nMotiv: **${decisionNote}**` : ""}\n\nDecizie luată de: **${evaluatorName}**`
                    );
                }
            } catch (discordDmError) {
                console.error("Leave Discord DM Error:", discordDmError?.response?.data || discordDmError?.message || discordDmError);
                leaveDiscordWarnings.push("Decizia a fost salvată, dar mesajul privat Discord nu a putut fi trimis.");
            }


            res.json({

                success:
                    true,

                discordWarnings:
                    leaveDiscordWarnings,

                message:
                    decision ===
                    "APPROVED"

                        ? "Cererea a fost aprobată."

                        : "Cererea a fost respinsă.",

                request:
                    mapLeaveRequest(
                        updated
                    ),

                usage:
                    await getLeaveUsage(
                        existing.author_id
                    )
            });

        }

        catch (error) {

            console.error(
                "Admin Leave Decision Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Decizia nu a putut fi salvată."
                });
        }
    }
);


// ======================================================
// BLACKLIST - LISTĂ COMPLETĂ
// DOAR COORDONATOR+
// ======================================================

app.get(
    "/api/admin/blacklist",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            await updateBlacklistStatuses();


            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "*"
                    )
                    .order(
                        "created_at",
                        {
                            ascending:
                                false
                        }
                    );


            if (error) {
                throw error;
            }


            const entries =
                (
                    data ||
                    []
                )
                    .map(
                        mapBlacklist
                    );


            res.json({

                success:
                    true,

                total:
                    entries.length,

                entries
            });

        }

        catch (error) {

            console.error(
                "Blacklist List Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Blacklist-ul nu a putut fi încărcat."
                });
        }
    }
);


// ======================================================
// BLACKLIST - VERIFICARE DISCORD ID
// ======================================================

app.get(
    "/api/admin/blacklist/check/:discordId",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const discordId =
                String(
                    req.params.discordId ||
                    ""
                ).trim();


            if (
                !/^\d{17,20}$/.test(
                    discordId
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Discord ID invalid."
                    });
            }


            await updateBlacklistStatuses();


            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "discord_id",
                        discordId
                    )
                    .order(
                        "created_at",
                        {
                            ascending:
                                false
                        }
                    );


            if (error) {
                throw error;
            }


            const entries =
                (
                    data ||
                    []
                )
                    .map(
                        mapBlacklist
                    );


            const active =
                entries.find(
                    entry =>
                        entry.status ===
                        "ACTIVE"
                ) ||
                null;


            res.json({

                success:
                    true,

                blacklisted:
                    Boolean(active),

                activeEntry:
                    active,

                history:
                    entries
            });

        }

        catch (error) {

            console.error(
                "Blacklist Check Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Verificarea blacklist-ului a eșuat."
                });
        }
    }
);


// ======================================================
// BLACKLIST - DETALII ÎNREGISTRARE
// ======================================================

app.get(
    "/api/admin/blacklist/:id",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            await updateBlacklistStatuses();


            const blacklistId =
                String(
                    req.params.id ||
                    ""
                ).trim();


            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "id",
                        blacklistId
                    )
                    .maybeSingle();


            if (error) {
                throw error;
            }


            if (!data) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Înregistrarea nu a fost găsită."
                    });
            }


            res.json({

                success:
                    true,

                entry:
                    mapBlacklist(
                        data
                    )
            });

        }

        catch (error) {

            console.error(
                "Blacklist Details Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Înregistrarea nu a putut fi încărcată."
                });
        }
    }
);



// ======================================================
// DISCORD — BLACKLIST NOU
// ======================================================

async function sendBlacklistCreateMessage(entry = {}) {
    if (!BOT_TOKEN || !BLACKLIST_CHANNEL_ID) {
        throw new Error(
            "Canalul de blacklist sau botul Discord nu este configurat."
        );
    }

    const durationText =
        entry.duration_type === "PERMANENT"
            ? "PERMANENT"
            : (
                entry.expires_at
                    ? `TEMPORAR • până la ${new Date(entry.expires_at).toLocaleString("ro-RO", {
                        day: "2-digit",
                        month: "2-digit",
                        year: "numeric",
                        hour: "2-digit",
                        minute: "2-digit"
                    })}`
                    : "TEMPORAR"
            );

    const embed = {
        title:
            "⛔ BLACKLIST NOU",

        color:
            0xED4245,

        description:
            "O persoană a fost adăugată în blacklist-ul Poliției.",

        fields: [
            {
                name:
                    "PERSOANĂ",

                value:
                    String(
                        entry.name ||
                        "Necunoscut"
                    ).slice(
                        0,
                        1024
                    ),

                inline:
                    true
            },
            {
                name:
                    "DISCORD ID",

                value:
                    `\`${String(
                        entry.discord_id ||
                        "-"
                    )}\``,

                inline:
                    true
            },
            {
                name:
                    "DURATĂ",

                value:
                    durationText,

                inline:
                    true
            },
            {
                name:
                    "MOTIV",

                value:
                    String(
                        entry.reason ||
                        "-"
                    ).slice(
                        0,
                        1024
                    ),

                inline:
                    false
            },
            {
                name:
                    "ADĂUGAT DE",

                value:
                    `${entry.added_by_name || "Conducerea DIICOT"}\n${entry.added_by_rank || "CONDUCERE DIICOT"}`,

                inline:
                    true
            },
            {
                name:
                    "STATUS",

                value:
                    "ACTIV",

                inline:
                    true
            }
        ],

        footer: {
            text:
                "Poliția Română • Centru de Comandă • Rush România"
        },

        timestamp:
            entry.created_at ||
            new Date().toISOString()
    };

    if (
        entry.avatar &&
        /^https?:\/\//i.test(
            String(entry.avatar)
        )
    ) {
        embed.thumbnail = {
            url:
                String(entry.avatar)
        };
    }

    await axios.post(
        `https://discord.com/api/v10/channels/${BLACKLIST_CHANNEL_ID}/messages`,
        {
            embeds: [
                embed
            ],

            allowed_mentions: {
                parse: []
            }
        },
        {
            headers: {
                Authorization:
                    `Bot ${BOT_TOKEN}`,

                "Content-Type":
                    "application/json"
            }
        }
    );
}


// ======================================================
// BLACKLIST - ADĂUGARE
// ======================================================

app.post(
    "/api/admin/blacklist",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const discordId =
                String(
                    req.body.discordId ||
                    ""
                ).trim();


            const reason =
                String(
                    req.body.reason ||
                    ""
                ).trim();


            const durationType =
                String(
                    req.body.durationType ||
                    ""
                )
                    .trim()
                    .toUpperCase();


            const expiresAtRaw =
                req.body.expiresAt
                    ? String(
                        req.body.expiresAt
                    ).trim()
                    : null;


            if (
                !/^\d{17,20}$/.test(
                    discordId
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Discord ID invalid."
                    });
            }


            if (
                reason.length < 3 ||
                reason.length > 2000
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Motivul trebuie să aibă între 3 și 2000 de caractere."
                    });
            }


            if (
                ![
                    "PERMANENT",
                    "TEMPORARY"
                ].includes(
                    durationType
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Tipul duratei trebuie să fie PERMANENT sau TEMPORARY."
                    });
            }


            let expiresAt =
                null;


            if (
                durationType ===
                "TEMPORARY"
            ) {

                if (!expiresAtRaw) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Trebuie să alegi data expirării."
                        });
                }


                const parsed =
                    new Date(
                        expiresAtRaw
                    );


                if (
                    Number.isNaN(
                        parsed.getTime()
                    )
                ) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Data expirării nu este validă."
                        });
                }


                if (
                    parsed <=
                    new Date()
                ) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Data expirării trebuie să fie în viitor."
                        });
                }


                expiresAt =
                    parsed
                        .toISOString();
            }


            await updateBlacklistStatuses();


            const {
                data:
                    existing,

                error:
                    existingError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "discord_id",
                        discordId
                    )
                    .eq(
                        "status",
                        "ACTIVE"
                    )
                    .limit(1);


            if (existingError) {
                throw existingError;
            }


            if (
                existing?.length
            ) {

                return res
                    .status(409)
                    .json({
                        error:
                            "Acest utilizator este deja în blacklist."
                    });
            }


            const discordUser =
                await getDiscordUserBasic(
                    discordId
                );


            const now =
                new Date()
                    .toISOString();


            const row = {

                id:
                    crypto.randomUUID(),

                discord_id:
                    discordId,

                name:
                    discordUser?.displayName ||
                    String(
                        req.body.name ||
                        "Necunoscut"
                    ).trim(),

                username:
                    discordUser?.username ||
                    String(
                        req.body.username ||
                        ""
                    ).trim() ||
                    null,

                avatar:
                    discordUser?.avatar ||
                    null,

                reason,

                duration_type:
                    durationType,

                expires_at:
                    expiresAt,

                status:
                    "ACTIVE",

                added_by_id:
                    String(
                        req.session.user.id
                    ),

                added_by_name:
                    req.session.user.displayName ||
                    req.session.user.username,

                added_by_username:
                    req.session.user.username,

                added_by_rank:
                    req.session.user.rank,

                created_at:
                    now,

                deactivated_at:
                    null,

                deactivated_by_id:
                    null,

                deactivated_by_name:
                    null,

                deactivated_reason:
                    null,

                updated_at:
                    now,

                updated_by_id:
                    String(
                        req.session.user.id
                    ),

                updated_by_name:
                    req.session.user.displayName ||
                    req.session.user.username
            };


            const {
                data:
                    inserted,

                error:
                    insertError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .insert(
                        row
                    )
                    .select()
                    .single();


            if (insertError) {
                throw insertError;
            }


            let discordSent =
                false;

            let discordError =
                null;

            try {
                await sendBlacklistCreateMessage(
                    inserted
                );

                discordSent =
                    true;
            }
            catch (error) {
                discordError =
                    error?.response?.data?.message ||
                    error?.message ||
                    "Mesajul de blacklist nu a putut fi trimis pe Discord.";

                console.warn(
                    "Blacklist Discord Channel Warning:",
                    discordError
                );
            }


            res
                .status(201)
                .json({

                    success:
                        true,

                    message:
                        discordSent
                            ? "Utilizatorul a fost adăugat în blacklist și trimis pe Discord."
                            : "Utilizatorul a fost adăugat în blacklist.",

                    discordSent,
                    discordError,

                    entry:
                        mapBlacklist(
                            inserted
                        )
                });

        }

        catch (error) {

            console.error(
                "Blacklist Create Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Utilizatorul nu a putut fi adăugat în blacklist."
                });
        }
    }
);


// ======================================================
// BLACKLIST - EDITARE
// ======================================================

app.patch(
    "/api/admin/blacklist/:id",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const blacklistId =
                String(
                    req.params.id ||
                    ""
                ).trim();


            const {
                data:
                    existing,

                error:
                    findError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "id",
                        blacklistId
                    )
                    .maybeSingle();


            if (findError) {
                throw findError;
            }


            if (!existing) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Înregistrarea nu a fost găsită."
                    });
            }


            const reason =
                req.body.reason !==
                undefined

                    ? String(
                        req.body.reason ||
                        ""
                    ).trim()

                    : existing.reason;


            const durationType =
                req.body.durationType !==
                undefined

                    ? String(
                        req.body.durationType ||
                        ""
                    )
                        .trim()
                        .toUpperCase()

                    : existing.duration_type;


            if (
                reason.length < 3 ||
                reason.length > 2000
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Motivul trebuie să aibă între 3 și 2000 de caractere."
                    });
            }


            if (
                ![
                    "PERMANENT",
                    "TEMPORARY"
                ].includes(
                    durationType
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Tipul duratei nu este valid."
                    });
            }


            let expiresAt =
                existing.expires_at;


            if (
                durationType ===
                "PERMANENT"
            ) {

                expiresAt =
                    null;
            }

            else {

                const expiresAtRaw =
                    req.body.expiresAt !==
                    undefined

                        ? String(
                            req.body.expiresAt ||
                            ""
                        ).trim()

                        : existing.expires_at;


                if (!expiresAtRaw) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Trebuie să alegi data expirării."
                        });
                }


                const parsed =
                    new Date(
                        expiresAtRaw
                    );


                if (
                    Number.isNaN(
                        parsed.getTime()
                    )
                ) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Data expirării nu este validă."
                        });
                }


                expiresAt =
                    parsed
                        .toISOString();
            }


            const now =
                new Date()
                    .toISOString();


            const {
                data:
                    updated,

                error:
                    updateError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .update({

                        reason,

                        duration_type:
                            durationType,

                        expires_at:
                            expiresAt,

                        updated_at:
                            now,

                        updated_by_id:
                            String(
                                req.session.user.id
                            ),

                        updated_by_name:
                            req.session.user.displayName ||
                            req.session.user.username

                    })
                    .eq(
                        "id",
                        blacklistId
                    )
                    .select()
                    .single();


            if (updateError) {
                throw updateError;
            }


            res.json({

                success:
                    true,

                message:
                    "Blacklist-ul a fost actualizat.",

                entry:
                    mapBlacklist(
                        updated
                    )
            });

        }

        catch (error) {

            console.error(
                "Blacklist Update Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Înregistrarea nu a putut fi actualizată."
                });
        }
    }
);


// ======================================================
// BLACKLIST - DEZACTIVARE
// ======================================================

app.patch(
    "/api/admin/blacklist/:id/deactivate",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const blacklistId =
                String(
                    req.params.id ||
                    ""
                ).trim();


            const reason =
                String(
                    req.body.reason ||
                    "Dezactivat manual"
                ).trim();


            const {
                data:
                    existing,

                error:
                    findError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "id",
                        blacklistId
                    )
                    .maybeSingle();


            if (findError) {
                throw findError;
            }


            if (!existing) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Înregistrarea nu a fost găsită."
                    });
            }


            if (
                existing.status !==
                "ACTIVE"
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Această înregistrare nu mai este activă."
                    });
            }


            const now =
                new Date()
                    .toISOString();


            const {
                data:
                    updated,

                error:
                    updateError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .update({

                        status:
                            "INACTIVE",

                        deactivated_at:
                            now,

                        deactivated_by_id:
                            String(
                                req.session.user.id
                            ),

                        deactivated_by_name:
                            req.session.user.displayName ||
                            req.session.user.username,

                        deactivated_reason:
                            reason,

                        updated_at:
                            now,

                        updated_by_id:
                            String(
                                req.session.user.id
                            ),

                        updated_by_name:
                            req.session.user.displayName ||
                            req.session.user.username

                    })
                    .eq(
                        "id",
                        blacklistId
                    )
                    .select()
                    .single();


            if (updateError) {
                throw updateError;
            }


            res.json({

                success:
                    true,

                message:
                    "Înregistrarea a fost dezactivată.",

                entry:
                    mapBlacklist(
                        updated
                    )
            });

        }

        catch (error) {

            console.error(
                "Blacklist Deactivate Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Înregistrarea nu a putut fi dezactivată."
                });
        }
    }
);


// ======================================================
// BLACKLIST - REACTIVARE
// ======================================================

app.patch(
    "/api/admin/blacklist/:id/reactivate",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const blacklistId =
                String(
                    req.params.id ||
                    ""
                ).trim();


            const {
                data:
                    existing,

                error:
                    findError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "id",
                        blacklistId
                    )
                    .maybeSingle();


            if (findError) {
                throw findError;
            }


            if (!existing) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Înregistrarea nu a fost găsită."
                    });
            }


            if (
                existing.status ===
                "ACTIVE"
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Înregistrarea este deja activă."
                    });
            }


            const {
                data:
                    activeDuplicate,

                error:
                    duplicateError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "id"
                    )
                    .eq(
                        "discord_id",
                        existing.discord_id
                    )
                    .eq(
                        "status",
                        "ACTIVE"
                    )
                    .neq(
                        "id",
                        blacklistId
                    )
                    .limit(1);


            if (duplicateError) {
                throw duplicateError;
            }


            if (
                activeDuplicate?.length
            ) {

                return res
                    .status(409)
                    .json({
                        error:
                            "Există deja o înregistrare activă pentru acest Discord ID."
                    });
            }


            let expiresAt =
                existing.expires_at;


            if (
                existing.duration_type ===
                "TEMPORARY"
            ) {

                const expiresAtRaw =
                    req.body.expiresAt
                        ? String(
                            req.body.expiresAt
                        ).trim()
                        : null;


                if (expiresAtRaw) {

                    const parsed =
                        new Date(
                            expiresAtRaw
                        );


                    if (
                        Number.isNaN(
                            parsed.getTime()
                        )
                    ) {

                        return res
                            .status(400)
                            .json({
                                error:
                                    "Data expirării nu este validă."
                            });
                    }


                    expiresAt =
                        parsed
                            .toISOString();
                }


                if (
                    !expiresAt ||
                    new Date(
                        expiresAt
                    ) <=
                        new Date()
                ) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Pentru reactivarea blacklist-ului temporar trebuie setată o dată de expirare în viitor."
                        });
                }
            }


            const now =
                new Date()
                    .toISOString();


            const {
                data:
                    updated,

                error:
                    updateError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .update({

                        status:
                            "ACTIVE",

                        expires_at:
                            expiresAt,

                        deactivated_at:
                            null,

                        deactivated_by_id:
                            null,

                        deactivated_by_name:
                            null,

                        deactivated_reason:
                            null,

                        updated_at:
                            now,

                        updated_by_id:
                            String(
                                req.session.user.id
                            ),

                        updated_by_name:
                            req.session.user.displayName ||
                            req.session.user.username

                    })
                    .eq(
                        "id",
                        blacklistId
                    )
                    .select()
                    .single();


            if (updateError) {
                throw updateError;
            }


            res.json({

                success:
                    true,

                message:
                    "Înregistrarea a fost reactivată.",

                entry:
                    mapBlacklist(
                        updated
                    )
            });

        }

        catch (error) {

            console.error(
                "Blacklist Reactivate Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Înregistrarea nu a putut fi reactivată."
                });
        }
    }
);


// ======================================================
// BLACKLIST - ȘTERGERE DEFINITIVĂ
// ======================================================

app.delete(
    "/api/admin/blacklist/:id",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const blacklistId =
                String(
                    req.params.id ||
                    ""
                ).trim();


            const {
                data:
                    existing,

                error:
                    findError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .select(
                        "id"
                    )
                    .eq(
                        "id",
                        blacklistId
                    )
                    .maybeSingle();


            if (findError) {
                throw findError;
            }


            if (!existing) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Înregistrarea nu a fost găsită."
                    });
            }


            const {
                error:
                    deleteError
            } =
                await supabase
                    .from(
                        "blacklist"
                    )
                    .delete()
                    .eq(
                        "id",
                        blacklistId
                    );


            if (deleteError) {
                throw deleteError;
            }


            res.json({

                success:
                    true,

                message:
                    "Înregistrarea a fost ștearsă definitiv."
            });

        }

        catch (error) {

            console.error(
                "Blacklist Delete Error:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Înregistrarea nu a putut fi ștearsă."
                });
        }
    }
);



// ======================================================
// DISCORD — LISTARE COMPLETĂ MEMBRI GUILD
// Discord returnează maximum 1000 membri / request.
// Facem paginare ca PERSONAL DIICOT să nu depindă doar de
// primii 1000 membri ai serverului.
// ======================================================

async function fetchAllGuildMembersForPersonnel() {
    return getGuildMembersCached();
}


function mapDiscordPersonnelMember(member) {
    try {
        const user =
            member?.user ||
            {};

        if (!user.id) {
            return null;
        }

        const roles =
            Array.isArray(member.roles)
                ? member.roles.map(String)
                : [];

        const rank =
            getHighestDIICOTRole(
                roles
            );

        if (!rank) {
            return null;
        }

        return {
            id:
                String(user.id),

            username:
                user.username ||
                "Necunoscut",

            displayName:
                member.nick ||
                user.global_name ||
                user.username ||
                "Necunoscut",

            avatar:
                discordMemberAvatar(
                    user
                ),

            rank:
                rank.name,

            rankLevel:
                Number(rank.level || 0),

            rankRoleId:
                rank.id
        };
    }
    catch (error) {
        console.error(
            "Personnel member map error:",
            error.message ||
            error
        );

        return null;
    }
}


async function fetchPersonnelFallbackIds() {
    const ids =
        new Set();

    // Utilizatorul autentificat va fi adăugat separat în rută.
    if (
        SUPABASE_URL &&
        SUPABASE_SERVICE_KEY
    ) {
        try {
            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "docs_personnel"
                    )
                    .select(
                        "discord_id"
                    )
                    .not(
                        "discord_id",
                        "is",
                        null
                    );

            if (!error) {
                for (
                    const row of
                    data || []
                ) {
                    const id =
                        String(
                            row.discord_id ||
                            ""
                        ).trim();

                    if (
                        /^\d{17,20}$/.test(
                            id
                        )
                    ) {
                        ids.add(id);
                    }
                }
            }
        }
        catch (error) {
            console.error(
                "Personnel DOCS fallback ids error:",
                error.message ||
                error
            );
        }
    }

    return [
        ...ids
    ];
}



// ======================================================
// DEBUG PERSONAL DIICOT — doar utilizator autentificat
// Returnează rolurile proprii și gradul DIICOT detectat.
// Nu expune token-uri sau secrete.
// ======================================================

app.get(
    "/api/personnel-debug",
    requireAuth,
    async (req, res) => {
        if (!BOT_TOKEN || !GUILD_ID) {
            return res.status(500).json({
                error:
                    "Bot/Guild neconfigurat."
            });
        }

        try {
            const userId =
                String(
                    req.session.user.id ||
                    ""
                );

            const member =
                await getDiscordMemberCached(
                    userId
                );

            const roles =
                Array.isArray(
                    member?.roles
                )
                    ? member.roles.map(String)
                    : [];

            const rank =
                resolveHighestDIICOTRoleSafe(
                    roles
                );

            return res.json({
                success: true,
                userId,
                roles,
                matchedDIICOTRole:
                    rank
                        ? {
                            id: rank.id,
                            name: rank.name,
                            level: rank.level
                        }
                        : null,
                configuredDIICOTRoleIds:
                    DIICOT_ROLES.map(
                        role => role.id
                    )
            });
        }
        catch (error) {
            console.error(
                "Personnel Debug Error:",
                error.response?.data ||
                error.message
            );

            return res.status(
                error.response?.status ||
                500
            ).json({
                error:
                    "Debug-ul personalului a eșuat.",
                discordStatus:
                    error.response?.status ||
                    null,
                discordMessage:
                    error.response?.data?.message ||
                    error.message ||
                    null
            });
        }
    }
);



// ======================================================
// HUB MAI — PERSONAL COMBINAT POLITIE + DIICOT
// Date reale din acelasi Discord, folosite de indexul HUB.
// ======================================================
const HUB_DIICOT_ROLES = [
    { id: "1528758226420633746", name: "PROCUROR ȘEF", level: 13 },
    { id: "1528758226420633745", name: "PROCUROR ȘEF ADJUNCT", level: 12 },
    { id: "1528758226420633744", name: "PROCUROR", level: 11 },
    { id: "1528758226416435219", name: "COORDONATOR", level: 10 },
    { id: "1528758226416435217", name: "COMISAR ȘEF", level: 9 },
    { id: "1528758226416435216", name: "COMISAR", level: 8 },
    { id: "1528758226416435215", name: "SUB COMISAR", level: 7 },
    { id: "1528758226416435214", name: "INSPECTOR PRINCIPAL", level: 6 },
    { id: "1528758226416435213", name: "INSPECTOR", level: 5 },
    { id: "1528758226416435211", name: "SUB INSPECTOR", level: 4 },
    { id: "1528758226416435210", name: "AGENT PRINCIPAL", level: 3 },
    { id: "1528758226407919645", name: "AGENT OPERATIV", level: 2 },
    { id: "1528758226407919644", name: "AGENT STAGIAR", level: 1 }
];

function hubHighestRole(roles, defs) {
    const set = new Set((roles || []).map(String));
    return [...defs].sort((a,b) => b.level-a.level).find(r => set.has(String(r.id))) || null;
}
function hubCallsign(nick, department) {
    const s = String(nick || "");
    const d = s.match(/\bD[\s\-_]?0*(\d{1,3})\b/i);
    if (department === "DIICOT" && d) return `D-${String(Number(d[1])).padStart(2,"0")}`;
    const b = s.match(/\[(?:D[\s\-_]?)?0*(\d{1,3})\]|\b(?:ID[\s\-_]?)?0*(\d{3})\b/i);
    if (b) {
        const n = b[1] || b[2];
        return department === "DIICOT" ? `D-${String(Number(n)).padStart(2,"0")}` : String(Number(n)).padStart(3,"0");
    }
    return "";
}

app.get("/api/hub/personnel", requireAuth, async (req, res) => {
    try {
        const members = await fetchAllGuildMembersForPersonnel();
        const police = [];
        const diicot = [];

        for (const member of members || []) {
            const user = member?.user || {};
            if (!user.id || user.bot) continue;
            const roles = Array.isArray(member.roles) ? member.roles.map(String) : [];
            const common = {
                id: String(user.id),
                username: user.username || "Necunoscut",
                displayName: member.nick || user.global_name || user.username || "Necunoscut",
                avatar: discordMemberAvatar(user)
            };

            const pr = hubHighestRole(roles, DIICOT_ROLES);
            if (pr) police.push({
                ...common, department: "POLITIE", rank: pr.name, rankLevel: Number(pr.level || 0),
                callsign: hubCallsign(member.nick || common.displayName, "POLITIE")
            });

            const dr = hubHighestRole(roles, HUB_DIICOT_ROLES);
            if (dr) diicot.push({
                ...common, department: "DIICOT", rank: dr.name, rankLevel: Number(dr.level || 0),
                callsign: hubCallsign(member.nick || common.displayName, "DIICOT")
            });
        }

        const sorter = (a,b) => (b.rankLevel-a.rankLevel) || a.displayName.localeCompare(b.displayName, "ro");
        police.sort(sorter); diicot.sort(sorter);
        res.set("Cache-Control", "private, max-age=30");
        return res.json({ success:true, totals:{police:police.length,diicot:diicot.length,all:police.length+diicot.length}, police, diicot });
    } catch (error) {
        console.error("HUB personnel error:", error?.response?.data || error?.message || error);
        return res.status(500).json({error:"Membrii MAI nu au putut fi încărcați."});
    }
});


// ======================================================
// PERSONAL DIICOT
// ======================================================

app.get(
    "/api/personnel",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !BOT_TOKEN ||
            !GUILD_ID
        ) {
            return res
                .status(500)
                .json({
                    error:
                        "Botul Discord nu este configurat complet."
                });
        }

        try {
            const personnelById =
                new Map();

            // --------------------------------------------------
            // 1. Luăm TOȚI membrii Discord, nu doar primii 1000.
            // --------------------------------------------------
            try {
                const members =
                    await fetchAllGuildMembersForPersonnel();

                for (
                    const member of
                    members
                ) {
                    const mapped =
                        mapDiscordPersonnelMember(
                            member
                        );

                    if (mapped) {
                        personnelById.set(
                            mapped.id,
                            mapped
                        );
                    }
                }
            }
            catch (listError) {
                console.error(
                    "Personnel Discord full-list warning:",
                    listError.response?.data ||
                    listError.message
                );
            }

            // --------------------------------------------------
            // 2. Garantăm verificarea utilizatorului autentificat.
            // Dacă este DIICOT, trebuie să apară chiar dacă listarea
            // mare a Discordului nu l-a returnat.
            // --------------------------------------------------
            const fallbackIds =
                new Set();

            const currentUserId =
                String(
                    req.session.user.id ||
                    ""
                ).trim();

            if (
                /^\d{17,20}$/.test(
                    currentUserId
                )
            ) {
                fallbackIds.add(
                    currentUserId
                );
            }

            // --------------------------------------------------
            // 3. Adăugăm ca fallback și ID-urile deja cunoscute
            // din DOCS. Nu modificăm și nu ștergem nimic din DOCS.
            // --------------------------------------------------
            const docsIds =
                await fetchPersonnelFallbackIds();

            for (
                const id of
                docsIds
            ) {
                fallbackIds.add(
                    String(id)
                );
            }

            // --------------------------------------------------
            // 4. Membrii care lipsesc sunt verificați individual
            // direct în Discord.
            // --------------------------------------------------
            for (
                const userId of
                fallbackIds
            ) {
                if (
                    personnelById.has(
                        userId
                    )
                ) {
                    continue;
                }

                try {
                    const member =
                        await getDiscordMemberCached(
                            userId
                        );

                    const mapped =
                        mapDiscordPersonnelMember(
                            member
                        );

                    if (mapped) {
                        personnelById.set(
                            mapped.id,
                            mapped
                        );
                    }
                }
                catch (memberError) {
                    if (
                        memberError.response?.status !==
                        404
                    ) {
                        console.error(
                            `Personnel member fallback ${userId}:`,
                            memberError.response?.data ||
                            memberError.message
                        );
                    }
                }
            }

            const personnel =
                Array.from(
                    personnelById.values()
                )
                    .sort(
                        (
                            a,
                            b
                        ) => {
                            if (
                                Number(b.rankLevel) !==
                                Number(a.rankLevel)
                            ) {
                                return (
                                    Number(b.rankLevel) -
                                    Number(a.rankLevel)
                                );
                            }

                            return String(
                                a.displayName ||
                                ""
                            ).localeCompare(
                                String(
                                    b.displayName ||
                                    ""
                                ),
                                "ro"
                            );
                        }
                    );

            const grouped =
                DIICOT_ROLES
                    .map(
                        role => ({
                            id:
                                role.id,

                            name:
                                role.name,

                            level:
                                role.level,

                            members:
                                personnel.filter(
                                    member =>
                                        String(
                                            member.rankRoleId
                                        ) ===
                                        String(
                                            role.id
                                        )
                                )
                        })
                    )
                    .filter(
                        group =>
                            group.members.length >
                            0
                    );

            console.log(
                `[PERSONAL DIICOT] ${personnel.length} membri găsiți.`
            );

            return res.json({
                success:
                    true,

                total:
                    personnel.length,

                personnel,

                groups:
                    grouped
            });
        }
        catch (error) {
            console.error(
                "Personnel Discord Error:",
                error.response?.data ||
                error.message ||
                error
            );

            return res
                .status(500)
                .json({
                    error:
                        "Personalul DIICOT nu a putut fi încărcat."
                });
        }
    }
);


// ======================================================
// PROFIL MEMBRU DIICOT
// ======================================================

app.get(
    "/api/profile/:userId",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }


        try {

            const userId =
                String(
                    req.params.userId ||
                    ""
                ).trim();


            if (
                !/^\d{17,20}$/.test(
                    userId
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Discord ID invalid."
                    });
            }


            if (!BOT_TOKEN) {

                return res
                    .status(500)
                    .json({
                        error:
                            "Botul Discord nu este configurat."
                    });
            }


            let member;


            try {

                const response =
                    await axios.get(

                        `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                        {
                            headers: {

                                Authorization:
                                    `Bot ${BOT_TOKEN}`
                            }
                        }
                    );


                member =
                    response.data;

            }

            catch (error) {

                if (
                    error.response?.status ===
                    404
                ) {

                    return res
                        .status(404)
                        .json({
                            error:
                                "Membrul nu a fost găsit pe serverul Discord."
                        });
                }


                throw error;
            }


            const roles =
                Array.isArray(
                    member.roles
                )

                    ? member.roles
                        .map(String)

                    : [];


            const rank =
                getHighestDIICOTRole(
                    roles
                );


            if (!rank) {

                return res
                    .status(403)
                    .json({
                        error:
                            "Acest utilizator nu face parte din structura Poliției."
                    });
            }


            const discordUser =
                member.user ||
                {};


            const username =
                discordUser.username ||
                "Necunoscut";


            const discordDisplayName =
                member.nick ||
                discordUser.global_name ||
                username;


            const avatar =
                discordUser.avatar

                    ? `https://cdn.discordapp.com/avatars/${userId}/${discordUser.avatar}.png?size=256`

                    : `https://cdn.discordapp.com/embed/avatars/${Number(
                        BigInt(
                            userId
                        ) >> 22n
                    ) % 6}.png`;


            const {
                data:
                    profileRow,

                error:
                    profileError
            } =
                await supabase
                    .from(
                        "user_profiles"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "user_id",
                        userId
                    )
                    .maybeSingle();


            if (profileError) {
                throw profileError;
            }


            const displayName =
                profileRow?.display_name ||
                discordDisplayName;


            const duties =
                Array.isArray(
                    profileRow?.duties
                )

                    ? profileRow.duties

                    : [];

            const reports =
                await listB2Reports(
                    userId
                );


            const reportsWithImages =
                reports.filter(
                    report =>
                        Array.isArray(
                            report.images
                        ) &&
                        report.images.length >
                        0
                ).length;


            const promotionEligibility =
                await buildPromotionEligibility(
                    userId,
                    rank,
                    reports
                );


            const reportsForClient =
                await withDirectB2ImageUrlsMany(reports);


            const recentActivity =
                reportsForClient
                    .slice(
                        0,
                        10
                    )
                    .map(
                        report => ({

                            id:
                                report.id,

                            type:
                                report.type,

                            title:
                                report.title,

                            description:
                                report.description,

                            images:
                                report.images,

                            createdAt:
                                report.createdAt,

                            createdAtFormatted:
                                report.createdAtFormatted
                        })
                    );


            const isOwnProfile =
                String(
                    req.session.user.id
                ) ===
                userId;


            const canManage =
                hasPoliceFullAccess(
                    req.session.user
                ) &&
                !isOwnProfile;


            res.json({

                success:
                    true,

                profile: {

                    id:
                        userId,

                    username,

                    displayName,

                    discordDisplayName,

                    avatar,

                    rank:
                        rank.name,

                    rankLevel:
                        rank.level,

                    rankRoleId:
                        rank.id,

                    duties,

                    isOwnProfile,

                    canManage,

                    promotionEligibility,

                    statistics: {

                        totalReports:
                            reports.length,

                        reportsWithImages,

                        lastActivity:
                            reports.length

                                ? reports[0]
                                    .createdAtFormatted

                                : "-"
                    },

                    reports:
                        reportsForClient,

                    recentActivity
                }
            });

        }

        catch (error) {

            console.error(
                "Member Profile Error:",
                error.response?.data ||
                error.message
            );


            res
                .status(500)
                .json({
                    error:
                        "Profilul membrului nu a putut fi încărcat."
                });
        }
    }
);


// ======================================================
// ADMIN - LISTĂ GRADE DISPONIBILE
// CONDUCEREA POLIȚIEI POATE ALEGE GRADELE POLIȚIEI
// ======================================================

app.get(
    "/api/admin/roles",

    requireAdmin,

    (
        req,
        res
    ) => {

        res.json({

            success:
                true,

            roles:
                DIICOT_ROLES.map(
                    role => ({

                        id:
                            role.id,

                        name:
                            role.name,

                        level:
                            role.level
                    })
                )
        });
    }
);


// ======================================================
// ADMIN - SCHIMBARE GRAD MEMBRU
// Endpoint folosit de formularul "GESTIONEAZĂ GRAD"
// ======================================================

app.patch(
    "/api/admin/members/:userId/role",

    requireAdmin,

    async (
        req,
        res
    ) => {

        const userId =
            String(
                req.params.userId ||
                ""
            ).trim();


        const roleId =
            String(
                req.body.roleId ||
                req.body.rankRoleId ||
                ""
            ).trim();


        if (
            !/^\d{17,20}$/.test(
                userId
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Discord ID invalid."
                });
        }


        if (
            userId ===
            String(
                req.session.user.id
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Nu îți poți modifica propriul grad."
                });
        }


        const targetRole =
            DIICOT_ROLES.find(
                role =>
                    role.id ===
                    roleId
            );


        if (!targetRole) {

            return res
                .status(400)
                .json({
                    error:
                        "Gradul selectat nu este valid."
                });
        }


        if (!BOT_TOKEN) {

            return res
                .status(500)
                .json({
                    error:
                        "Botul Discord nu este configurat."
                });
        }


        try {

            const memberResponse =
                await axios.get(

                    `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                    {
                        headers: {

                            Authorization:
                                `Bot ${BOT_TOKEN}`
                        }
                    }
                );


            const member =
                memberResponse.data;


            const currentRoles =
                Array.isArray(
                    member.roles
                )

                    ? member.roles
                        .map(String)

                    : [];


            const diicotRoleIds =
                new Set(
                    DIICOT_ROLES.map(
                        role =>
                            role.id
                    )
                );


            const preservedRoles =
                currentRoles.filter(
                    roleId =>
                        !diicotRoleIds.has(
                            roleId
                        )
                );


            const newRoles = [
                ...new Set([
                    ...preservedRoles,
                    targetRole.id
                ])
            ];


            await axios.patch(

                `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                {
                    roles:
                        newRoles
                },

                {
                    headers: {

                        Authorization:
                            `Bot ${BOT_TOKEN}`,

                        "Content-Type":
                            "application/json"
                    }
                }
            );


            await resetRankProgressNow(
                userId,
                targetRole
            );


            res.json({

                success:
                    true,

                message:
                    `Gradul a fost schimbat în ${targetRole.name}.`,

                rank: {

                    id:
                        targetRole.id,

                    name:
                        targetRole.name,

                    level:
                        targetRole.level
                }
            });

        }

        catch (error) {

            console.error(
                "Admin Change Role Error:",
                error.response?.data ||
                error.message
            );


            if (
                error.response?.status ===
                403
            ) {

                return res
                    .status(403)
                    .json({
                        error:
                            "Discord a refuzat modificarea. Verifică dacă rolul botului este deasupra gradelor DIICOT și deasupra membrului."
                    });
            }


            if (
                error.response?.status ===
                404
            ) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Membrul nu a fost găsit pe Discord."
                    });
            }


            res
                .status(500)
                .json({
                    error:
                        "Gradul nu a putut fi modificat."
                });
        }
    }
);


// ======================================================
// ADMIN - UP / DOWN EXACT UN GRAD
// ======================================================

app.patch(
    "/api/admin/members/:userId/rank-step",

    requireAdmin,

    async (
        req,
        res
    ) => {

        const userId =
            String(
                req.params.userId ||
                ""
            ).trim();


        const direction =
            String(
                req.body.direction ||
                ""
            )
                .trim()
                .toUpperCase();


        if (
            !/^\d{17,20}$/.test(
                userId
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Discord ID invalid."
                });
        }


        if (
            userId ===
            String(
                req.session.user.id
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Nu îți poți modifica propriul grad."
                });
        }


        if (
            ![
                "UP",
                "DOWN"
            ].includes(
                direction
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Direcția trebuie să fie UP sau DOWN."
                });
        }


        if (!BOT_TOKEN) {

            return res
                .status(500)
                .json({
                    error:
                        "Botul Discord nu este configurat."
                });
        }


        try {

            const memberResponse =
                await axios.get(

                    `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                    {
                        headers: {

                            Authorization:
                                `Bot ${BOT_TOKEN}`
                        }
                    }
                );


            const member =
                memberResponse.data;


            const currentRoles =
                Array.isArray(
                    member.roles
                )

                    ? member.roles
                        .map(String)

                    : [];


            const currentRank =
                getHighestDIICOTRole(
                    currentRoles
                );


            if (!currentRank) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Membrul nu are un grad DIICOT."
                    });
            }


            let targetLevel;


            if (
                direction ===
                "UP"
            ) {

                targetLevel =
                    currentRank.level +
                    1;
            }

            else {

                targetLevel =
                    currentRank.level -
                    1;
            }


            const targetRank =
                getDIICOTRoleByLevel(
                    targetLevel
                );


            if (!targetRank) {

                if (
                    direction ===
                    "UP"
                ) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Membrul are deja cel mai mare grad DIICOT."
                        });
                }


                return res
                    .status(400)
                    .json({
                        error:
                            "Membrul are deja cel mai mic grad DIICOT."
                    });
            }


            const diicotRoleIds =
                new Set(
                    DIICOT_ROLES.map(
                        role =>
                            role.id
                    )
                );


            const preservedRoles =
                currentRoles.filter(
                    roleId =>
                        !diicotRoleIds.has(
                            roleId
                        )
                );


            const newRoles = [
                ...new Set([
                    ...preservedRoles,
                    targetRank.id
                ])
            ];


            await axios.patch(

                `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                {
                    roles:
                        newRoles
                },

                {
                    headers: {

                        Authorization:
                            `Bot ${BOT_TOKEN}`,

                        "Content-Type":
                            "application/json"
                    }
                }
            );


            await resetRankProgressNow(
                userId,
                targetRank
            );


            res.json({

                success:
                    true,

                message:
                    direction ===
                    "UP"

                        ? `Membrul a fost avansat la ${targetRank.name}.`

                        : `Membrul a fost retrogradat la ${targetRank.name}.`,

                previousRank: {

                    id:
                        currentRank.id,

                    name:
                        currentRank.name,

                    level:
                        currentRank.level
                },

                rank: {

                    id:
                        targetRank.id,

                    name:
                        targetRank.name,

                    level:
                        targetRank.level
                }
            });

        }

        catch (error) {

            console.error(
                "Admin Rank Step Error:",
                error.response?.data ||
                error.message
            );


            if (
                error.response?.status ===
                403
            ) {

                return res
                    .status(403)
                    .json({
                        error:
                            "Discord a refuzat modificarea gradului. Verifică poziția rolului botului în ierarhia Discord."
                    });
            }


            if (
                error.response?.status ===
                404
            ) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Membrul nu a fost găsit pe Discord."
                    });
            }


            res
                .status(500)
                .json({
                    error:
                        "Gradul membrului nu a putut fi modificat."
                });
        }
    }
);


// ======================================================
// ADMIN - SCHIMBARE CALLSIGN
// Format final: [XXX] Nume
// Exemple:
// 6      -> D-06
// 06     -> D-06
// D-6    -> D-06
// D-06   -> D-06
// [D-06] -> D-06
// ======================================================

app.patch(
    "/api/admin/members/:userId/callsign",

    requireAdmin,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }


        const userId =
            String(
                req.params.userId ||
                ""
            ).trim();


        if (
            !/^\d{17,20}$/.test(
                userId
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Discord ID invalid."
                });
        }


        if (
            userId ===
            String(
                req.session.user.id
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Nu îți poți modifica propriul callsign din această secțiune."
                });
        }


        const callsign =
            normalizeCallsign(
                req.body.callsign
            );


        if (!callsign) {

            return res
                .status(400)
                .json({
                    error:
                        "Callsign invalid. Folosește un call-sign valid din grila Poliției."
                });
        }


        if (!BOT_TOKEN) {

            return res
                .status(500)
                .json({
                    error:
                        "Botul Discord nu este configurat."
                });
        }


        try {

            const memberResponse =
                await axios.get(

                    `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                    {
                        headers: {

                            Authorization:
                                `Bot ${BOT_TOKEN}`
                        }
                    }
                );


            const member =
                memberResponse.data;


            const roles =
                Array.isArray(
                    member.roles
                )

                    ? member.roles
                        .map(String)

                    : [];


            const rank =
                getHighestDIICOTRole(
                    roles
                );


            if (!rank) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Acest utilizator nu face parte din structura Poliției."
                    });
            }


            const discordUser =
                member.user ||
                {};


            const currentName =
                member.nick ||
                discordUser.global_name ||
                discordUser.username ||
                "Membru";


            const cleanName =
                removeExistingCallsign(
                    currentName
                );


            const newNickname =
                buildCallsignNickname(
                    callsign,
                    cleanName
                );


            if (
                newNickname.length >
                32
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Numele rezultat este prea lung pentru Discord."
                    });
            }


            // ==========================================
            // MODIFICARE NICKNAME PE DISCORD
            // ==========================================

            try {

                await axios.patch(

                    `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,

                    {
                        nick:
                            newNickname
                    },

                    {
                        headers: {

                            Authorization:
                                `Bot ${BOT_TOKEN}`,

                            "Content-Type":
                                "application/json"
                        }
                    }
                );

            }

            catch (discordError) {

                console.error(
                    "Callsign Discord Error:",
                    discordError.response?.data ||
                    discordError.message
                );


                if (
                    discordError.response?.status ===
                    403
                ) {

                    return res
                        .status(403)
                        .json({
                            error:
                                "Discord a refuzat schimbarea callsign-ului. Verifică dacă rolul botului este deasupra membrului. Nickname-ul ownerului serverului nu poate fi modificat de bot."
                        });
                }


                throw discordError;
            }


            // ==========================================
            // SALVARE ȘI ÎN PROFILUL SITE-ULUI
            // ==========================================

            const {
                data:
                    currentProfile,

                error:
                    profileFindError
            } =
                await supabase
                    .from(
                        "user_profiles"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "user_id",
                        userId
                    )
                    .maybeSingle();


            if (profileFindError) {

                throw profileFindError;
            }


            const existingDuties =
                Array.isArray(
                    currentProfile?.duties
                )

                    ? currentProfile.duties

                    : [];


            const {
                error:
                    profileSaveError
            } =
                await supabase
                    .from(
                        "user_profiles"
                    )
                    .upsert(
                        {
                            user_id:
                                userId,

                            display_name:
                                newNickname,

                            duties:
                                existingDuties,

                            updated_at:
                                new Date()
                                    .toISOString()
                        },
                        {
                            onConflict:
                                "user_id"
                        }
                    );


            if (profileSaveError) {

                throw profileSaveError;
            }


            res.json({

                success:
                    true,

                message:
                    `Callsign-ul a fost schimbat în ${callsign}.`,

                callsign,

                displayName:
                    newNickname,

                member: {

                    id:
                        userId,

                    username:
                        discordUser.username ||
                        "Necunoscut",

                    displayName:
                        newNickname,

                    rank:
                        rank.name,

                    rankLevel:
                        rank.level
                }
            });

        }

        catch (error) {

            console.error(
                "Admin Callsign Error:",
                error.response?.data ||
                error.message
            );


            if (
                error.response?.status ===
                404
            ) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Membrul nu a fost găsit pe Discord."
                    });
            }


            res
                .status(500)
                .json({
                    error:
                        "Callsign-ul nu a putut fi modificat."
                });
        }
    }
);




// ======================================================
// DOCS — REGISTRU PERSONAL
// Vizibil tuturor membrilor autentificați.
// Editare: COORDONATOR+
// ======================================================

app.get(
    "/api/docs",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "docs_personnel"
                    )
                    .select(
                        "*"
                    )
                    .order(
                        "position",
                        {
                            ascending:
                                true
                        }
                    )
                    .order(
                        "rank_level",
                        {
                            ascending:
                                false
                        }
                    )
                    .order(
                        "full_name",
                        {
                            ascending:
                                true
                        }
                    );

            if (error) {
                throw error;
            }

            res.json({
                success:
                    true,

                canEdit: hasDocsEditAccess(req.session.user),

                rows:
                    (
                        data ||
                        []
                    )
                        .filter(isPoliceDocsRow)
                        .map(
                            mapDocsRow
                        )
            });

        }

        catch (error) {

            console.error(
                "DOCS List Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Registrul DOCS nu a putut fi încărcat."
                });
        }
    }
);


// ======================================================
// DOCS — ADAUGĂ RÂND
// ======================================================

app.post(
    "/api/admin/docs",

    requireDocsEditor,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const now =
                new Date()
                    .toISOString();

            const row = {
                id:
                    crypto.randomUUID(),

                discord_id:
                    null,

                rank:
                    "AGENT STAGIAR DIICOT",

                rank_level:
                    1,

                full_name:
                    String(
                        req.body.fullName ||
                        "Membru nou"
                    )
                        .trim()
                        .slice(
                            0,
                            120
                        ),

                internal_id:
                    "",

                callsign:
                    "",

                active:
                    true,

                last_promotion:
                    null,

                joined_at:
                    null,

                cert_ftp:
                    false,

                cert_radio:
                    false,

                cert_air:
                    false,

                cert_ac: false,

                cert_hs: false,

                cert_moto: false,

                roles:
                    "",

                notes:
                    "",

                penalty_points:
                    0,

                discord:
                    "",

                position:
                    1000,

                created_at:
                    now,

                updated_at:
                    now,

                updated_by_id:
                    String(
                        req.session.user.id
                    ),

                updated_by_name:
                    req.session.user.displayName ||
                    req.session.user.username
            };

            const {
                data:
                    inserted,

                error:
                    insertError
            } =
                await supabase
                    .from(
                        "docs_personnel"
                    )
                    .insert(
                        row
                    )
                    .select()
                    .single();

            if (insertError) {
                throw insertError;
            }

            res
                .status(201)
                .json({
                    success:
                        true,

                    row:
                        mapDocsRow(
                            inserted
                        )
                });

        }

        catch (error) {

            console.error(
                "DOCS Create Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Rândul DOCS nu a putut fi creat."
                });
        }
    }
);


// ======================================================
// DOCS — SALVARE TOATE MODIFICĂRILE
// ======================================================

app.patch(
    "/api/admin/docs/bulk",

    requireDocsEditor,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const rows =
                Array.isArray(
                    req.body?.rows
                )
                    ? req.body.rows
                    : [];

            if (!rows.length) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Nu există modificări de salvat."
                    });
            }

            if (
                rows.length > 150
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Prea multe rânduri într-o singură salvare."
                    });
            }

            const now =
                new Date()
                    .toISOString();

            let updated =
                0;

            for (
                const item
                of rows
            ) {

                const id =
                    String(
                        item.id ||
                        ""
                    ).trim();

                if (!id) {
                    continue;
                }

                const update = {
                    full_name:
                        String(
                            item.fullName ||
                            ""
                        )
                            .trim()
                            .slice(
                                0,
                                120
                            ),

                    internal_id:
                        String(
                            item.internalId ||
                            ""
                        )
                            .trim()
                            .slice(
                                0,
                                40
                            ),

                    callsign:
                        String(
                            item.callsign ||
                            ""
                        )
                            .trim()
                            .slice(
                                0,
                                20
                            ),

                    active:
                        Boolean(
                            item.active
                        ),

                    last_promotion:
                        item.lastPromotion ||
                        null,

                    joined_at:
                        item.joinedAt ||
                        null,

                    cert_ftp:
                        Boolean(
                            item.certFtp
                        ),

                    cert_radio:
                        Boolean(
                            item.certRadio
                        ),

                    cert_air:
                        Boolean(
                            item.certAir
                        ),

                    cert_ac: Boolean(item.certAc),
                    cert_hs: Boolean(item.certHs),
                    cert_moto: Boolean(item.certMoto),

                    roles:
                        String(
                            item.roles ||
                            ""
                        )
                            .trim()
                            .slice(
                                0,
                                160
                            ),

                    discord:
                        String(
                            item.discord ||
                            ""
                        )
                            .trim()
                            .slice(
                                0,
                                120
                            ),

                    updated_at:
                        now,

                    updated_by_id:
                        String(
                            req.session.user.id
                        ),

                    updated_by_name:
                        req.session.user.displayName ||
                        req.session.user.username
                };

                const {
                    error
                } =
                    await supabase
                        .from(
                            "docs_personnel"
                        )
                        .update(
                            update
                        )
                        .eq(
                            "id",
                            id
                        );

                if (error) {
                    throw error;
                }

                updated++;
            }

            const {
                data:
                    refreshedRows,

                error:
                    refreshError
            } =
                await supabase
                    .from(
                        "docs_personnel"
                    )
                    .select(
                        "*"
                    )
                    .order(
                        "position",
                        {
                            ascending:
                                true
                        }
                    )
                    .order(
                        "rank_level",
                        {
                            ascending:
                                false
                        }
                    );

            if (refreshError) {
                throw refreshError;
            }

            res.json({
                success:
                    true,

                updated,

                rows:
                    (
                        refreshedRows ||
                        []
                    )
                        .map(
                            mapDocsRow
                        )
            });

        }

        catch (error) {

            console.error(
                "DOCS Bulk Update Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Modificările DOCS nu au putut fi salvate."
                });
        }
    }
);


// ======================================================
// DOCS — SALVARE RÂND
// ======================================================

app.patch(
    "/api/admin/docs/:id",

    requireDocsEditor,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const id =
                String(
                    req.params.id ||
                    ""
                ).trim();

            const {
                data:
                    existing,

                error:
                    findError
            } =
                await supabase
                    .from(
                        "docs_personnel"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "id",
                        id
                    )
                    .maybeSingle();

            if (findError) {
                throw findError;
            }

            if (!existing) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Înregistrarea DOCS nu a fost găsită."
                    });
            }

            const payload =
                req.body ||
                {};

            const update = {
                full_name:
                    String(
                        payload.fullName ??
                        existing.full_name ??
                        ""
                    )
                        .trim()
                        .slice(
                            0,
                            120
                        ),

                internal_id:
                    String(
                        payload.internalId ??
                        existing.internal_id ??
                        ""
                    )
                        .trim()
                        .slice(
                            0,
                            40
                        ),

                callsign:
                    String(
                        payload.callsign ??
                        existing.callsign ??
                        ""
                    )
                        .trim()
                        .slice(
                            0,
                            20
                        ),

                active:
                    payload.active ===
                    undefined
                        ? Boolean(
                            existing.active
                        )
                        : Boolean(
                            payload.active
                        ),

                last_promotion:
                    payload.lastPromotion ||
                    null,

                joined_at:
                    payload.joinedAt ||
                    null,

                cert_ftp:
                    payload.certFtp ===
                    undefined
                        ? Boolean(
                            existing.cert_ftp
                        )
                        : Boolean(
                            payload.certFtp
                        ),

                cert_radio:
                    payload.certRadio ===
                    undefined
                        ? Boolean(
                            existing.cert_radio
                        )
                        : Boolean(
                            payload.certRadio
                        ),

                cert_air:
                    payload.certAir ===
                    undefined
                        ? Boolean(
                            existing.cert_air
                        )
                        : Boolean(
                            payload.certAir
                        ),

                cert_ac: payload.certAc === undefined ? Boolean(existing.cert_ac) : Boolean(payload.certAc),
                cert_hs: payload.certHs === undefined ? Boolean(existing.cert_hs) : Boolean(payload.certHs),
                cert_moto: payload.certMoto === undefined ? Boolean(existing.cert_moto) : Boolean(payload.certMoto),

                roles:
                    String(
                        payload.roles ??
                        existing.roles ??
                        ""
                    )
                        .trim()
                        .slice(
                            0,
                            160
                        ),

                notes:
                    String(
                        payload.notes ??
                        existing.notes ??
                        ""
                    )
                        .trim()
                        .slice(
                            0,
                            1500
                        ),

                penalty_points:
                    Math.max(
                        0,
                        Math.min(
                            999,
                            Number(
                                payload.penaltyPoints ??
                                existing.penalty_points ??
                                0
                            ) ||
                            0
                        )
                    ),

                discord:
                    String(
                        payload.discord ??
                        existing.discord ??
                        ""
                    )
                        .trim()
                        .slice(
                            0,
                            120
                        ),

                updated_at:
                    new Date()
                        .toISOString(),

                updated_by_id:
                    String(
                        req.session.user.id
                    ),

                updated_by_name:
                    req.session.user.displayName ||
                    req.session.user.username
            };

            const {
                data:
                    updated,

                error:
                    updateError
            } =
                await supabase
                    .from(
                        "docs_personnel"
                    )
                    .update(
                        update
                    )
                    .eq(
                        "id",
                        id
                    )
                    .select()
                    .single();

            if (updateError) {
                throw updateError;
            }

            res.json({
                success:
                    true,

                row:
                    mapDocsRow(
                        updated
                    )
            });

        }

        catch (error) {

            console.error(
                "DOCS Update Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Înregistrarea DOCS nu a putut fi salvată."
                });
        }
    }
);


// ======================================================
// DOCS — ȘTERGERE
// ======================================================

app.delete(
    "/api/admin/docs/:id",

    requireDocsEditor,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const id =
                String(
                    req.params.id ||
                    ""
                ).trim();

            const {
                error
            } =
                await supabase
                    .from(
                        "docs_personnel"
                    )
                    .delete()
                    .eq(
                        "id",
                        id
                    );

            if (error) {
                throw error;
            }

            res.json({
                success:
                    true
            });

        }

        catch (error) {

            console.error(
                "DOCS Delete Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Înregistrarea DOCS nu a putut fi ștearsă."
                });
        }
    }
);


// ======================================================
// DOCS — SINCRONIZARE CU PERSONALUL DISCORD
// OPTIMIZAT PENTRU CLOUDFLARE WORKERS:
// - lista Discord se citește paginat o singură dată;
// - Supabase se citește o singură dată;
// - toate sloturile DOCS se salvează printr-un singur UPSERT;
// - nu mai facem UPDATE separat pentru fiecare membru.
// ======================================================

app.post(
    "/api/admin/docs/sync",
    requireDocsEditor,
    async (req, res) => {
        if (!ensureSupabase(res)) return;
        if (!BOT_TOKEN) {
            return res.status(500).json({
                error: "Botul Discord nu este configurat."
            });
        }

        try {
            const now = new Date().toISOString();
            const editorId = String(req.session.user.id);
            const editorName =
                req.session.user.displayName ||
                req.session.user.username ||
                "Editor DOCS";

            const validNumbers = getAllPoliceDocsCallsigns();

            // 1 singur request Supabase pentru toate rândurile DOCS.
            let { data: rows, error: rowsError } =
                await supabase
                    .from("docs_personnel")
                    .select("*");

            if (rowsError) throw rowsError;
            rows = Array.isArray(rows) ? rows : [];

            // Indexăm doar rândurile Poliției.
            const policeRows = rows.filter(isPoliceDocsRow);
            const byId = new Map(
                policeRows.map(row => [String(row.id), row])
            );
            const byDiscord = new Map();
            const byCallsign = new Map();

            for (const row of policeRows) {
                const discordId = String(row.discord_id || "").trim();
                if (discordId) byDiscord.set(discordId, row);

                const normalized = normalizePoliceCallsign(row.callsign);
                if (normalized) {
                    const list = byCallsign.get(normalized.callsign) || [];
                    list.push(row);
                    byCallsign.set(normalized.callsign, list);
                }
            }

            // Construim grila completă în memorie.
            // 000 are două sloturi, restul câte unul.
            const slotRows = [];
            let created = 0;

            for (const number of validNumbers) {
                const callsign = String(number).padStart(3, "0");
                const rank = getDocsRankForSlot(number);
                const requiredSlots = number === 0 ? 2 : 1;
                const existing = [...(byCallsign.get(callsign) || [])];

                for (let index = 0; index < requiredSlots; index++) {
                    let row = existing[index];

                    if (!row) {
                        row = {
                            id: crypto.randomUUID(),
                            discord_id: null,
                            rank: rank.name,
                            rank_level: rank.level,
                            full_name: "",
                            internal_id: "",
                            callsign,
                            active: false,
                            last_promotion: null,
                            joined_at: null,
                            cert_ftp: false,
                            cert_radio: false,
                            cert_ac: false,
                            cert_hs: false,
                            cert_air: false,
                            cert_moto: false,
                            roles: "",
                            notes: "",
                            penalty_points: 0,
                            discord: "",
                            position: number,
                            created_at: now,
                            updated_at: now,
                            updated_by_id: editorId,
                            updated_by_name: editorName
                        };
                        created++;
                    }

                    slotRows.push({ ...row });
                }
            }

            const slotById = new Map(
                slotRows.map(row => [String(row.id), row])
            );

            // Curățăm ocupanții curenți în MEMORIE.
            // Câmpurile manuale/certificările rămân pe slot.
            for (const row of slotRows) {
                row.discord_id = null;
                row.full_name = "";
                row.active = false;
                row.discord = "";
                row.updated_at = now;
                row.updated_by_id = editorId;
                row.updated_by_name = editorName;
            }

            // Discord: maxim câteva request-uri paginate (1000 membri/pagină),
            // nu câte un request pentru fiecare persoană.
            const members = await getGuildMembersCached({ force: true });

            const policeRoleIds = new Set(
                DIICOT_ROLES.map(role => String(role.id))
            );

            const eligibleMembers = (Array.isArray(members) ? members : [])
                .filter(member => {
                    if (!member?.user?.id || member?.user?.bot) return false;
                    const roles = Array.isArray(member.roles)
                        ? member.roles.map(String)
                        : [];
                    return roles.some(id => policeRoleIds.has(id));
                })
                .sort((a, b) =>
                    Number(
                        GOVERNMENT_RESPONSIBLE_IDS.has(
                            String(b?.user?.id || "")
                        )
                    ) -
                    Number(
                        GOVERNMENT_RESPONSIBLE_IDS.has(
                            String(a?.user?.id || "")
                        )
                    )
                );

            let assigned = 0;
            let moved = 0;
            let cleared = 0;
            const occupiedSlotIds = new Set();

            for (const member of eligibleMembers) {
                const discordId = String(member.user.id);
                const roles = Array.isArray(member.roles)
                    ? member.roles.map(String)
                    : [];

                const displayName =
                    member.nick ||
                    member.user?.global_name ||
                    member.user?.username ||
                    "Membru Poliție";

                const bracket =
                    displayName.match(/\[(?:D-|P-)?(\d{1,3})\]/i);
                const prefix =
                    displayName.match(
                        /^(?:D-|P-)?(\d{1,3})(?:\s*[-|•:]\s*|\s+)/i
                    );

                const isGovernmentResponsible =
                    GOVERNMENT_RESPONSIBLE_IDS.has(discordId);

                const oldRow = byDiscord.get(discordId);

                const cs = isGovernmentResponsible
                    ? normalizePoliceCallsign("000")
                    : (
                        normalizePoliceCallsign(
                            bracket?.[1] ||
                            prefix?.[1] ||
                            ""
                        ) ||
                        normalizePoliceCallsign(oldRow?.callsign || "")
                    );

                if (!cs) continue;
                if (cs.callsign === "000" && !isGovernmentResponsible) {
                    continue;
                }

                const candidates = slotRows.filter(row =>
                    String(row.callsign) === String(cs.callsign) &&
                    !occupiedSlotIds.has(String(row.id))
                );

                if (!candidates.length) continue;

                // Dacă utilizatorul era deja pe unul dintre sloturile
                // callsign-ului, îl păstrăm pe acela; altfel primul liber.
                let target =
                    candidates.find(row =>
                        String(row.id) === String(oldRow?.id || "")
                    ) ||
                    candidates[0];

                const source = oldRow || {};
                const oldCallsign =
                    normalizePoliceCallsign(source.callsign)?.callsign || "";

                if (oldCallsign && oldCallsign !== cs.callsign) moved++;

                const cleanName = displayName
                    .replace(/\[(?:D-|P-)?\d{1,3}\]/ig, "")
                    .replace(
                        /^(?:D-|P-)?\d{1,3}(?:\s*[-|•:]\s*|\s+)/i,
                        ""
                    )
                    .trim();

                target.discord_id = discordId;
                target.rank = cs.rank.name;
                target.rank_level = cs.rank.level;
                target.full_name =
                    cleanName ||
                    member.user?.username ||
                    "Membru Poliție";
                target.internal_id =
                    source.internal_id || target.internal_id || "";
                target.callsign = cs.callsign;
                target.active = true;
                target.last_promotion =
                    source.last_promotion || target.last_promotion || null;
                target.joined_at =
                    source.joined_at ||
                    target.joined_at ||
                    member.joined_at ||
                    now;

                // Păstrăm datele manuale ale persoanei dacă existau.
                target.cert_ftp = Boolean(
                    source.cert_ftp ?? target.cert_ftp
                );
                target.cert_radio = Boolean(
                    source.cert_radio ?? target.cert_radio
                );
                target.cert_ac = Boolean(
                    source.cert_ac ?? target.cert_ac
                );
                target.cert_hs = Boolean(
                    source.cert_hs ?? target.cert_hs
                );
                target.cert_air = Boolean(
                    source.cert_air ?? target.cert_air
                );
                target.cert_moto = Boolean(
                    source.cert_moto ?? target.cert_moto
                );
                target.roles = source.roles || target.roles || "";
                target.notes = source.notes || target.notes || "";
                target.penalty_points =
                    Number(
                        source.penalty_points ??
                        target.penalty_points ??
                        0
                    );
                target.discord =
                    member.user?.username
                        ? `@${member.user.username}`
                        : discordId;
                target.position = cs.number;
                target.updated_at = now;
                target.updated_by_id = editorId;
                target.updated_by_name = editorName;

                occupiedSlotIds.add(String(target.id));
                assigned++;
            }

            // Numărăm persoanele vechi care nu mai sunt în Poliție / nu mai
            // au un callsign valid și care au fost eliberate din grilă.
            for (const oldRow of policeRows) {
                const oldDiscordId = String(oldRow.discord_id || "");
                if (!oldDiscordId) continue;

                const stillPresent = slotRows.some(row =>
                    String(row.discord_id || "") === oldDiscordId
                );

                if (!stillPresent) cleared++;
            }

            // IMPORTANT: un singur subrequest Supabase pentru toate sloturile.
            const payload = slotRows.map(row => ({
                id: row.id,
                discord_id: row.discord_id || null,
                rank: row.rank,
                rank_level: Number(row.rank_level || 0),
                full_name: row.full_name || "",
                internal_id: row.internal_id || "",
                callsign: row.callsign,
                active: Boolean(row.active),
                last_promotion: row.last_promotion || null,
                joined_at: row.joined_at || null,
                cert_ftp: Boolean(row.cert_ftp),
                cert_radio: Boolean(row.cert_radio),
                cert_ac: Boolean(row.cert_ac),
                cert_hs: Boolean(row.cert_hs),
                cert_air: Boolean(row.cert_air),
                cert_moto: Boolean(row.cert_moto),
                roles: row.roles || "",
                notes: row.notes || "",
                penalty_points: Number(row.penalty_points || 0),
                discord: row.discord || "",
                position: Number(row.position || 0),
                created_at: row.created_at || now,
                updated_at: now,
                updated_by_id: editorId,
                updated_by_name: editorName
            }));

            const { error: saveError } =
                await supabase
                    .from("docs_personnel")
                    .upsert(payload, {
                        onConflict: "id"
                    });

            if (saveError) throw saveError;

            return res.json({
                success: true,
                created,
                assigned,
                moved,
                cleared,
                totalSlots: slotRows.length,
                discordMembersRead: eligibleMembers.length,
                optimized: true
            });
        }
        catch (error) {
            console.error(
                "DOCS Sync Error:",
                error?.response?.data ||
                error?.message ||
                error
            );

            return res.status(500).json({
                error:
                    `Personalul DOCS Poliție nu a putut fi sincronizat: ` +
                    `${error?.message || "eroare necunoscută"}`
            });
        }
    }
);


// ======================================================

app.post(
    "/api/admin/docs/sync",
    requireDocsEditor,
    async (req, res) => {
        if (!ensureSupabase(res)) return;
        if (!BOT_TOKEN) return res.status(500).json({ error: "Botul Discord nu este configurat." });

        try {
            const now = new Date().toISOString();
            const editorId = String(req.session.user.id);
            const editorName = req.session.user.displayName || req.session.user.username;
            const validNumbers = getAllPoliceDocsCallsigns();

            let { data: rows, error } = await supabase.from("docs_personnel").select("*");
            if (error) throw error;
            rows = rows || [];

            // Păstrăm doar sloturile Poliției. Rândurile DIICOT din aceeași
            // bază de date nu sunt afișate și nu sunt modificate.
            const byCallsign = new Map();
            for (const row of rows) {
                if (!isPoliceDocsRow(row)) continue;
                const cs = normalizePoliceCallsign(row.callsign);
                if (!cs) continue;
                const list = byCallsign.get(cs.callsign) || [];
                list.push(row);
                byCallsign.set(cs.callsign, list);
            }

            const missing = [];
            for (const number of validNumbers) {
                const callsign = String(number).padStart(3, "0");
                const rank = getDocsRankForSlot(number);
                const requiredSlots = number === 0 ? 2 : 1;
                const existingSlots = (byCallsign.get(callsign) || []).length;

                for (let index = existingSlots; index < requiredSlots; index++) {
                    missing.push({
                        id: crypto.randomUUID(), discord_id: null, rank: rank.name, rank_level: rank.level,
                        full_name: "", internal_id: "", callsign, active: false, last_promotion: null, joined_at: null,
                        cert_ftp: false, cert_radio: false, cert_ac: false, cert_hs: false, cert_air: false, cert_moto: false,
                        roles: "", notes: "", penalty_points: 0, discord: "", position: number,
                        created_at: now, updated_at: now, updated_by_id: editorId, updated_by_name: editorName
                    });
                }
            }
            if (missing.length) {
                const r = await supabase.from("docs_personnel").insert(missing);
                if (r.error) throw r.error;
            }

            ({ data: rows, error } = await supabase.from("docs_personnel").select("*"));
            if (error) throw error;
            rows = rows || [];

            // Normalizează poziția/gradul sloturilor fără să mute oamenii arbitrar.
            for (const row of rows) {
                if (!isPoliceDocsRow(row)) continue;
                const cs = normalizePoliceCallsign(row.callsign);
                if (!cs) continue;
                const r = await supabase.from("docs_personnel").update({
                    callsign: cs.callsign, rank: cs.rank.name, rank_level: cs.rank.level, position: cs.number, updated_at: now
                }).eq("id", row.id);
                if (r.error) throw r.error;
            }

            // Callsign-ul 000 este rezervat exclusiv celor doi Responsabili
            // Guvernamentale. Orice asociere veche greșită este eliberată.
            ({ data: rows, error } = await supabase.from("docs_personnel").select("*"));
            if (error) throw error;
            rows = rows || [];

            for (const row of rows) {
                const cs = normalizePoliceCallsign(row.callsign);
                const discordId = String(row.discord_id || "");
                if (
                    isPoliceDocsRow(row) &&
                    cs?.callsign === "000" &&
                    discordId &&
                    !GOVERNMENT_RESPONSIBLE_IDS.has(discordId)
                ) {
                    const clearedRow = await supabase.from("docs_personnel").update({
                        discord_id: null, full_name: "", internal_id: "", active: false,
                        last_promotion: null, joined_at: null, discord: "", roles: "", notes: "",
                        penalty_points: 0, updated_at: now
                    }).eq("id", row.id);
                    if (clearedRow.error) throw clearedRow.error;
                }
            }

            const members = await getGuildMembersCached({ force: true });
            const policeRoleIds = new Set([
                "1528758226437275791","1528758226437275788","1528758226437275787","1528758226437275786",
                "1528758226428891368","1528758226428891366","1528758226428891365","1528758226428891364",
                "1528758226428891363","1528758226428891362","1528758226428891361","1528758226428891360",
                "1528758226428891359","1528758226420633752","1528758226420633750"
            ]);

            let assigned = 0, moved = 0, cleared = 0;
            const orderedMembers = [...members].sort((a, b) =>
                Number(GOVERNMENT_RESPONSIBLE_IDS.has(String(b?.user?.id || ""))) -
                Number(GOVERNMENT_RESPONSIBLE_IDS.has(String(a?.user?.id || "")))
            );

            for (const member of orderedMembers) {
                if (member?.user?.bot) continue;
                const roles = (member.roles || []).map(String);
                if (!roles.some(id => policeRoleIds.has(id))) continue;
                const discordId = String(member.user?.id || "");
                if (!discordId) continue;
                const displayName = member.nick || member.user?.global_name || member.user?.username || "Membru Poliție";
                const bracket = displayName.match(/\[(?:D-|P-)?(\d{1,3})\]/i);
                const prefix = displayName.match(/^(?:D-|P-)?(\d{1,3})(?:\s*[-|•:]\s*|\s+)/i);
                const isGovernmentResponsible =
                    GOVERNMENT_RESPONSIBLE_IDS.has(discordId);
                const existingByDiscord = (rows || []).find(row =>
                    isPoliceDocsRow(row) &&
                    String(row.discord_id || "") === discordId
                );
                const cs = isGovernmentResponsible
                    ? normalizePoliceCallsign("000")
                    : (
                        normalizePoliceCallsign(bracket?.[1] || prefix?.[1] || "") ||
                        normalizePoliceCallsign(existingByDiscord?.callsign || "")
                    );
                if (!cs) continue;
                if (cs.callsign === "000" && !isGovernmentResponsible) continue;

                ({ data: rows, error } = await supabase.from("docs_personnel").select("*"));
                if (error) throw error;
                const candidates = (rows || []).filter(r =>
                    isPoliceDocsRow(r) &&
                    normalizePoliceCallsign(r.callsign)?.callsign === cs.callsign
                );
                const target =
                    candidates.find(r => String(r.discord_id || "") === discordId) ||
                    candidates.find(r => !String(r.discord_id || "").trim());
                if (!target) continue;
                const old = (rows || []).find(r => isPoliceDocsRow(r) && String(r.discord_id || "") === discordId && r.id !== target.id);

                // Dacă omul și-a schimbat callsign-ul pe Discord, eliberăm vechiul slot, dar păstrăm callsign-ul/rândul.
                let source = target;
                if (old) {
                    source = {
                        ...target,
                        internal_id: target.internal_id || old.internal_id || "",
                        last_promotion: target.last_promotion || old.last_promotion || null,
                        joined_at: target.joined_at || old.joined_at || null,
                        cert_ftp: Boolean(target.cert_ftp || old.cert_ftp), cert_radio: Boolean(target.cert_radio || old.cert_radio),
                        cert_ac: Boolean(target.cert_ac || old.cert_ac), cert_hs: Boolean(target.cert_hs || old.cert_hs),
                        cert_air: Boolean(target.cert_air || old.cert_air), cert_moto: Boolean(target.cert_moto || old.cert_moto),
                        roles: target.roles || old.roles || "", notes: target.notes || old.notes || "",
                        penalty_points: Number(target.penalty_points || old.penalty_points || 0)
                    };
                    const oldCs = normalizePoliceCallsign(old.callsign);
                    const oldRank = oldCs ? getDocsRankForSlot(oldCs.number) : { name: old.rank || "", level: old.rank_level || 0 };
                    const r = await supabase.from("docs_personnel").update({
                        discord_id: null, full_name: "", internal_id: "", active: false,
                        last_promotion: null, joined_at: null, cert_ftp: false, cert_radio: false, cert_ac: false, cert_hs: false, cert_air: false, cert_moto: false,
                        roles: "", notes: "", penalty_points: 0, discord: "", rank: oldRank.name, rank_level: oldRank.level, updated_at: now
                    }).eq("id", old.id);
                    if (r.error) throw r.error;
                    moved++; cleared++;
                }

                const cleanName = displayName
                    .replace(/\[(?:D-|P-)?\d{1,3}\]/ig, "")
                    .replace(/^(?:D-|P-)?\d{1,3}(?:\s*[-|•:]\s*|\s+)/i, "")
                    .trim();
                const r = await supabase.from("docs_personnel").update({
                    discord_id: discordId, rank: cs.rank.name, rank_level: cs.rank.level, full_name: cleanName || member.user?.username || "Membru Poliție",
                    internal_id: source.internal_id || "", callsign: cs.callsign, active: true, last_promotion: source.last_promotion || null,
                    joined_at: source.joined_at || member.joined_at || now,
                    cert_ftp: Boolean(source.cert_ftp), cert_radio: Boolean(source.cert_radio), cert_ac: Boolean(source.cert_ac), cert_hs: Boolean(source.cert_hs),
                    cert_air: Boolean(source.cert_air), cert_moto: Boolean(source.cert_moto), roles: source.roles || "", notes: source.notes || "",
                    penalty_points: Number(source.penalty_points || 0), discord: member.user?.username ? `@${member.user.username}` : discordId,
                    position: cs.number, updated_at: now, updated_by_id: editorId, updated_by_name: editorName
                }).eq("id", target.id);
                if (r.error) throw r.error;
                assigned++;
            }

            return res.json({ success: true, created: missing.length, assigned, moved, cleared, totalSlots: validNumbers.length + 1 });
        } catch (error) {
            console.error("DOCS Sync Error:", error.response?.data || error.message || error);
            return res.status(500).json({ error: `Personalul DOCS Poliție nu a putut fi sincronizat: ${error?.message || "eroare necunoscută"}` });
        }
    }
);


// ======================================================
// ACTIVITĂȚI — CERERI CALLSIGN
// ======================================================

function mapCallsignRequest(row) {
    if (!row) return null;

    return {
        id: row.id,
        authorId: row.author_id,
        authorName: row.author_name,
        authorUsername: row.author_username,
        authorRank: row.author_rank,
        gameId: row.game_id || "",
        gameName: row.game_name || "",
        note: row.note || "",
        status: row.status || "PENDING",
        assignedCallsign: row.assigned_callsign || null,
        decidedById: row.decided_by_id || null,
        decidedByName: row.decided_by_name || null,
        decidedByRank: row.decided_by_rank || null,
        decisionNote: row.decision_note || "",
        createdAt: row.created_at,
        decidedAt: row.decided_at
    };
}


async function sendDiscordDM(userId, content) {
    if (!BOT_TOKEN) {
        throw new Error("Botul Discord nu este configurat.");
    }

    const dmResponse = await axios.post(
        "https://discord.com/api/v10/users/@me/channels",
        {
            recipient_id: String(userId)
        },
        {
            headers: {
                Authorization: `Bot ${BOT_TOKEN}`,
                "Content-Type": "application/json"
            }
        }
    );

    await axios.post(
        `https://discord.com/api/v10/channels/${dmResponse.data.id}/messages`,
        {
            content: String(content).slice(0, 1900),
            allowed_mentions: {
                parse: []
            }
        },
        {
            headers: {
                Authorization: `Bot ${BOT_TOKEN}`,
                "Content-Type": "application/json"
            }
        }
    );
}


function callsignLogStatusLabel(status) {
    if (status === "APPROVED") return "APROBATĂ";
    if (status === "REJECTED") return "RESPINSĂ";
    return "ÎN AȘTEPTARE";
}


function buildCallsignLogEmbed(requestRow, {
    status = "PENDING",
    callsign = null,
    decidedByName = null,
    decidedByRank = null,
    decisionNote = null
} = {}) {
    const color =
        status === "APPROVED"
            ? 0x57F287
            : status === "REJECTED"
                ? 0xED4245
                : 0xF0B232;

    const fields = [
        {
            name: "Membru",
            value:
                `${requestRow.author_name || "Membru"}\n` +
                `<@${requestRow.author_id}>`,
            inline: true
        },
        {
            name: "Grad",
            value: String(requestRow.author_rank || "MEMBRU").slice(0, 1024),
            inline: true
        },
        {
            name: "Status",
            value: callsignLogStatusLabel(status),
            inline: true
        },
        {
            name: "Date din joc",
            value:
                `**ID:** ${requestRow.game_id || "-"}\n` +
                `**Nume:** ${requestRow.game_name || "-"}`,
            inline: false
        }
    ];

    if (requestRow.note) {
        fields.push({
            name: "Mențiune",
            value: String(requestRow.note).slice(0, 1024),
            inline: false
        });
    }

    if (status === "APPROVED") {
        fields.push({
            name: "Callsign acordat",
            value: `**${callsign || requestRow.assigned_callsign || "-"}**`,
            inline: true
        });
    }

    if (status !== "PENDING") {
        fields.push({
            name: "Soluționat de",
            value:
                `${decidedByName || "Conducerea DIICOT"}` +
                `${decidedByRank ? `\n${decidedByRank}` : ""}`,
            inline: true
        });

        if (decisionNote) {
            fields.push({
                name: status === "REJECTED" ? "Motiv" : "Observație",
                value: String(decisionNote).slice(0, 1024),
                inline: false
            });
        }
    }

    return {
        title:
            status === "APPROVED"
                ? "✅ Cerere Callsign — Aprobată"
                : status === "REJECTED"
                    ? "❌ Cerere Callsign — Respinsă"
                    : "📟 Cerere nouă de Callsign",
        color,
        fields,
        footer: {
            text: `DIICOT • Cerere ${requestRow.id}`
        },
        timestamp:
            status === "PENDING"
                ? (requestRow.created_at || new Date().toISOString())
                : new Date().toISOString()
    };
}


function callsignReviewUrl(requestId) {
    const base = String(CALLSIGN_DASHBOARD_URL || "").replace(/\/+$/, "");
    const separator = base.includes("?") ? "&" : "?";
    return `${base}${separator}callsignRequest=${encodeURIComponent(requestId)}`;
}


async function sendCallsignLogMessage(requestRow) {
    if (!BOT_TOKEN || !CALLSIGN_LOG_CHANNEL_ID) {
        throw new Error("Botul Discord sau canalul de logs callsign nu este configurat.");
    }

    const response = await axios.post(
        `https://discord.com/api/v10/channels/${CALLSIGN_LOG_CHANNEL_ID}/messages`,
        {
            embeds: [
                buildCallsignLogEmbed(requestRow, {
                    status: "PENDING"
                })
            ],
            components: [
                {
                    type: 1,
                    components: [
                        {
                            type: 2,
                            style: 5,
                            label: "VERIFICĂ CALLSIGN",
                            url: callsignReviewUrl(requestRow.id)
                        }
                    ]
                }
            ],
            allowed_mentions: {
                parse: []
            }
        },
        {
            headers: {
                Authorization: `Bot ${BOT_TOKEN}`,
                "Content-Type": "application/json"
            }
        }
    );

    return response.data;
}


async function updateCallsignLogMessage(requestRow, {
    status,
    callsign = null,
    decidedByName = null,
    decidedByRank = null,
    decisionNote = null
}) {
    const messageId = String(requestRow.discord_log_message_id || "").trim();
    const channelId =
        String(requestRow.discord_log_channel_id || CALLSIGN_LOG_CHANNEL_ID || "").trim();

    if (!BOT_TOKEN || !messageId || !channelId) {
        return false;
    }

    await axios.patch(
        `https://discord.com/api/v10/channels/${channelId}/messages/${messageId}`,
        {
            embeds: [
                buildCallsignLogEmbed(requestRow, {
                    status,
                    callsign,
                    decidedByName,
                    decidedByRank,
                    decisionNote
                })
            ],
            components: [],
            allowed_mentions: {
                parse: []
            }
        },
        {
            headers: {
                Authorization: `Bot ${BOT_TOKEN}`,
                "Content-Type": "application/json"
            }
        }
    );

    return true;
}


// ======================================================
// SANCȚIUNI — ROLURI FW + CANAL INFO-SANCTIUNI
// ======================================================

const FACTION_WARN_ROLE_IDS = {
    1: "1528758226319966342",
    2: "1528758226319966343",
    3: "1528758226319966344",
    4: "1528758226319966345",
    5: "1528758226319966346"
};

const INFO_SANCTIONS_CHANNEL_ID = "1549734760702812300";
const BLACKLIST_CHANNEL_ID = "1542990688814243981";

async function syncFactionWarnDiscordRole(userId, level) {
    if (!BOT_TOKEN || !GUILD_ID) {
        throw new Error("Botul Discord sau serverul Discord nu este configurat.");
    }

    const desiredLevel = Math.max(0, Math.min(5, Number(level) || 0));
    const desiredRoleId = desiredLevel > 0 ? FACTION_WARN_ROLE_IDS[desiredLevel] : null;

    const memberResponse = await axios.get(
        `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,
        {
            headers: {
                Authorization: `Bot ${BOT_TOKEN}`
            }
        }
    );

    const currentRoles = new Set((memberResponse.data?.roles || []).map(String));
    const allFwRoleIds = Object.values(FACTION_WARN_ROLE_IDS);

    // Scoate orice rol FW vechi, cu excepția celui care trebuie păstrat.
    for (const roleId of allFwRoleIds) {
        if (currentRoles.has(roleId) && roleId !== desiredRoleId) {
            await axios.delete(
                `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}/roles/${roleId}`,
                {
                    headers: {
                        Authorization: `Bot ${BOT_TOKEN}`
                    }
                }
            );
        }
    }

    // Aplică rolul corespunzător nivelului curent.
    if (desiredRoleId && !currentRoles.has(desiredRoleId)) {
        await axios.put(
            `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}/roles/${desiredRoleId}`,
            {},
            {
                headers: {
                    Authorization: `Bot ${BOT_TOKEN}`,
                    "Content-Type": "application/json"
                }
            }
        );
    }

    return {
        level: desiredLevel,
        roleId: desiredRoleId
    };
}


async function sendSanctionRevokedInfoMessage({
    targetId,
    targetName,
    type,
    fwCount,
    activeFw,
    reason,
    removedByName,
    removedByRank
}) {
    if (!BOT_TOKEN || !INFO_SANCTIONS_CHANNEL_ID) {
        throw new Error("Canalul info-sanctiuni sau botul Discord nu este configurat.");
    }

    const isOut = type === "OUT";

    const embed = {
        title: isOut
            ? "🟢 Sancțiune retrasă — OUT"
            : "🟢 Faction Warn retras",
        color: 0x57F287,
        fields: [
            {
                name: "Membru",
                value: `${targetName || "Necunoscut"}\n<@${targetId}>`,
                inline: true
            },
            {
                name: "Sancțiune retrasă",
                value: isOut ? "OUT" : `${Number(fwCount || 0)} FW`,
                inline: true
            },
            {
                name: "Situație FW rămasă",
                value: `${Number(activeFw || 0)}/5 FW`,
                inline: true
            },
            {
                name: "Motiv sancțiune inițială",
                value: String(reason || "-").slice(0, 1000),
                inline: false
            },
            {
                name: "Retrasă de",
                value: `${removedByName || "Conducerea Poliției"}\n${removedByRank || "CONDUCERE POLIȚIA ROMÂNĂ"}`,
                inline: true
            }
        ],
        footer: {
            text: "Poliția Română • Centru de Comandă • Rush România"
        },
        timestamp: new Date().toISOString()
    };

    await axios.post(
        `https://discord.com/api/v10/channels/${INFO_SANCTIONS_CHANNEL_ID}/messages`,
        {
            embeds: [embed],
            allowed_mentions: { parse: [] }
        },
        {
            headers: {
                Authorization: `Bot ${BOT_TOKEN}`,
                "Content-Type": "application/json"
            }
        }
    );
}


async function sendSanctionInfoMessage({
    targetId,
    targetName,
    type,
    fwCount,
    activeFw,
    reason,
    appliedByName,
    appliedByRank
}) {
    if (!BOT_TOKEN || !INFO_SANCTIONS_CHANNEL_ID) {
        throw new Error("Canalul info-sanctiuni sau botul Discord nu este configurat.");
    }

    const isOut = type === "OUT";
    const displayedLevel = isOut ? 5 : activeFw;
    const title = isOut
        ? "🔴 Sancțiune aplicată — OUT"
        : `🟡 Sancțiune aplicată — Faction Warn ${displayedLevel}/5`;

    const embed = {
        title,
        color: isOut ? 0xED4245 : 0xF0B232,
        fields: [
            {
                name: "Membru",
                value: `${targetName || "Necunoscut"}\n<@${targetId}>`,
                inline: true
            },
            {
                name: "Tip sancțiune",
                value: isOut ? "OUT" : `FACTION WARN (+${fwCount})`,
                inline: true
            },
            {
                name: "Situație FW",
                value: isOut ? "5/5 — OUT" : `${activeFw}/5 FW`,
                inline: true
            },
            {
                name: "Motiv",
                value: String(reason || "-" ).slice(0, 1000),
                inline: false
            },
            {
                name: "Aplicată de",
                value: `${appliedByName || "Conducerea Poliției"}\n${appliedByRank || "CONDUCERE POLIȚIA ROMÂNĂ"}`,
                inline: true
            }
        ],
        footer: {
            text: "Poliția Română • Sistem sancțiuni"
        },
        timestamp: new Date().toISOString()
    };

    await axios.post(
        `https://discord.com/api/v10/channels/${INFO_SANCTIONS_CHANNEL_ID}/messages`,
        {
            embeds: [embed],
            allowed_mentions: {
                parse: []
            }
        },
        {
            headers: {
                Authorization: `Bot ${BOT_TOKEN}`,
                "Content-Type": "application/json"
            }
        }
    );
}


// Toți membrii autentificați își pot vedea cererile.
app.get(
    "/api/callsign-requests/me",
    requireAuth,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        try {
            const { data, error } =
                await supabase
                    .from("callsign_requests")
                    .select("*")
                    .eq("author_id", String(req.session.user.id))
                    .order("created_at", { ascending: false })
                    .limit(50);

            if (error) throw error;

            return res.json({
                requests: (data || []).map(mapCallsignRequest)
            });
        }
        catch (error) {
            console.error("Callsign Requests Me Error:", error);
            return res.status(500).json({
                error: "Cererile de callsign nu au putut fi încărcate."
            });
        }
    }
);


// Orice membru autentificat poate depune o cerere.
// Maximum o cerere PENDING simultan.
app.post(
    "/api/callsign-requests",
    requireAuth,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        try {
            const gameId =
                String(req.body?.gameId || "")
                    .trim()
                    .slice(0, 20);

            const gameName =
                String(req.body?.gameName || "")
                    .trim()
                    .slice(0, 80);

            const note =
                String(req.body?.note || "")
                    .trim()
                    .slice(0, 700);

            if (!gameId || !gameName) {
                return res.status(400).json({
                    error: "Completează ID-ul din joc și numele după joc."
                });
            }

            if (!/^\d{1,20}$/.test(gameId)) {
                return res.status(400).json({
                    error: "ID-ul din joc trebuie să conțină doar cifre."
                });
            }

            const { data: pending, error: pendingError } =
                await supabase
                    .from("callsign_requests")
                    .select("id")
                    .eq("author_id", String(req.session.user.id))
                    .eq("status", "PENDING")
                    .limit(1);

            if (pendingError) throw pendingError;

            if ((pending || []).length) {
                return res.status(409).json({
                    error: "Ai deja o cerere de callsign în așteptare."
                });
            }

            const row = {
                id: crypto.randomUUID(),
                author_id: String(req.session.user.id),
                author_name:
                    req.session.user.displayName ||
                    req.session.user.username ||
                    "Membru",
                author_username:
                    req.session.user.username || "",
                author_rank:
                    req.session.user.rank || "",
                game_id: gameId,
                game_name: gameName,
                note,
                status: "PENDING"
            };

            const { data, error } =
                await supabase
                    .from("callsign_requests")
                    .insert(row)
                    .select("*")
                    .single();

            if (error) throw error;

            let discordLogSent = false;

            try {
                const logMessage =
                    await sendCallsignLogMessage(data);

                if (logMessage?.id) {
                    const { error: logStoreError } =
                        await supabase
                            .from("callsign_requests")
                            .update({
                                discord_log_message_id:
                                    String(logMessage.id),
                                discord_log_channel_id:
                                    CALLSIGN_LOG_CHANNEL_ID,
                                discord_log_sent_at:
                                    new Date().toISOString()
                            })
                            .eq("id", data.id);

                    if (logStoreError) {
                        console.warn(
                            "Callsign Log Store Warning:",
                            logStoreError
                        );
                    }
                    else {
                        data.discord_log_message_id =
                            String(logMessage.id);
                        data.discord_log_channel_id =
                            CALLSIGN_LOG_CHANNEL_ID;
                        discordLogSent = true;
                    }
                }
            }
            catch (logError) {
                console.warn(
                    "Callsign Request Log Warning:",
                    logError.response?.data || logError.message
                );
            }

            return res.status(201).json({
                success: true,
                request: mapCallsignRequest(data),
                discordLogSent
            });
        }
        catch (error) {
            console.error("Callsign Request Create Error:", error);
            return res.status(500).json({
                error: "Cererea de callsign nu a putut fi trimisă."
            });
        }
    }
);


// Conducerea Poliției vede toate cererile.
app.get(
    "/api/admin/callsign-requests",
    requireAdmin,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        try {
            const { data, error } =
                await supabase
                    .from("callsign_requests")
                    .select("*")
                    .order("created_at", { ascending: false })
                    .limit(300);

            if (error) throw error;

            return res.json({
                requests: (data || []).map(mapCallsignRequest)
            });
        }
        catch (error) {
            console.error("Admin Callsign Requests Error:", error);
            return res.status(500).json({
                error: "Cererile de callsign nu au putut fi încărcate."
            });
        }
    }
);


// Conducerea Poliției aprobă și acordă callsign-ul.
// Se actualizează Discord nickname + profilul site-ului. DOCS rămâne complet separat.
app.patch(
    "/api/admin/callsign-requests/:id/approve",
    requireAdmin,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        const requestId = String(req.params.id || "").trim();
        const callsign = normalizeCallsign(req.body?.callsign);

        if (!requestId || !callsign) {
            return res.status(400).json({
                error: "Cererea sau callsign-ul este invalid. Folosește un call-sign valid din grila Poliției."
            });
        }

        try {
            const { data: requestRow, error: requestError } =
                await supabase
                    .from("callsign_requests")
                    .select("*")
                    .eq("id", requestId)
                    .maybeSingle();

            if (requestError) throw requestError;

            if (!requestRow) {
                return res.status(404).json({
                    error: "Cererea nu a fost găsită."
                });
            }

            if (requestRow.status !== "PENDING") {
                return res.status(409).json({
                    error: "Această cerere a fost deja soluționată."
                });
            }

            const targetId = String(requestRow.author_id);

            // Cererile de callsign nu citesc și nu modifică DOCS-ul.

            if (!BOT_TOKEN) {
                return res.status(500).json({
                    error: "Botul Discord nu este configurat."
                });
            }

            const memberResponse =
                await axios.get(
                    `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${targetId}`,
                    {
                        headers: {
                            Authorization: `Bot ${BOT_TOKEN}`
                        }
                    }
                );

            const member = memberResponse.data;
            const roles =
                Array.isArray(member.roles)
                    ? member.roles.map(String)
                    : [];

            const rank = getHighestDIICOTRole(roles);

            if (!rank) {
                return res.status(400).json({
                    error: "Membrul nu mai face parte din structura Poliției."
                });
            }

            const discordUser = member.user || {};
            const currentName =
                member.nick ||
                discordUser.global_name ||
                discordUser.username ||
                requestRow.author_name ||
                "Membru";

            const newNickname =
                buildCallsignNickname(
                    callsign,
                    removeExistingCallsign(currentName)
                );

            if (newNickname.length > 32) {
                return res.status(400).json({
                    error: "Nickname-ul rezultat este prea lung pentru Discord."
                });
            }

            try {
                await axios.patch(
                    `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${targetId}`,
                    {
                        nick: newNickname
                    },
                    {
                        headers: {
                            Authorization: `Bot ${BOT_TOKEN}`,
                            "Content-Type": "application/json"
                        }
                    }
                );
            }
            catch (discordError) {
                console.error(
                    "Callsign Request Discord Nick Error:",
                    discordError.response?.data || discordError.message
                );

                if (discordError.response?.status === 403) {
                    return res.status(403).json({
                        error: "Discord a refuzat schimbarea nickname-ului. Rolul botului trebuie să fie deasupra membrului."
                    });
                }

                throw discordError;
            }

            // Profil site — păstrăm duties existente.
            const { data: profile } =
                await supabase
                    .from("user_profiles")
                    .select("*")
                    .eq("user_id", targetId)
                    .maybeSingle();

            const duties =
                Array.isArray(profile?.duties)
                    ? profile.duties
                    : [];

            const { error: profileError } =
                await supabase
                    .from("user_profiles")
                    .upsert(
                        {
                            user_id: targetId,
                            display_name: newNickname,
                            duties,
                            updated_at: new Date().toISOString()
                        },
                        {
                            onConflict: "user_id"
                        }
                    );

            if (profileError) throw profileError;

            // Fără sincronizare cu DOCS.

            const now = new Date().toISOString();

            const { error: decisionError } =
                await supabase
                    .from("callsign_requests")
                    .update({
                        status: "APPROVED",
                        assigned_callsign: callsign,
                        decided_by_id: String(req.session.user.id),
                        decided_by_name:
                            req.session.user.displayName ||
                            req.session.user.username,
                        decided_by_rank:
                            req.session.user.rank || "",
                        decision_note:
                            String(req.body?.decisionNote || "")
                                .trim()
                                .slice(0, 500),
                        decided_at: now,
                        updated_at: now
                    })
                    .eq("id", requestId);

            if (decisionError) throw decisionError;

            let discordLogUpdated = false;

            try {
                discordLogUpdated =
                    await updateCallsignLogMessage(
                        requestRow,
                        {
                            status: "APPROVED",
                            callsign,
                            decidedByName:
                                req.session.user.displayName ||
                                req.session.user.username,
                            decidedByRank:
                                req.session.user.rank || "",
                            decisionNote:
                                String(req.body?.decisionNote || "")
                                    .trim()
                                    .slice(0, 500)
                        }
                    );
            }
            catch (logError) {
                console.warn(
                    "Callsign Approve Log Update Warning:",
                    logError.response?.data || logError.message
                );
            }

            let dmSent = true;

            try {
                await sendDiscordDM(
                    targetId,
                    `📟 CERERE CALLSIGN APROBATĂ\n\nAi primit callsign-ul **${callsign}**.\nAi la dispoziție **24 de ore** să îl folosești și să respecți formatul stabilit de conducerea Poliției. Dacă nu respecți această obligație în termenul de 24 de ore, poți primi sancțiune conform regulamentului intern.\n\nAcordat de: **${req.session.user.displayName || req.session.user.username}**`
                );
            }
            catch (dmError) {
                dmSent = false;
                console.error(
                    "Callsign Request DM Error:",
                    dmError.response?.data || dmError.message
                );
            }

            return res.json({
                success: true,
                callsign,
                displayName: newNickname,
                dmSent,
                discordLogUpdated
            });
        }
        catch (error) {
            console.error(
                "Callsign Request Approve Error:",
                error.response?.data || error
            );

            return res.status(500).json({
                error: `Callsign-ul nu a putut fi acordat: ${error?.response?.data?.message || error?.message || "eroare necunoscută"}`
            });
        }
    }
);


// COORDONATOR+ poate respinge cererea.
app.patch(
    "/api/admin/callsign-requests/:id/reject",
    requireAdmin,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        try {
            const requestId = String(req.params.id || "").trim();
            const reason =
                String(req.body?.reason || "")
                    .trim()
                    .slice(0, 500);

            const { data: requestRow, error: findError } =
                await supabase
                    .from("callsign_requests")
                    .select("*")
                    .eq("id", requestId)
                    .maybeSingle();

            if (findError) throw findError;

            if (!requestRow) {
                return res.status(404).json({
                    error: "Cererea nu a fost găsită."
                });
            }

            if (requestRow.status !== "PENDING") {
                return res.status(409).json({
                    error: "Această cerere a fost deja soluționată."
                });
            }

            const now = new Date().toISOString();

            const { error } =
                await supabase
                    .from("callsign_requests")
                    .update({
                        status: "REJECTED",
                        decided_by_id: String(req.session.user.id),
                        decided_by_name:
                            req.session.user.displayName ||
                            req.session.user.username,
                        decided_by_rank:
                            req.session.user.rank || "",
                        decision_note: reason,
                        decided_at: now,
                        updated_at: now
                    })
                    .eq("id", requestId);

            if (error) throw error;

            let discordLogUpdated = false;

            try {
                discordLogUpdated =
                    await updateCallsignLogMessage(
                        requestRow,
                        {
                            status: "REJECTED",
                            decidedByName:
                                req.session.user.displayName ||
                                req.session.user.username,
                            decidedByRank:
                                req.session.user.rank || "",
                            decisionNote:
                                reason
                        }
                    );
            }
            catch (logError) {
                console.warn(
                    "Callsign Reject Log Update Warning:",
                    logError.response?.data || logError.message
                );
            }

            let dmSent = true;

            try {
                await sendDiscordDM(
                    String(requestRow.author_id),
                    `📟 CERERE CALLSIGN RESPINSĂ\n\nCererea ta de callsign a fost respinsă.${reason ? `\nMotiv: **${reason}**` : ""}\n\nDecizie luată de: **${req.session.user.displayName || req.session.user.username}**`
                );
            }
            catch (dmError) {
                dmSent = false;
                console.error(
                    "Callsign Reject DM Error:",
                    dmError.response?.data || dmError.message
                );
            }

            return res.json({
                success: true,
                dmSent,
                discordLogUpdated
            });
        }
        catch (error) {
            console.error("Callsign Request Reject Error:", error);
            return res.status(500).json({
                error: "Cererea nu a putut fi respinsă."
            });
        }
    }
);


// ======================================================
// ACTIVITĂȚI — RECLAMAȚII
// ======================================================

app.post(
    "/api/complaints",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const targetId =
                String(
                    req.body?.targetId ||
                    ""
                ).trim();

            const targetName =
                String(
                    req.body?.targetName ||
                    ""
                )
                    .trim()
                    .slice(
                        0,
                        120
                    );

            const reason =
                String(
                    req.body?.reason ||
                    ""
                )
                    .trim()
                    .slice(
                        0,
                        1500
                    );

            const evidence =
                String(
                    req.body?.evidence ||
                    ""
                )
                    .trim()
                    .slice(
                        0,
                        500
                    );

            if (
                !targetId ||
                !reason
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Selectează colegul și completează motivul."
                    });
            }

            if (
                String(
                    req.session.user.id
                ) ===
                targetId
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Nu poți trimite o reclamație împotriva ta."
                    });
            }

            const row = {
                id:
                    crypto.randomUUID(),

                author_id:
                    String(
                        req.session.user.id
                    ),

                author_name:
                    req.session.user.displayName ||
                    req.session.user.username,

                author_rank:
                    req.session.user.rank ||
                    "",

                target_id:
                    targetId,

                target_name:
                    targetName,

                reason,

                evidence,

                status:
                    "PENDING"
            };

            const {
                error
            } =
                await supabase
                    .from(
                        "complaints"
                    )
                    .insert(
                        row
                    );

            if (error) {
                throw error;
            }

            res
                .status(201)
                .json({
                    success:
                        true
                });

        }

        catch (error) {

            console.error(
                "Complaint Create Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Reclamația nu a putut fi trimisă."
                });
        }
    }
);



// ======================================================
// CONDUCERE — PANOU RECLAMAȚII
// ======================================================

app.get(
    "/api/admin/complaints",
    requireAdmin,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        try {
            const { data, error } =
                await supabase
                    .from("complaints")
                    .select("*")
                    .order("created_at", { ascending: false });

            if (error) throw error;

            return res.json({
                complaints: (data || []).map(row => ({
                    id: row.id,
                    authorId: row.author_id,
                    authorName: row.author_name,
                    authorRank: row.author_rank,
                    targetId: row.target_id,
                    targetName: row.target_name,
                    reason: row.reason,
                    evidence: row.evidence || "",
                    status: row.status || "PENDING",
                    resolution: row.resolution || "",
                    evaluatorId: row.evaluator_id || "",
                    evaluatorName: row.evaluator_name || "",
                    evaluatorRank: row.evaluator_rank || "",
                    decidedAt: row.decided_at || null,
                    createdAt: row.created_at
                }))
            });

        } catch (error) {
            console.error("Admin Complaints List Error:", error);

            return res.status(500).json({
                error: "Reclamațiile nu au putut fi încărcate."
            });
        }
    }
);


app.patch(
    "/api/admin/complaints/:id",
    requireAdmin,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        try {
            const id = String(req.params.id || "").trim();
            const status = String(req.body?.status || "").trim().toUpperCase();
            const resolution = String(req.body?.resolution || "").trim().slice(0, 1500);

            const allowedStatuses = new Set([
                "IN_REVIEW",
                "SOLVED",
                "REJECTED"
            ]);

            if (!id) {
                return res.status(400).json({
                    error: "ID reclamație invalid."
                });
            }

            if (!allowedStatuses.has(status)) {
                return res.status(400).json({
                    error: "Status reclamație invalid."
                });
            }

            if (
                (status === "SOLVED" || status === "REJECTED") &&
                resolution.length < 3
            ) {
                return res.status(400).json({
                    error: "Completează rezoluția oficială înainte de soluționare/respingere."
                });
            }

            const update = {
                status,
                resolution,
                evaluator_id: String(req.session.user.id),
                evaluator_name:
                    req.session.user.displayName ||
                    req.session.user.username ||
                    "",
                evaluator_rank:
                    req.session.user.rank ||
                    "",
                decided_at: new Date().toISOString()
            };

            const { data, error } =
                await supabase
                    .from("complaints")
                    .update(update)
                    .eq("id", id)
                    .select("*")
                    .maybeSingle();

            if (error) throw error;

            if (!data) {
                return res.status(404).json({
                    error: "Reclamația nu a fost găsită."
                });
            }

            // Încercăm să notificăm persoana reclamată prin DM.
            let dmSent = false;

            try {
                if (data.target_id) {
                    const statusText =
                        status === "SOLVED"
                            ? "SOLUȚIONATĂ"
                            : status === "REJECTED"
                                ? "RESPINSĂ"
                                : "ÎN ANALIZĂ";

                    await sendDiscordDM(
                        String(data.target_id),
                        `⚠️ ACTUALIZARE RECLAMAȚIE\n\nO reclamație în care ești menționat(ă) a fost actualizată la statusul **${statusText}**.${resolution ? `\n\nRezoluție: **${resolution}**` : ""}\n\nActualizat de: **${update.evaluator_name}**`
                    );

                    dmSent = true;
                }
            } catch (dmError) {
                console.error(
                    "Complaint Status DM Error:",
                    dmError.response?.data || dmError.message
                );
            }

            return res.json({
                success: true,
                dmSent
            });

        } catch (error) {
            console.error("Admin Complaint Update Error:", error);

            return res.status(500).json({
                error: "Reclamația nu a putut fi actualizată."
            });
        }
    }
);


// ======================================================
// ACTIVITĂȚI — TESTARE CANDIDAȚI
// ======================================================

app.post(
    "/api/candidate-tests",

    requireAuth,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const candidateName =
                String(
                    req.body?.candidateName ||
                    ""
                )
                    .trim()
                    .slice(
                        0,
                        100
                    );

            const candidateDiscord =
                String(
                    req.body?.candidateDiscord ||
                    ""
                )
                    .trim()
                    .slice(
                        0,
                        100
                    );

            const result =
                String(
                    req.body?.result ||
                    ""
                )
                    .trim()
                    .toUpperCase();

            const notes =
                String(
                    req.body?.notes ||
                    ""
                )
                    .trim()
                    .slice(
                        0,
                        1500
                    );

            const rawScore =
                req.body?.score;

            const score =
                rawScore ===
                "" ||
                rawScore ===
                null ||
                rawScore ===
                undefined

                    ? null

                    : Math.max(
                        0,
                        Math.min(
                            100,
                            Number(
                                rawScore
                            ) ||
                            0
                        )
                    );

            if (!candidateName) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Numele candidatului este obligatoriu."
                    });
            }

            if (
                ![
                    "PASSED",
                    "FAILED"
                ].includes(
                    result
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Rezultatul testului este invalid."
                    });
            }

            const row = {
                id:
                    crypto.randomUUID(),

                tester_id:
                    String(
                        req.session.user.id
                    ),

                tester_name:
                    req.session.user.displayName ||
                    req.session.user.username,

                tester_rank:
                    req.session.user.rank ||
                    "",

                candidate_name:
                    candidateName,

                candidate_discord:
                    candidateDiscord,

                result,

                score,

                notes
            };

            const {
                error
            } =
                await supabase
                    .from(
                        "candidate_tests"
                    )
                    .insert(
                        row
                    );

            if (error) {
                throw error;
            }

            res
                .status(201)
                .json({
                    success:
                        true
                });

        }

        catch (error) {

            console.error(
                "Candidate Test Create Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Testul candidatului nu a putut fi salvat."
                });
        }
    }
);


// ======================================================
// ACTIVITĂȚI — SANCȚIUNI COORDONATOR+
// ======================================================


app.get(
    "/api/admin/sanctions/active",
    requireSanctionManager,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        try {
            const { data, error } = await supabase
                .from("sanctions")
                .select("id,target_id,target_name,type,fw_count,reason,active,applied_by_id,applied_by_name,applied_by_rank,created_at")
                .eq("active", true)
                .order("created_at", { ascending: false });

            if (error) throw error;

            return res.json({
                sanctions: (data || []).map(row => ({
                    id: row.id,
                    targetId: row.target_id,
                    targetName: row.target_name,
                    type: row.type,
                    fwCount: Number(row.fw_count || 0),
                    reason: row.reason || "",
                    appliedById: row.applied_by_id || "",
                    appliedByName: row.applied_by_name || "",
                    appliedByRank: row.applied_by_rank || "",
                    createdAt: row.created_at || null
                }))
            });
        } catch (error) {
            console.error("Sanctions Active List Error:", error);
            return res.status(500).json({
                error: "Sancțiunile active nu au putut fi încărcate."
            });
        }
    }
);


app.patch(
    "/api/admin/sanctions/:id/revoke",
    requireSanctionManager,
    async (req, res) => {
        if (!ensureSupabase(res)) return;

        try {
            const sanctionId = String(req.params.id || "").trim();

            const { data: sanction, error: sanctionError } = await supabase
                .from("sanctions")
                .select("*")
                .eq("id", sanctionId)
                .maybeSingle();

            if (sanctionError) throw sanctionError;

            if (!sanction) {
                return res.status(404).json({
                    error: "Sancțiunea nu a fost găsită."
                });
            }

            if (!sanction.active) {
                return res.status(400).json({
                    error: "Sancțiunea este deja retrasă."
                });
            }

            const { error: updateError } = await supabase
                .from("sanctions")
                .update({ active: false })
                .eq("id", sanctionId);

            if (updateError) throw updateError;

            const targetId = String(sanction.target_id || "");
            const targetName = String(sanction.target_name || "Necunoscut");

            const { data: remainingRows, error: remainingError } = await supabase
                .from("sanctions")
                .select("fw_count")
                .eq("target_id", targetId)
                .eq("type", "FW")
                .eq("active", true);

            if (remainingError) throw remainingError;

            const activeFw = Math.min(5, (remainingRows || []).reduce(
                (total, row) => total + Number(row.fw_count || 0),
                0
            ));

            let roleSynced = false;
            let roleSyncError = null;

            try {
                await syncFactionWarnDiscordRole(targetId, activeFw);
                roleSynced = true;
            } catch (error) {
                roleSyncError =
                    error?.response?.data?.message ||
                    error?.message ||
                    "Rolul Discord nu a putut fi sincronizat.";
            }

            const removedByName =
                req.session.user.displayName ||
                req.session.user.username ||
                "Conducerea Poliției";

            const removedByRank =
                req.session.user.rank ||
                "CONDUCERE POLIȚIA ROMÂNĂ";

            let dmSent = false;
            let dmError = null;

            try {
                const text = [
                    "✅ **NOTIFICARE SANCȚIUNE — POLIȚIA ROMÂNĂ**",
                    "",
                    sanction.type === "OUT"
                        ? "Sancțiunea **OUT** a fost retrasă."
                        : `Au fost retrase **${Number(sanction.fw_count || 0)} FW**.`,
                    `**Situație activă:** ${activeFw}/5 FW`,
                    `**Retrasă de:** ${removedByName} — ${removedByRank}`
                ].join("\n");

                await sendDiscordDM(targetId, text);
                dmSent = true;
            } catch (error) {
                dmError =
                    error?.response?.data?.message ||
                    error?.message ||
                    "DM nelivrat.";
            }

            let channelSent = false;
            let channelError = null;

            try {
                await sendSanctionRevokedInfoMessage({
                    targetId,
                    targetName,
                    type: sanction.type,
                    fwCount: sanction.fw_count,
                    activeFw,
                    reason: sanction.reason,
                    removedByName,
                    removedByRank
                });
                channelSent = true;
            } catch (error) {
                channelError =
                    error?.response?.data?.message ||
                    error?.message ||
                    "Mesaj canal netrimis.";
            }

            return res.json({
                success: true,
                activeFw,
                roleSynced,
                roleSyncError,
                dmSent,
                dmError,
                channelSent,
                channelError
            });
        } catch (error) {
            console.error("Sanction Revoke Error:", error);
            return res.status(500).json({
                error: "Sancțiunea nu a putut fi retrasă."
            });
        }
    }
);


app.post(
    "/api/admin/sanctions",

    requireSanctionManager,

    async (
        req,
        res
    ) => {

        if (
            !ensureSupabase(res)
        ) {
            return;
        }

        try {

            const targetId =
                String(
                    req.body?.targetId ||
                    ""
                ).trim();

            const targetName =
                String(
                    req.body?.targetName ||
                    ""
                )
                    .trim()
                    .slice(
                        0,
                        120
                    );

            const type =
                String(
                    req.body?.type ||
                    ""
                )
                    .trim()
                    .toUpperCase();

            const reason =
                String(
                    req.body?.reason ||
                    ""
                )
                    .trim()
                    .slice(
                        0,
                        1500
                    );

            if (
                !targetId ||
                !reason
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Selectează membrul și completează motivul."
                    });
            }

            if (
                ![
                    "FW",
                    "OUT"
                ].includes(
                    type
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Tipul sancțiunii este invalid."
                    });
            }

            let fwCount =
                type ===
                    "FW"

                    ? Math.max(
                        1,
                        Math.min(
                            5,
                            Number(
                                req.body?.fwCount ||
                                1
                            ) ||
                            1
                        )
                    )

                    : 0;

            let activeFw =
                0;

            if (
                type ===
                "FW"
            ) {

                const {
                    data:
                        existing,

                    error:
                        existingError
                } =
                    await supabase
                        .from(
                            "sanctions"
                        )
                        .select(
                            "fw_count"
                        )
                        .eq(
                            "target_id",
                            targetId
                        )
                        .eq(
                            "type",
                            "FW"
                        )
                        .eq(
                            "active",
                            true
                        );

                if (existingError) {
                    throw existingError;
                }

                const currentFw =
                    (
                        existing ||
                        []
                    ).reduce(
                        (
                            total,
                            row
                        ) =>
                            total +
                            Number(
                                row.fw_count ||
                                0
                            ),

                        0
                    );

                if (currentFw >= 5) {
                    return res.status(400).json({
                        error: "Membrul are deja 5/5 FW active."
                    });
                }

                // Aplicăm doar diferența disponibilă până la 5/5.
                // Exemplu: 2/5 + cerere 3 FW = 5/5, niciodată 7/5.
                fwCount = Math.min(fwCount, 5 - currentFw);
                activeFw = Math.min(5, currentFw + fwCount);
            }

            if (
                type ===
                "OUT"
            ) {

                // Un OUT închide FW-urile active ale membrului.
                const {
                    error:
                        deactivateError
                } =
                    await supabase
                        .from(
                            "sanctions"
                        )
                        .update({
                            active:
                                false
                        })
                        .eq(
                            "target_id",
                            targetId
                        )
                        .eq(
                            "type",
                            "FW"
                        )
                        .eq(
                            "active",
                            true
                        );

                if (deactivateError) {
                    throw deactivateError;
                }
            }

            const row = {
                id:
                    crypto.randomUUID(),

                target_id:
                    targetId,

                target_name:
                    targetName,

                type,

                fw_count:
                    fwCount,

                reason,

                active:
                    true,

                applied_by_id:
                    String(
                        req.session.user.id
                    ),

                applied_by_name:
                    req.session.user.displayName ||
                    req.session.user.username,

                applied_by_rank:
                    req.session.user.rank ||
                    ""
            };

            const {
                error
            } =
                await supabase
                    .from(
                        "sanctions"
                    )
                    .insert(
                        row
                    );

            if (error) {
                throw error;
            }

            const appliedByName = req.session.user.displayName || req.session.user.username || "Conducerea Poliției";
            const appliedByRank = req.session.user.rank || "CONDUCERE POLIȚIA ROMÂNĂ";

            // Sincronizează automat rolul de Faction Warn pe Discord.
            // OUT folosește rolul 5/5 (OUT).
            let roleSynced = false;
            let roleSyncError = null;
            try {
                const roleLevel = type === "OUT" ? 5 : activeFw;
                await syncFactionWarnDiscordRole(targetId, roleLevel);
                roleSynced = true;
            }
            catch (discordRoleError) {
                roleSyncError = discordRoleError?.response?.data?.message || discordRoleError?.message || "Rolul FW nu a putut fi sincronizat.";
                console.warn("Sanction Discord Role Warning:", targetId, roleSyncError);
            }

            // Postează automat sancțiunea în canalul info-sanctiuni.
            let channelSent = false;
            let channelError = null;
            try {
                await sendSanctionInfoMessage({
                    targetId,
                    targetName,
                    type,
                    fwCount,
                    activeFw,
                    reason,
                    appliedByName,
                    appliedByRank
                });
                channelSent = true;
            }
            catch (channelPostError) {
                channelError = channelPostError?.response?.data?.message || channelPostError?.message || "Mesajul din info-sanctiuni nu a putut fi trimis.";
                console.warn("Sanction Info Channel Warning:", channelError);
            }

            let dmSent = false;
            let dmError = null;
            try {
                const dmLines = type === "OUT"
                    ? ["📋 **NOTIFICARE SANCȚIUNE — POLIȚIA ROMÂNĂ**", "", "Ai primit sancțiunea **OUT**.", `**Motiv:** ${reason}`, `**Aplicată de:** ${appliedByName} — ${appliedByRank}`, "", "Această sancțiune a fost înregistrată în sistemul Poliției Române."]
                    : ["⚠️ **NOTIFICARE SANCȚIUNE — POLIȚIA ROMÂNĂ**", "", `Ai primit **${fwCount} Faction Warn**.`, `**Situație activă:** ${activeFw}/5 FW`, `**Motiv:** ${reason}`, `**Aplicată de:** ${appliedByName} — ${appliedByRank}`, "", "Această sancțiune a fost înregistrată în sistemul Poliției Române."];
                await sendDiscordDM(targetId, dmLines.join("\n"));
                dmSent = true;
            }
            catch (discordError) {
                dmError = discordError?.response?.data?.message || discordError?.message || "Mesajul privat nu a putut fi livrat.";
                console.warn("Sanction Discord DM Warning:", targetId, dmError);
            }

            res
                .status(201)
                .json({
                    success:
                        true,

                    activeFw,
                    dmSent,
                    dmError,
                    roleSynced,
                    roleSyncError,
                    channelSent,
                    channelError
                });

        }

        catch (error) {

            console.error(
                "Sanction Create Error:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Sancțiunea nu a putut fi aplicată."
                });
        }
    }
);



// ======================================================
// TEST MANAGEMENT — LOAD
// ======================================================

app.get(
    "/api/test-management",
    requireAuth,
    async (req, res) => {

        if (!ensureSupabase(res)) {
            return;
        }

        try {

            const [
                categoriesResult,
                questionsResult,
                settingsResult,
                historyResult
            ] = await Promise.all([
                supabase
                    .from("test_categories")
                    .select("*")
                    .order("position", { ascending: true })
                    .order("name", { ascending: true }),

                supabase
                    .from("test_questions")
                    .select("*")
                    .order("position", { ascending: true }),

                supabase
                    .from("test_settings")
                    .select("*")
                    .eq("department", "POLITIE")
                    .maybeSingle(),

                supabase
                    .from("test_history")
                    .select("*")
                    .eq("department", "POLITIE")
                    .order("created_at", { ascending: false })
                    .limit(500)
            ]);

            if (categoriesResult.error) throw categoriesResult.error;
            if (questionsResult.error) throw questionsResult.error;
            if (settingsResult.error) throw settingsResult.error;
            if (historyResult.error) throw historyResult.error;

            const settingsRow =
                settingsResult.data || {};

            return res.json({
                permissions: {
                    leadership:
                        hasPoliceFullAccess(req.session.user),
                    tester:
                        hasTesterAccess(req.session.user)
                },

                categories:
                    (categoriesResult.data || []).map(mapTestCategory),

                questions:
                    (questionsResult.data || []).map(mapTestQuestion),

                settings: {
                    rejectionThreshold:
                        Number(settingsRow.rejection_threshold || 3),

                    admittedRoleIds:
                        settingsRow.admitted_role_ids || "",

                    dmPassed:
                        settingsRow.dm_passed || "",

                    dmFailed:
                        settingsRow.dm_failed || "",

                    extraction:
                        settingsRow.extraction &&
                        typeof settingsRow.extraction === "object"
                            ? settingsRow.extraction
                            : {}
                },

                history:
                    (historyResult.data || []).map(mapTestHistory)
            });

        }
        catch (error) {

            console.error(
                "Test Management Load Error:",
                error
            );

            return res.status(500).json({
                error:
                    "Gestionarea testelor nu a putut fi încărcată."
            });
        }
    }
);


// ======================================================
// TEST CATEGORIES — COORDONATOR+
// ======================================================

app.post(
    "/api/admin/test-categories",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        const name =
            String(req.body?.name || "")
                .trim()
                .slice(0, 100);

        if (!name) {
            return res.status(400).json({
                error:
                    "Numele categoriei este obligatoriu."
            });
        }

        try {

            const {
                data,
                error
            } = await supabase
                .from("test_categories")
                .insert({
                    id:
                        crypto.randomUUID(),
                    name
                })
                .select("*")
                .single();

            if (error) throw error;

            return res.status(201).json({
                success: true,
                category:
                    mapTestCategory(data)
            });
        }
        catch (error) {

            return res.status(500).json({
                error:
                    "Categoria nu a putut fi creată."
            });
        }
    }
);


// ======================================================

app.patch(
    "/api/admin/test-categories/order",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        const ids =
            Array.isArray(req.body?.ids)
                ? req.body.ids
                    .map(id => String(id || "").trim())
                    .filter(Boolean)
                : [];

        if (!ids.length) {
            return res.status(400).json({
                error:
                    "Ordinea categoriilor este goală."
            });
        }

        try {

            for (let index = 0; index < ids.length; index++) {

                const {
                    error
                } = await supabase
                    .from("test_categories")
                    .update({
                        position:
                            index + 1,
                        updated_at:
                            new Date().toISOString()
                    })
                    .eq(
                        "id",
                        ids[index]
                    );

                if (error) {
                    throw error;
                }
            }

            return res.json({
                success: true
            });
        }
        catch (error) {

            console.error(
                "Test Category Order Error:",
                error
            );

            return res.status(500).json({
                error:
                    "Ordinea categoriilor nu a putut fi salvată."
            });
        }
    }
);


app.patch(
    "/api/admin/test-categories/:id",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        const name =
            String(req.body?.name || "")
                .trim()
                .slice(0, 100);

        if (!name) {
            return res.status(400).json({
                error:
                    "Numele categoriei este obligatoriu."
            });
        }

        try {

            const {
                error
            } = await supabase
                .from("test_categories")
                .update({
                    name,
                    updated_at:
                        new Date().toISOString()
                })
                .eq(
                    "id",
                    String(req.params.id)
                );

            if (error) throw error;

            return res.json({
                success: true
            });
        }
        catch (error) {

            return res.status(500).json({
                error:
                    "Categoria nu a putut fi actualizată."
            });
        }
    }
);


app.delete(
    "/api/admin/test-categories/:id",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        try {

            const {
                error
            } = await supabase
                .from("test_categories")
                .delete()
                .eq(
                    "id",
                    String(req.params.id)
                );

            if (error) throw error;

            return res.json({
                success: true
            });
        }
        catch (error) {

            return res.status(500).json({
                error:
                    "Categoria nu a putut fi ștearsă."
            });
        }
    }
);


// ======================================================
// TEST CATEGORIES — ORDER COORDONATOR+



// ======================================================
// TEST QUESTIONS — COORDONATOR+
// ======================================================

app.post(
    "/api/admin/test-questions",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        const categoryId =
            String(req.body?.categoryId || "").trim();

        const question =
            String(req.body?.question || "")
                .trim()
                .slice(0, 1000);

        const answer =
            String(req.body?.answer || "")
                .trim()
                .slice(0, 2000);

        if (!categoryId || !question || !answer) {
            return res.status(400).json({
                error:
                    "Categoria, întrebarea și răspunsul sunt obligatorii."
            });
        }

        try {

            const {
                data,
                error
            } = await supabase
                .from("test_questions")
                .insert({
                    id:
                        crypto.randomUUID(),
                    category_id:
                        categoryId,
                    question,
                    answer
                })
                .select("*")
                .single();

            if (error) throw error;

            return res.status(201).json({
                success: true,
                question:
                    mapTestQuestion(data)
            });
        }
        catch (error) {

            return res.status(500).json({
                error:
                    "Întrebarea nu a putut fi creată."
            });
        }
    }
);


// ======================================================

app.patch(
    "/api/admin/test-questions/order",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        const groups =
            Array.isArray(req.body?.groups)
                ? req.body.groups
                : [];

        if (!groups.length) {
            return res.status(400).json({
                error:
                    "Ordinea întrebărilor este goală."
            });
        }

        try {

            for (const group of groups) {

                const categoryId =
                    String(
                        group?.categoryId ||
                        ""
                    ).trim();

                const questionIds =
                    Array.isArray(group?.questionIds)
                        ? group.questionIds
                            .map(id => String(id || "").trim())
                            .filter(Boolean)
                        : [];

                if (!categoryId) {
                    continue;
                }

                for (
                    let index = 0;
                    index < questionIds.length;
                    index++
                ) {

                    const {
                        error
                    } = await supabase
                        .from("test_questions")
                        .update({
                            category_id:
                                categoryId,
                            position:
                                index + 1,
                            updated_at:
                                new Date().toISOString()
                        })
                        .eq(
                            "id",
                            questionIds[index]
                        );

                    if (error) {
                        throw error;
                    }
                }
            }

            return res.json({
                success: true
            });
        }
        catch (error) {

            console.error(
                "Test Question Order Error:",
                error
            );

            return res.status(500).json({
                error:
                    "Ordinea întrebărilor nu a putut fi salvată."
            });
        }
    }
);


app.patch(
    "/api/admin/test-questions/:id",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        const categoryId =
            String(req.body?.categoryId || "").trim();

        const question =
            String(req.body?.question || "")
                .trim()
                .slice(0, 1000);

        const answer =
            String(req.body?.answer || "")
                .trim()
                .slice(0, 2000);

        if (!categoryId || !question || !answer) {
            return res.status(400).json({
                error:
                    "Categoria, întrebarea și răspunsul sunt obligatorii."
            });
        }

        try {

            const {
                error
            } = await supabase
                .from("test_questions")
                .update({
                    category_id:
                        categoryId,
                    question,
                    answer,
                    updated_at:
                        new Date().toISOString()
                })
                .eq(
                    "id",
                    String(req.params.id)
                );

            if (error) throw error;

            return res.json({
                success: true
            });
        }
        catch (error) {

            return res.status(500).json({
                error:
                    "Întrebarea nu a putut fi actualizată."
            });
        }
    }
);


app.delete(
    "/api/admin/test-questions/:id",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        try {

            const {
                error
            } = await supabase
                .from("test_questions")
                .delete()
                .eq(
                    "id",
                    String(req.params.id)
                );

            if (error) throw error;

            return res.json({
                success: true
            });
        }
        catch (error) {

            return res.status(500).json({
                error:
                    "Întrebarea nu a putut fi ștearsă."
            });
        }
    }
);


// ======================================================
// TEST QUESTIONS — ORDER / MOVE COORDONATOR+
// Permite reordonarea și mutarea între categorii.



// ======================================================
// TEST SETTINGS — COORDONATOR+
// ======================================================

app.patch(
    "/api/admin/test-settings",
    requireAdmin,
    async (req, res) => {

        if (!ensureSupabase(res)) return;

        const rejectionThreshold =
            Math.max(
                1,
                Math.min(
                    100,
                    Number(req.body?.rejectionThreshold || 3) || 3
                )
            );

        const admittedRoleIds =
            String(req.body?.admittedRoleIds || "")
                .trim()
                .slice(0, 1000);

        const dmPassed =
            String(req.body?.dmPassed || "")
                .slice(0, 4000);

        const dmFailed =
            String(req.body?.dmFailed || "")
                .slice(0, 4000);

        const extraction =
            req.body?.extraction &&
            typeof req.body.extraction === "object"
                ? req.body.extraction
                : {};

        try {

            const {
                error
            } = await supabase
                .from("test_settings")
                .upsert({
                    department:
                        "POLITIE",
                    rejection_threshold:
                        rejectionThreshold,
                    admitted_role_ids:
                        admittedRoleIds,
                    dm_passed:
                        dmPassed,
                    dm_failed:
                        dmFailed,
                    extraction,
                    updated_at:
                        new Date().toISOString(),
                    updated_by_id:
                        String(req.session.user.id),
                    updated_by_name:
                        req.session.user.displayName ||
                        req.session.user.username
                }, {
                    onConflict:
                        "department"
                });

            if (error) throw error;

            return res.json({
                success: true
            });
        }
        catch (error) {

            return res.status(500).json({
                error:
                    "Setările nu au putut fi salvate."
            });
        }
    }
);


// ======================================================
// COMPLETE TEST
// ======================================================

app.post(
    "/api/candidate-tests/complete",
    requireTester,
    async (req, res) => {

        if (!ensureSupabase(res)) {
            return;
        }

        const candidateName =
            String(
                req.body?.candidateName ||
                ""
            )
                .trim()
                .slice(0, 120);

        const candidateDiscord =
            String(
                req.body?.candidateDiscord ||
                ""
            )
                .trim();

        const mistakes =
            Math.max(
                0,
                Number(
                    req.body?.mistakes ||
                    0
                ) ||
                0
            );

        const questions =
            Array.isArray(
                req.body?.questions
            )
                ? req.body.questions
                : [];

        if (
            !candidateName ||
            !/^\d{17,20}$/.test(
                candidateDiscord
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Numele candidatului sau Discord ID-ul este invalid."
                });
        }

        try {

            /*
             * Pragul și rolurile sunt citite DIRECT din Supabase.
             * Nu avem încredere în verdictul/pragul trimis de browser.
             */
            const {
                data:
                    settingsRow,

                error:
                    settingsError
            } =
                await supabase
                    .from(
                        "test_settings"
                    )
                    .select(
                        "*"
                    )
                    .eq(
                        "department",
                        "POLITIE"
                    )
                    .maybeSingle();

            if (settingsError) {
                throw settingsError;
            }

            const threshold =
                Math.max(
                    1,
                    Number(
                        settingsRow?.rejection_threshold ||
                        3
                    ) ||
                    3
                );

            const verdict =
                mistakes <
                    threshold
                    ? "PASSED"
                    : "FAILED";

            let assignedRoleIds =
                [];

            /*
             * Dacă este ADMIS:
             * - citim rolurile configurate în SETĂRI
             * - verificăm candidatul în guild
             * - adăugăm fiecare rol cu endpoint-ul Discord dedicat
             */
            if (
                verdict ===
                "PASSED"
            ) {

                if (!BOT_TOKEN) {

                    return res
                        .status(500)
                        .json({
                            error:
                                "Botul Discord nu este configurat. Testul nu a fost finalizat."
                        });
                }

                const admittedRoleIds =
                    String(
                        settingsRow?.admitted_role_ids ||
                        ""
                    )
                        .split(
                            /[\s,;]+/
                        )
                        .map(
                            roleId =>
                                roleId.trim()
                        )
                        .filter(
                            roleId =>
                                /^\d{17,20}$/.test(
                                    roleId
                                )
                        );

                if (
                    !admittedRoleIds.length
                ) {

                    return res
                        .status(400)
                        .json({
                            error:
                                "Candidatul este ADMIS, dar nu ai configurat niciun ID de rol în SETĂRI → ID-URI ROLURI DISCORD (ADMIS)."
                        });
                }

                /*
                 * Verificăm că membrul există pe server.
                 */
                try {

                    await axios.get(
                        `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${candidateDiscord}`,
                        {
                            headers: {
                                Authorization:
                                    `Bot ${BOT_TOKEN}`
                            }
                        }
                    );

                }
                catch (discordMemberError) {

                    if (
                        discordMemberError.response?.status ===
                        404
                    ) {

                        return res
                            .status(404)
                            .json({
                                error:
                                    "Candidatul nu a fost găsit pe serverul Discord."
                            });
                    }

                    throw discordMemberError;
                }

                for (
                    const roleId
                    of admittedRoleIds
                ) {

                    try {

                        await axios.put(
                            `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${candidateDiscord}/roles/${roleId}`,
                            null,
                            {
                                headers: {
                                    Authorization:
                                        `Bot ${BOT_TOKEN}`
                                }
                            }
                        );

                        assignedRoleIds.push(
                            roleId
                        );

                    }
                    catch (roleError) {

                        console.error(
                            "Discord Assign Test Role Error:",
                            roleError.response?.data ||
                            roleError.message
                        );

                        if (
                            roleError.response?.status ===
                            403
                        ) {

                            return res
                                .status(403)
                                .json({
                                    error:
                                        "Discord a refuzat acordarea rolului. Pune rolul botului deasupra rolurilor acordate candidatului."
                                });
                        }

                        if (
                            roleError.response?.status ===
                            404
                        ) {

                            return res
                                .status(404)
                                .json({
                                    error:
                                        `Rolul Discord ${roleId} sau candidatul nu a fost găsit.`
                                });
                        }

                        return res
                            .status(500)
                            .json({
                                error:
                                    `Rolul Discord ${roleId} nu a putut fi acordat.`
                            });
                    }
                }
            }

            // Numărăm testele anterioare ale ACESTUI candidat pentru TEST #1, #2, #3...
            const {
                count: previousTestCount,
                error: testCountError
            } = await supabase
                .from("test_history")
                .select("id", { count: "exact", head: true })
                .eq("candidate_discord", candidateDiscord);

            if (testCountError) {
                throw testCountError;
            }

            const candidateTestNumber = Number(previousTestCount || 0) + 1;

            const {
                error:
                    historyError
            } =
                await supabase
                    .from(
                        "test_history"
                    )
                    .insert({
                        id:
                            crypto.randomUUID(),

                        department:
                            "POLITIE",

                        candidate_name:
                            candidateName,

                        candidate_discord:
                            candidateDiscord,

                        tester_id:
                            String(
                                req.session.user.id
                            ),

                        tester_name:
                            req.session.user.displayName ||
                            req.session.user.username,

                        tester_rank:
                            req.session.user.rank ||
                            "",

                        mistakes,

                        threshold,

                        verdict,

                        question_results:
                            questions
                    });

            if (historyError) {
                throw historyError;
            }

            // Log Discord după ce testul a fost salvat cu succes.
            // Dacă Discord are o problemă, testul rămâne finalizat în site.
            if (BOT_TOKEN && CANDIDATE_TEST_LOG_CHANNEL_ID) {
                try {
                    const testerName =
                        req.session.user.displayName ||
                        req.session.user.username ||
                        "Tester";

                    const verdictText = verdict === "PASSED" ? "ADMIS" : "RESPINS";
                    const verdictColor = verdict === "PASSED" ? 0x2ecc71 : 0xe74c3c;
                    const questionCount = Array.isArray(questions) ? questions.length : 0;

                    await axios.post(
                        `https://discord.com/api/v10/channels/${CANDIDATE_TEST_LOG_CHANNEL_ID}/messages`,
                        {
                            embeds: [
                                {
                                    title: `📝 TESTARE CANDIDAT — TEST #${candidateTestNumber}`,
                                    color: verdictColor,
                                    fields: [
                                        { name: "👤 Candidat", value: candidateName || "-", inline: true },
                                        { name: "🆔 Discord", value: `<@${candidateDiscord}>\n\`${candidateDiscord}\``, inline: true },
                                        { name: "🎯 Rezultat", value: `**${verdictText}**`, inline: true },
                                        { name: "👮 Tester", value: `${testerName}\n<@${req.session.user.id}>`, inline: true },
                                        { name: "❌ Greșeli", value: `${mistakes} / prag ${threshold}`, inline: true },
                                        { name: "📋 Întrebări", value: String(questionCount), inline: true }
                                    ],
                                    footer: { text: `Poliția Română • Testul #${candidateTestNumber} al candidatului` },
                                    timestamp: new Date().toISOString()
                                }
                            ],
                            allowed_mentions: { parse: [] }
                        },
                        {
                            headers: {
                                Authorization: `Bot ${BOT_TOKEN}`,
                                "Content-Type": "application/json"
                            }
                        }
                    );
                }
                catch (testLogError) {
                    console.error(
                        "Discord Candidate Test Log Error:",
                        testLogError.response?.data || testLogError.message
                    );
                }
            }

            return res
                .status(201)
                .json({
                    success:
                        true,

                    verdict,

                    threshold,

                    mistakes,

                    assignedRoleIds,

                    testNumber:
                        candidateTestNumber
                });

        }
        catch (error) {

            console.error(
                "Complete Test Error:",
                error.response?.data ||
                error
            );

            return res
                .status(500)
                .json({
                    error:
                        `Testul nu a putut fi finalizat: ${error?.response?.data?.message || error?.message || "eroare necunoscută"}`
                });
        }
    }
);



// ======================================================
// HUB MAI — APLICAȚII POLIȚIE / DIICOT
// ======================================================
const HUB_POLICE_TESTER_ROLE_ID="1528758226420633751",HUB_DIICOT_TESTER_ROLE_ID="1528758226407919637",HUB_APPLICATION_COOLDOWN_MS=86400000;
const hubAppDept=v=>["POLITIE","DIICOT"].includes(String(v||"").toUpperCase())?String(v).toUpperCase():null;
async function hubAppPerms(id){try{const m=await getDiscordMemberCached(String(id)),r=(m?.roles||[]).map(String);return{policeTester:r.includes(HUB_POLICE_TESTER_ROLE_ID),diicotTester:r.includes(HUB_DIICOT_TESTER_ROLE_ID)}}catch{return{policeTester:false,diicotTester:false}}}
const hubCanReview=(p,d)=>d==="POLITIE"?p.policeTester:p.diicotTester;
const hubWords=v=>String(v||"").trim().split(/\s+/).filter(Boolean).length;
function hubValidateApp(d,a={}){const req=d==="POLITIE"?["ooc_name","ooc_age","server_hours","rp_experience","daily_time","description","read_rules","ic_name","ic_age","cnp","department_help","driving","shooting","why_join","story"]:["ooc_name","ooc_age","server_hours","daily_time","was_diicot","read_diicot_rules","read_server_rules","description","ic_name","cnp","ic_age","department_help","driving","shooting","why_join","skills"];for(const k of req)if(!String(a[k]??"").trim())return"Completează toate câmpurile.";if(+a.ooc_age<(d==="POLITIE"?14:16))return`Vârsta minimă este ${d==="POLITIE"?14:16} ani.`;if(d==="DIICOT"&&+a.server_hours<75)return"Pentru DIICOT sunt necesare minimum 75 de ore.";if(hubWords(a.description)<40)return"Descrierea trebuie să aibă minimum 40 de cuvinte.";if(d==="POLITIE"&&hubWords(a.story)<50)return"Povestea trebuie să aibă minimum 50 de cuvinte.";if([+a.driving,+a.shooting].some(n=>n<1||n>10))return"Condusul și trasul trebuie să fie între 1 și 10.";return null}
async function hubAppDM(id,msg){try{await sendDiscordDM(String(id),String(msg));return true}catch(e){console.error("[HUB APP DM]",e?.response?.data||e?.message||e);return false}}
app.get("/api/hub/applications/me",requireAuth,async(req,res)=>{try{const id=String(req.session.user.id),{data,error}=await supabase.from("hub_applications").select("*").eq("discord_id",id).order("created_at",{ascending:false}).limit(30);if(error)throw error;const x=(data||[]).find(a=>a.status==="REJECTED"&&a.decided_at);let cooldownUntil=null;if(x){const u=new Date(new Date(x.decided_at).getTime()+HUB_APPLICATION_COOLDOWN_MS);if(u>Date.now())cooldownUntil=u.toISOString()}res.json({applications:data||[],cooldownUntil})}catch(e){res.status(500).json({error:e.message})}});
app.post("/api/hub/applications",requireAuth,async(req,res)=>{try{const d=hubAppDept(req.body?.department),a=req.body?.answers||{};if(!d)return res.status(400).json({error:"Departament invalid."});const v=hubValidateApp(d,a);if(v)return res.status(400).json({error:v});const id=String(req.session.user.id),{data:old,error:oe}=await supabase.from("hub_applications").select("status,decided_at").eq("discord_id",id).order("created_at",{ascending:false}).limit(50);if(oe)throw oe;if((old||[]).some(x=>x.status==="PENDING"))return res.status(409).json({error:"Ai deja o aplicație în așteptare."});const rej=(old||[]).find(x=>x.status==="REJECTED"&&x.decided_at);if(rej){const u=new Date(new Date(rej.decided_at).getTime()+HUB_APPLICATION_COOLDOWN_MS);if(u>Date.now())return res.status(429).json({error:"Ai cooldown 24 de ore după respingere, valabil la ambele structuri.",cooldownUntil:u.toISOString()})}const name=req.session.user.displayName||req.session.user.global_name||req.session.user.username||id,{data,error}=await supabase.from("hub_applications").insert({department:d,discord_id:id,discord_name:name,answers:a,status:"PENDING"}).select().single();if(error)throw error;res.json({success:true,application:data})}catch(e){console.error("[HUB APP CREATE]",e);res.status(500).json({error:e.message||"Aplicația nu a putut fi trimisă."})}});
app.get("/api/hub/applications/review",requireAuth,async(req,res)=>{try{const p=await hubAppPerms(req.session.user.id);if(!p.policeTester&&!p.diicotTester)return res.status(403).json({error:"Nu ai rol de tester."});const ds=[];if(p.policeTester)ds.push("POLITIE");if(p.diicotTester)ds.push("DIICOT");const{data,error}=await supabase.from("hub_applications").select("*").in("department",ds).order("created_at",{ascending:false}).limit(200);if(error)throw error;res.json({permissions:p,applications:data||[]})}catch(e){res.status(500).json({error:e.message})}});
app.post("/api/hub/applications/:id/decision",requireAuth,async(req,res)=>{try{const dec=String(req.body?.decision||"").toUpperCase();if(!["APPROVED","REJECTED"].includes(dec))return res.status(400).json({error:"Decizie invalidă."});const{data:a,error:ge}=await supabase.from("hub_applications").select("*").eq("id",req.params.id).single();if(ge||!a)return res.status(404).json({error:"Aplicația nu există."});if(a.status!=="PENDING")return res.status(409).json({error:"Aplicația a fost deja procesată."});const p=await hubAppPerms(req.session.user.id);if(!hubCanReview(p,a.department))return res.status(403).json({error:"Nu ai rolul de tester pentru această structură."});const rid=String(req.session.user.id),rn=req.session.user.displayName||req.session.user.global_name||req.session.user.username||rid,reason=String(req.body?.reason||"").trim().slice(0,1000);if(dec==="REJECTED"&&!reason)return res.status(400).json({error:"Scrie motivul respingerii."});const now=new Date().toISOString(),{data:u,error:ue}=await supabase.from("hub_applications").update({status:dec,decided_at:now,decided_by_id:rid,decided_by_name:rn,decision_reason:reason||null}).eq("id",a.id).eq("status","PENDING").select().single();if(ue)throw ue;const dept=a.department==="POLITIE"?"Poliția Română":"DIICOT";if(dec==="APPROVED"){await hubAppDM(a.discord_id,`✅ **Aplicație ${dept} acceptată**\nAi fost acceptat pentru etapa de testare. Un tester te va contacta.`);await hubAppDM(rid,`📨 **Ai acceptat o aplicație — ${dept}**\nCandidat: **${a.discord_name}**\nDiscord ID: \`${a.discord_id}\`\n\nTrimite-i tu invitația Discord și continuă testarea.`)}else await hubAppDM(a.discord_id,`❌ **Aplicație ${dept} respinsă**\nMotiv: ${reason}\n\nPoți aplica din nou peste **24 de ore**. Cooldown-ul este comun Poliție + DIICOT.`);res.json({success:true,application:u})}catch(e){console.error("[HUB APP DECISION]",e);res.status(500).json({error:e.message||"Decizia nu a putut fi salvată."})}});

// ======================================================
// LOGOUT
// ======================================================

app.get(
    "/logout",

    (
        req,
        res
    ) => {

        req.session =
            null;


        res.redirect(
            "/"
        );
    }
);


// ======================================================
// API LOGOUT
// ======================================================

app.post(
    "/api/logout",

    (
        req,
        res
    ) => {

        req.session =
            null;


        res.json({

            success:
                true,

            message:
                "Te-ai deconectat."
        });
    }
);



// ======================================================
// PREZENȚĂ ȘEDINȚĂ — DISCORD VOICE + FW AUTOMAT
// Acces exclusiv pentru utilizatorul configurat mai jos.
// Programările sunt persistate în B2 dacă B2 este disponibil.
// ======================================================

const MEETING_ATTENDANCE_USER_ID = "1315733546312142921";
const MEETING_VOICE_CHANNEL_ID = "1529137764828713040";
const MEETING_RESULT_CHANNEL_ID = "1551928220633399417";
const MEETING_ATTENDANCE_STATE_KEY = "system/meeting-attendance.json";

let meetingAttendanceJobs = [];
const meetingAttendanceTimers = new Map();

function requireMeetingAttendanceAccess(req, res, next) {
    if (!req.session?.user) {
        return res.status(401).json({ error: "Trebuie să fii autentificat." });
    }

    if (!hasPoliceFullAccess(req.session.user)) {
        return res.status(403).json({ error: "Doar Conducerea Poliției are acces la această secțiune." });
    }

    next();
}

function meetingAttendanceB2Ready() {
    return Boolean(B2_BUCKET && B2_REGION && B2_ENDPOINT && B2_KEY_ID && B2_APPLICATION_KEY);
}

async function loadMeetingAttendanceState() {
    if (!meetingAttendanceB2Ready()) return meetingAttendanceJobs;

    try {
        const state = await readB2JSON(MEETING_ATTENDANCE_STATE_KEY);
        meetingAttendanceJobs = Array.isArray(state?.meetings) ? state.meetings : [];
    } catch (error) {
        const status = Number(error?.$metadata?.httpStatusCode || error?.statusCode || 0);
        const name = String(error?.name || "");
        if (status !== 404 && !/NoSuchKey|NotFound/i.test(name)) {
            console.warn("Meeting Attendance state load warning:", error?.message || error);
        }
    }

    return meetingAttendanceJobs;
}

async function saveMeetingAttendanceState() {
    if (!meetingAttendanceB2Ready()) return;

    await b2.send(
        new PutObjectCommand({
            Bucket: B2_BUCKET,
            Key: MEETING_ATTENDANCE_STATE_KEY,
            Body: JSON.stringify({ meetings: meetingAttendanceJobs }, null, 2),
            ContentType: "application/json; charset=utf-8",
            CacheControl: "no-store"
        })
    );
}

function serializeMeetingJob(job) {
    return {
        id: String(job.id),
        scheduledAt: job.scheduledAt,
        status: job.status || "SCHEDULED",
        createdAt: job.createdAt || null,
        startedAt: job.startedAt || null,
        finishedAt: job.finishedAt || null,
        createdById: job.createdById || null,
        createdByName: job.createdByName || null,
        error: job.error || null,
        result: job.result || null
    };
}

async function discordGuildChannels() {
    if (!BOT_TOKEN || !GUILD_ID) {
        throw new Error("Botul Discord sau serverul Discord nu este configurat.");
    }

    const response = await axios.get(
        `https://discord.com/api/v10/guilds/${GUILD_ID}/channels`,
        {
            headers: { Authorization: `Bot ${BOT_TOKEN}` },
            timeout: 15000
        }
    );

    return Array.isArray(response.data) ? response.data : [];
}

async function resolveMeetingVoiceChannel() {
    const channels = await discordGuildChannels();
    const target = channels.find(channel =>
        String(channel?.id || "") === MEETING_VOICE_CHANNEL_ID &&
        [2, 13].includes(Number(channel?.type))
    );

    if (!target?.id) {
        throw new Error(`Nu am găsit canalul voice configurat (${MEETING_VOICE_CHANNEL_ID}).`);
    }

    return target;
}

function discordDisplayName(member = {}) {
    return String(
        member?.nick ||
        member?.user?.global_name ||
        member?.user?.username ||
        member?.user?.id ||
        "Necunoscut"
    );
}

function isDiicotMemberForAttendance(member = {}) {
    if (member?.user?.bot) return false;
    return Boolean(resolveHighestDIICOTRoleSafe(member?.roles || []));
}

async function getApprovedMeetingExcuses(at = new Date()) {
    if (!supabase) return new Set();

    const day = new Date(at);
    if (!Number.isFinite(day.getTime())) return new Set();
    const isoDate = day.toISOString().slice(0, 10);

    const { data, error } = await supabase
        .from("leave_requests")
        .select("author_id,type,start_date,end_date,status")
        .eq("status", "APPROVED")
        .in("type", ["VACATION", "MEETING_EXCUSE"])
        .lte("start_date", isoDate)
        .gte("end_date", isoDate);

    if (error) throw error;

    return new Set((data || []).map(row => String(row.author_id || "")).filter(Boolean));
}

const MEETING_VOICE_REQUEST_DELAY_MS = 400;
const MEETING_VOICE_MAX_RETRIES = 4;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, Math.max(0, Number(ms) || 0)));
}

async function getDiscordVoiceState(userId) {
    const id = encodeURIComponent(String(userId));

    for (let attempt = 0; attempt <= MEETING_VOICE_MAX_RETRIES; attempt += 1) {
        try {
            const response = await axios.get(
                `https://discord.com/api/v10/guilds/${GUILD_ID}/voice-states/${id}`,
                {
                    headers: { Authorization: `Bot ${BOT_TOKEN}` },
                    timeout: 10000,
                    validateStatus: status => status === 200 || status === 404 || status === 429
                }
            );

            if (response.status === 404) return null;
            if (response.status === 200) return response.data;

            // Discord 429: respectăm retry_after și NU bombardăm API-ul.
            const retryAfterSeconds = Number(response.data?.retry_after || 0);
            const retryAfterHeader = Number(response.headers?.['retry-after'] || 0);
            const waitMs = Math.max(
                1000,
                Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
                    ? Math.ceil(retryAfterSeconds * 1000)
                    : 0,
                Number.isFinite(retryAfterHeader) && retryAfterHeader > 0
                    ? Math.ceil(retryAfterHeader * 1000)
                    : 0
            );

            if (attempt >= MEETING_VOICE_MAX_RETRIES) {
                throw new Error(`Discord rate limit după ${MEETING_VOICE_MAX_RETRIES + 1} încercări.`);
            }

            console.warn(`Meeting voice-state rate limit pentru ${userId}; retry în ${waitMs}ms.`);
            await sleep(waitMs);
        } catch (error) {
            if (Number(error?.response?.status) === 404) return null;

            if (Number(error?.response?.status) === 429 && attempt < MEETING_VOICE_MAX_RETRIES) {
                const waitMs = Math.max(1000, getDiscordRetryAfterMs(error) || 1000);
                console.warn(`Meeting voice-state 429 pentru ${userId}; retry în ${waitMs}ms.`);
                await sleep(waitMs);
                continue;
            }

            throw error;
        }
    }

    return null;
}

async function mapWithConcurrency(items, limit, worker) {
    const results = new Array(items.length);
    let cursor = 0;

    async function run() {
        while (true) {
            const index = cursor++;
            if (index >= items.length) return;
            results[index] = await worker(items[index], index);
        }
    }

    const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length || 1)) }, run);
    await Promise.all(workers);
    return results;
}

async function applyMeetingAbsenceFactionWarn(member, actor = {}) {
    const targetId = String(member?.user?.id || "");
    const targetName = discordDisplayName(member);
    if (!targetId) return { targetId, targetName, added: 0, activeFw: 0 };

    const { data: existing, error: existingError } = await supabase
        .from("sanctions")
        .select("fw_count")
        .eq("target_id", targetId)
        .eq("type", "FW")
        .eq("active", true);

    if (existingError) throw existingError;

    const currentFw = (existing || []).reduce(
        (total, row) => total + Number(row.fw_count || 0),
        0
    );

    const fwCount = Math.max(0, Math.min(3, 5 - currentFw));
    const activeFw = Math.min(5, currentFw + fwCount);

    if (fwCount <= 0) {
        return { targetId, targetName, added: 0, activeFw };
    }

    const actorName = actor.displayName || actor.username || "Sistem Prezență Poliție";
    const actorRank = actor.rank || "CONTROL AUTOMAT";
    const reason = "Absență nemotivată la ședință";

    const row = {
        id: crypto.randomUUID(),
        target_id: targetId,
        target_name: targetName,
        type: "FW",
        fw_count: fwCount,
        reason,
        active: true,
        applied_by_id: String(actor.id || MEETING_ATTENDANCE_USER_ID),
        applied_by_name: actorName,
        applied_by_rank: actorRank
    };

    const { error } = await supabase.from("sanctions").insert(row);
    if (error) throw error;

    try {
        await syncFactionWarnDiscordRole(targetId, activeFw);
    } catch (discordRoleError) {
        console.warn("Meeting FW role warning:", targetId, discordRoleError?.message || discordRoleError);
    }

    try {
        await sendSanctionInfoMessage({
            targetId,
            targetName,
            type: "FW",
            fwCount,
            activeFw,
            reason,
            appliedByName: actorName,
            appliedByRank: actorRank
        });
    } catch (channelError) {
        console.warn("Meeting FW channel warning:", targetId, channelError?.message || channelError);
    }

    try {
        await sendDiscordDM(
            targetId,
            [
                "⚠️ **PREZENȚĂ ȘEDINȚĂ — POLIȚIA ROMÂNĂ**",
                "",
                `Ai primit **${fwCount} Faction Warn** pentru absență nemotivată la ședință.`,
                `**Situație activă:** ${activeFw}/5 FW`,
                "",
                "Sancțiunea a fost înregistrată automat de sistemul de prezență."
            ].join("\n")
        );
    } catch (dmError) {
        console.warn("Meeting FW DM warning:", targetId, dmError?.message || dmError);
    }

    return { targetId, targetName, added: fwCount, activeFw };
}

async function sendMeetingAttendanceResult(result) {
    if (!BOT_TOKEN || !MEETING_RESULT_CHANNEL_ID) return;

    const mentions = rows => (rows || []).length
        ? rows.map(x => `• <@${x.id}> — ${x.name}`).join("\n").slice(0, 1000)
        : "—";

    const sanctionText = (result.sanctions || []).length
        ? result.sanctions.map(x => `• <@${x.targetId}> — +${x.added || 0} FW (${x.activeFw ?? "?"}/5)`).join("\n").slice(0, 1000)
        : "—";

    const payload = {
        embeds: [{
            title: "📋 PREZENȚĂ ȘEDINȚĂ — POLIȚIA ROMÂNĂ",
            description: `Verificare automată în <#${result.channelId}>`,
            color: 0x2b8cff,
            fields: [
                { name: `✅ PREZENȚI (${result.present.length})`, value: mentions(result.present), inline: false },
                { name: `🟡 MOTIVAȚI (${result.excused.length})`, value: mentions(result.excused), inline: false },
                { name: `❌ ABSENȚI (${result.absent.length})`, value: mentions(result.absent), inline: false },
                { name: `⚠️ NECONFIRMAȚI (${result.unknown.length})`, value: mentions(result.unknown), inline: false },
                { name: "🛡️ SANCȚIUNI AUTOMATE", value: sanctionText, inline: false }
            ],
            footer: { text: "Poliția Română • Centru de Comandă • Rush România" },
            timestamp: result.checkedAt
        }],
        allowed_mentions: { parse: [] }
    };

    await axios.post(
        `https://discord.com/api/v10/channels/${MEETING_RESULT_CHANNEL_ID}/messages`,
        payload,
        { headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" }, timeout: 15000 }
    );
}

async function runMeetingAttendanceCheck(actor = {}) {
    if (!BOT_TOKEN || !GUILD_ID) {
        throw new Error("Botul Discord nu este configurat complet.");
    }
    if (!supabase) {
        throw new Error("Supabase nu este configurat.");
    }

    const voiceChannel = await resolveMeetingVoiceChannel();
    const members = (await getGuildMembersCached({ force: true }))
        .filter(isDiicotMemberForAttendance);
    const excusedIds = await getApprovedMeetingExcuses(new Date());

    // IMPORTANT: verificăm SECVENȚIAL membrii și introducem o pauză între request-uri.
    // Endpoint-ul Discord pentru voice-state este per utilizator; request-urile paralele
    // produceau 429 (rate limit) și făceau prezența instabilă.
    const checked = [];

    for (const member of members) {
        const id = String(member?.user?.id || "");
        const name = discordDisplayName(member);

        if (excusedIds.has(id)) {
            checked.push({ id, name, status: "EXCUSED" });
            continue;
        }

        let voiceState = null;
        let voiceCheckFailed = false;

        try {
            voiceState = await getDiscordVoiceState(id);
        } catch (error) {
            voiceCheckFailed = true;
            console.warn("Meeting voice-state warning:", id, error?.message || error);
        }

        // Dacă Discord încă refuză verificarea după retry-uri, NU marcăm persoana absentă.
        // Astfel evităm sancțiuni greșite cauzate doar de rate-limit/API.
        if (voiceCheckFailed) {
            checked.push({ id, name, status: "UNKNOWN" });
        } else if (String(voiceState?.channel_id || "") === String(voiceChannel.id)) {
            checked.push({ id, name, status: "PRESENT" });
        } else {
            checked.push({ id, name, status: "ABSENT", member });
        }

        await sleep(MEETING_VOICE_REQUEST_DELAY_MS);
    }

    const present = checked.filter(item => item.status === "PRESENT").map(({ id, name }) => ({ id, name }));
    const excused = checked.filter(item => item.status === "EXCUSED").map(({ id, name }) => ({ id, name }));
    const absentRows = checked.filter(item => item.status === "ABSENT");
    const unknown = checked.filter(item => item.status === "UNKNOWN").map(({ id, name }) => ({ id, name }));

    const sanctions = [];
    for (const item of absentRows) {
        // Conducerea Poliției este verificată la prezență, dar NU primește FW automat.
        // Considerăm conducere: COMISAR ȘEF+ (rank level >= 11) și persoanele
        // cu acces complet configurate în POLICE_FULL_ACCESS_IDS.
        const memberRank = resolveHighestDIICOTRoleSafe(item.member?.roles || []);
        const isLeadership =
            Number(memberRank?.level || 0) >= 11 ||
            POLICE_FULL_ACCESS_IDS.has(String(item.id || ""));

        if (isLeadership) {
            console.log(`[Meeting Attendance] Fără sancțiune pentru conducere: ${item.id} (${item.name})`);
            continue;
        }

        try {
            sanctions.push(await applyMeetingAbsenceFactionWarn(item.member, actor));
        } catch (error) {
            sanctions.push({
                targetId: item.id,
                targetName: item.name,
                added: 0,
                error: error?.message || "Sancțiunea nu a putut fi aplicată."
            });
        }
    }

    const result = {
        channelId: String(voiceChannel.id),
        channelName: voiceChannel.name,
        checkedAt: new Date().toISOString(),
        present,
        excused,
        absent: absentRows.map(({ id, name }) => ({ id, name })),
        unknown,
        sanctions
    };

    try {
        await sendMeetingAttendanceResult(result);
    } catch (error) {
        console.warn("Meeting attendance Discord log warning:", error?.message || error);
    }

    return result;
}

function clearMeetingAttendanceTimer(id) {
    const timer = meetingAttendanceTimers.get(String(id));
    if (timer) clearTimeout(timer);
    meetingAttendanceTimers.delete(String(id));
}

function armMeetingAttendanceJob(job) {
    clearMeetingAttendanceTimer(job.id);

    if (job.status !== "SCHEDULED") return;

    const delay = new Date(job.scheduledAt).getTime() - Date.now();
    if (!Number.isFinite(delay)) return;

    const runJob = async () => {
        job.status = "RUNNING";
        job.startedAt = new Date().toISOString();
        job.error = null;
        await saveMeetingAttendanceState().catch(() => {});

        try {
            job.result = await runMeetingAttendanceCheck({
                id: MEETING_ATTENDANCE_USER_ID,
                displayName: job.createdByName || "Sistem Prezență Poliție",
                rank: "CONTROL AUTOMAT"
            });
            job.status = "COMPLETED";
        } catch (error) {
            job.status = "ERROR";
            job.error = error?.message || "Verificarea a eșuat.";
        }

        job.finishedAt = new Date().toISOString();
        await saveMeetingAttendanceState().catch(() => {});
        clearMeetingAttendanceTimer(job.id);
    };

    if (delay <= 0) {
        setTimeout(runJob, 1000);
        return;
    }

    const MAX_TIMEOUT = 2147483647;
    if (delay > MAX_TIMEOUT) {
        const timer = setTimeout(() => armMeetingAttendanceJob(job), MAX_TIMEOUT);
        meetingAttendanceTimers.set(String(job.id), timer);
        return;
    }

    const timer = setTimeout(runJob, delay);
    meetingAttendanceTimers.set(String(job.id), timer);
}

async function initMeetingAttendanceScheduler() {
    try {
        await loadMeetingAttendanceState();
        for (const job of meetingAttendanceJobs) {
            if (job.status === "RUNNING") job.status = "SCHEDULED";
            if (job.status === "SCHEDULED") armMeetingAttendanceJob(job);
        }
        await saveMeetingAttendanceState().catch(() => {});
        console.log(`[Meeting Attendance] ${meetingAttendanceJobs.length} programări încărcate.`);
    } catch (error) {
        console.warn("Meeting Attendance init warning:", error?.message || error);
    }
}

app.get(
    "/api/meeting-attendance",
    requireMeetingAttendanceAccess,
    async (req, res) => {
        try {
            if (!meetingAttendanceJobs.length) {
                await loadMeetingAttendanceState();
            }
            return res.json({
                meetings: [...meetingAttendanceJobs]
                    .sort((a, b) => new Date(b.scheduledAt) - new Date(a.scheduledAt))
                    .map(serializeMeetingJob)
            });
        } catch (error) {
            console.error("Meeting Attendance List Error:", error);
            return res.status(500).json({ error: "Programările nu au putut fi încărcate." });
        }
    }
);

app.post(
    "/api/meeting-attendance",
    requireMeetingAttendanceAccess,
    async (req, res) => {
        try {
            const scheduledAt = new Date(String(req.body?.scheduledAt || ""));
            if (!Number.isFinite(scheduledAt.getTime())) {
                return res.status(400).json({ error: "Data și ora sunt invalide." });
            }
            if (scheduledAt.getTime() < Date.now() + 5000) {
                return res.status(400).json({ error: "Alege o oră cu cel puțin câteva secunde în viitor." });
            }

            const job = {
                id: crypto.randomUUID(),
                scheduledAt: scheduledAt.toISOString(),
                status: "SCHEDULED",
                createdAt: new Date().toISOString(),
                createdById: String(req.session.user.id),
                createdByName: req.session.user.displayName || req.session.user.username || "Administrator",
                startedAt: null,
                finishedAt: null,
                result: null,
                error: null
            };

            meetingAttendanceJobs.push(job);
            await saveMeetingAttendanceState();
            armMeetingAttendanceJob(job);

            return res.status(201).json({ success: true, meeting: serializeMeetingJob(job) });
        } catch (error) {
            console.error("Meeting Attendance Schedule Error:", error);
            return res.status(500).json({ error: error?.message || "Programarea a eșuat." });
        }
    }
);

app.post(
    "/api/meeting-attendance/run-now",
    requireMeetingAttendanceAccess,
    async (req, res) => {
        try {
            const result = await runMeetingAttendanceCheck(req.session.user || {});
            return res.json({ success: true, result });
        } catch (error) {
            console.error("Meeting Attendance Run Error:", error);
            return res.status(500).json({ error: error?.message || "Prezența a eșuat." });
        }
    }
);

app.delete(
    "/api/meeting-attendance/:id",
    requireMeetingAttendanceAccess,
    async (req, res) => {
        try {
            const id = String(req.params.id || "");
            const job = meetingAttendanceJobs.find(item => String(item.id) === id);
            if (!job) {
                return res.status(404).json({ error: "Programarea nu a fost găsită." });
            }
            if (job.status === "RUNNING") {
                return res.status(409).json({ error: "Verificarea este deja în curs." });
            }

            clearMeetingAttendanceTimer(id);
            meetingAttendanceJobs = meetingAttendanceJobs.filter(item => String(item.id) !== id);
            await saveMeetingAttendanceState();
            return res.json({ success: true });
        } catch (error) {
            console.error("Meeting Attendance Delete Error:", error);
            return res.status(500).json({ error: "Programarea nu a putut fi anulată." });
        }
    }
);

// ======================================================
// HEALTH CHECK
// ======================================================

app.get(
    "/health",

    (
        req,
        res
    ) => {

        res.json({

            status:
                "ok",

            service:
                "Police Command Center",

            timestamp:
                new Date()
                    .toISOString()
        });
    }
);


// ======================================================
// TRANSFER INTERDEPARTAMENTAL — POLITIE <-> DIICOT
// Persistenta: Backblaze B2
// Flux: solicitare -> aprobare Politie + aprobare DIICOT -> rol Discord nou
// ======================================================

const TRANSFER_STATE_KEY = "transfers/interdepartmental-requests.json";
const TRANSFER_POLICE_ROLES = DIICOT_ROLES.map(role => String(role.id));

const TRANSFER_DIICOT_ROLES = [
    { id: "1528758226407919644", name: "AGENT STAGIAR", level: 1 },
    { id: "1528758226407919645", name: "AGENT OPERATIV", level: 2 },
    { id: "1528758226416435210", name: "AGENT PRINCIPAL", level: 3 },
    { id: "1528758226416435211", name: "SUB-INSPECTOR", level: 4 },
    { id: "1528758226416435213", name: "INSPECTOR", level: 5 },
    { id: "1528758226416435214", name: "INSPECTOR PRINCIPAL", level: 6 },
    { id: "1528758226416435215", name: "SUB-COMISAR", level: 7 },
    { id: "1528758226416435216", name: "COMISAR", level: 8 },
    { id: "1528758226416435217", name: "COMISAR ȘEF", level: 9 },
    { id: "1528758226416435219", name: "COORDONATOR", level: 10 },
    { id: "1528758226420633744", name: "PROCUROR", level: 11 },
    { id: "1528758226420633745", name: "PROCUROR ȘEF ADJUNCT", level: 12 },
    { id: "1528758226420633746", name: "PROCUROR ȘEF", level: 13 }
];

const TRANSFER_DIICOT_ROLE_IDS = TRANSFER_DIICOT_ROLES.map(role => String(role.id));
const TRANSFER_DIICOT_LEADERSHIP_IDS = new Set([
    "1528758226416435219",
    "1528758226420633744",
    "1528758226420633745",
    "1528758226420633746"
]);

let transferState = { requests: [] };
let transferStateLoaded = false;

function normalizeTransferDepartment(value) {
    const v = String(value || "").trim().toUpperCase();
    return v === "POLITIE" || v === "DIICOT" ? v : "";
}

function getTransferRank(roles = [], department = "") {
    const roleSet = new Set((Array.isArray(roles) ? roles : []).map(String));
    const list = department === "DIICOT" ? TRANSFER_DIICOT_ROLES : DIICOT_ROLES;
    return [...list]
        .sort((a, b) => Number(b.level || 0) - Number(a.level || 0))
        .find(role => roleSet.has(String(role.id))) || null;
}

function canApprovePoliceTransfer(user) {
    return hasPoliceFullAccess(user);
}

function canApproveDiicotTransfer(user) {
    const roles = new Set((user?.roles || []).map(String));
    return [...TRANSFER_DIICOT_LEADERSHIP_IDS].some(id => roles.has(id));
}

async function loadTransferState({ force = false } = {}) {
    // Registrul este comun cu site-ul DIICOT. Nu păstrăm o copie veche
    // între request-uri, altfel modificările făcute pe celălalt site nu apar.
    if (transferStateLoaded && !force) return transferState;
    transferStateLoaded = true;

    if (!meetingAttendanceB2Ready()) {
        console.warn("[TRANSFER] B2 nu este configurat; cererile vor rămâne doar în memoria instanței.");
        return transferState;
    }

    try {
        const state = await readB2JSON(TRANSFER_STATE_KEY);
        transferState = {
            requests: Array.isArray(state?.requests) ? state.requests : []
        };
    } catch (error) {
        const status = Number(error?.$metadata?.httpStatusCode || error?.statusCode || 0);
        const name = String(error?.name || "");
        if (status !== 404 && !/NoSuchKey|NotFound/i.test(name)) {
            console.warn("[TRANSFER] Load warning:", error?.message || error);
        }
    }

    return transferState;
}

async function saveTransferState() {
    if (!meetingAttendanceB2Ready()) return;

    await b2.send(new PutObjectCommand({
        Bucket: B2_BUCKET,
        Key: TRANSFER_STATE_KEY,
        Body: JSON.stringify(transferState, null, 2),
        ContentType: "application/json; charset=utf-8",
        CacheControl: "no-store"
    }));
}

function publicTransferRequest(row, user) {
    return {
        ...row,
        // Acesta este backend-ul site-ului POLIȚIEI: poate decide doar Poliția.
        canDecidePolice: canApprovePoliceTransfer(user),
        canDecideDiicot: false
    };
}

async function transferDiscordRoles(request) {
    const userId = String(request.userId || "");
    const source = normalizeTransferDepartment(request.source);
    const destination = source === "POLITIE" ? "DIICOT" : "POLITIE";

    if (!userId || !source) throw new Error("Datele transferului sunt invalide.");

    const member = await getDiscordMemberCached(userId, { force: true });
    const currentRoles = new Set((member?.roles || []).map(String));

    const removeIds = source === "POLITIE"
        ? TRANSFER_POLICE_ROLES
        : TRANSFER_DIICOT_ROLE_IDS;

    const targetRoleId = destination === "DIICOT"
        ? "1528758226407919644" // Agent Stagiar
        : "1528758226420633750"; // Cadet

    for (const roleId of removeIds) {
        if (currentRoles.has(String(roleId))) {
            await setDiscordMemberRole(userId, roleId, false);
        }
    }

    await setDiscordMemberRole(userId, targetRoleId, true);

    return {
        destination,
        targetRoleId,
        targetRank: destination === "DIICOT" ? "AGENT STAGIAR" : "CADET"
    };
}

app.get("/api/transfers", requireAuth, async (req, res) => {
    try {
        await loadTransferState({ force: true });

        const user = req.session.user;
        const userId = String(user.id || "");
        const policeLeadership = canApprovePoliceTransfer(user);
        // Pe site-ul Poliției nu acordăm drept de decizie DIICOT, chiar dacă
        // utilizatorul are accidental și un rol DIICOT pe Discord.
        const diicotLeadership = false;

        let requests = transferState.requests || [];

        // Conducerea Poliției vede registrul comun complet; membrul vede doar cererile sale.
        if (!policeLeadership) {
            requests = requests.filter(row => String(row.userId) === userId);
        }

        requests = [...requests].sort((a, b) =>
            String(b.createdAt || "").localeCompare(String(a.createdAt || ""))
        );

        const roles = Array.isArray(user.roles) ? user.roles : [];
        const policeRank = getTransferRank(roles, "POLITIE");
        const diicotRank = getTransferRank(roles, "DIICOT");

        return res.json({
            success: true,
            permissions: {
                policeLeadership,
                diicotLeadership
            },
            profile: {
                discordId: userId,
                displayName: user.displayName || user.globalName || user.username || "Membru",
                policeRank: policeRank?.name || null,
                diicotRank: diicotRank?.name || null
            },
            requests: requests.map(row => publicTransferRequest(row, user))
        });
    } catch (error) {
        console.error("Transfer list error:", error);
        return res.status(500).json({ error: "Cererile de transfer nu au putut fi încărcate." });
    }
});

app.post("/api/transfers", requireAuth, async (req, res) => {
    try {
        await loadTransferState({ force: true });

        const source = normalizeTransferDepartment(req.body?.source);
        const reason = String(req.body?.reason || "").trim();
        const gameId = String(req.body?.gameId || "").trim();
        const age = Number(req.body?.age || 0);
        const user = req.session.user;
        const roles = Array.isArray(user.roles) ? user.roles : [];

        if (!source) return res.status(400).json({ error: "Structura de origine este invalidă." });
        if (source !== "POLITIE") {
            return res.status(403).json({ error: "Pe site-ul Poliției poți trimite doar cereri POLIȚIE → DIICOT." });
        }
        if (reason.length < 10) return res.status(400).json({ error: "Motivul transferului trebuie să aibă minimum 10 caractere." });
        if (!/^[0-9]{1,10}$/.test(gameId)) return res.status(400).json({ error: "Introdu un ID valid din joc." });
        if (!Number.isFinite(age) || age < 14 || age > 99) return res.status(400).json({ error: "Vârsta introdusă nu este validă." });

        const currentRank = getTransferRank(roles, source);
        if (!currentRank) {
            return res.status(403).json({
                error: source === "POLITIE"
                    ? "Nu ai un grad activ în Poliția Română."
                    : "Nu ai un grad activ în DIICOT."
            });
        }

        const destination = source === "POLITIE" ? "DIICOT" : "POLITIE";
        const userId = String(user.id);

        const duplicate = (transferState.requests || []).find(row =>
            String(row.userId) === userId &&
            row.status === "PENDING"
        );
        if (duplicate) {
            return res.status(409).json({ error: "Ai deja o cerere de transfer în așteptare." });
        }

        const now = new Date().toISOString();
        const request = {
            id: crypto.randomUUID(),
            userId,
            displayName: user.displayName || user.globalName || user.username || "Membru",
            username: user.username || "",
            gameId,
            age,
            source,
            destination,
            currentRank: currentRank.name,
            currentRankRoleId: String(currentRank.id),
            reason,
            status: "PENDING",
            policeDecision: "PENDING",
            policeDecisionById: null,
            policeDecisionByName: null,
            policeDecisionAt: null,
            diicotDecision: "PENDING",
            diicotDecisionById: null,
            diicotDecisionByName: null,
            diicotDecisionAt: null,
            createdAt: now,
            completedAt: null,
            targetRank: destination === "DIICOT" ? "AGENT STAGIAR" : "CADET"
        };

        transferState.requests.push(request);
        await saveTransferState();

        sendDiscordDM(
            userId,
            `📨 CERERE TRANSFER\n\nCererea ta de transfer ${source === "POLITIE" ? "POLIȚIA ROMÂNĂ" : "DIICOT"} → ${destination === "POLITIE" ? "POLIȚIA ROMÂNĂ" : "DIICOT"} a fost înregistrată.\n\nID joc: ${gameId}\nGrad actual: ${currentRank.name}\nStatus: așteaptă aprobarea ambelor conduceri.`
        ).catch(err => console.warn("Transfer DM create:", err?.message || err));

        return res.status(201).json({
            success: true,
            message: "Cererea de transfer a fost trimisă către ambele conduceri.",
            request: publicTransferRequest(request, user)
        });
    } catch (error) {
        console.error("Transfer create error:", error);
        return res.status(500).json({ error: "Cererea de transfer nu a putut fi salvată." });
    }
});

app.post("/api/transfers/:id/decision", requireAuth, async (req, res) => {
    try {
        await loadTransferState({ force: true });

        const id = String(req.params.id || "");
        const department = normalizeTransferDepartment(req.body?.department);
        const decision = String(req.body?.decision || "").trim().toUpperCase();
        const user = req.session.user;

        if (!["APPROVED", "REJECTED"].includes(decision)) {
            return res.status(400).json({ error: "Decizia este invalidă." });
        }

        if (!department) return res.status(400).json({ error: "Structura de aprobare este invalidă." });
        if (department !== "POLITIE") {
            return res.status(403).json({ error: "Decizia DIICOT poate fi dată doar de pe site-ul DIICOT." });
        }
        if (!canApprovePoliceTransfer(user)) {
            return res.status(403).json({ error: "Nu ai acces la aprobarea conducerii Poliției." });
        }

        const request = transferState.requests.find(row => String(row.id) === id);
        if (!request) return res.status(404).json({ error: "Cererea nu a fost găsită." });
        if (["REJECTED", "COMPLETED"].includes(request.status)) {
            return res.status(400).json({ error: "Cererea este deja finalizată." });
        }

        const prefix = department === "POLITIE" ? "police" : "diicot";
        if (request[`${prefix}Decision`] !== "PENDING") {
            return res.status(400).json({ error: "Această conducere a luat deja o decizie." });
        }

        request[`${prefix}Decision`] = decision;
        request[`${prefix}DecisionById`] = String(user.id);
        request[`${prefix}DecisionByName`] = user.displayName || user.username || "Conducere";
        request[`${prefix}DecisionAt`] = new Date().toISOString();

        if (decision === "REJECTED") {
            request.status = "REJECTED";
        } else if (request.policeDecision === "APPROVED" && request.diicotDecision === "APPROVED") {
            try {
                const result = await transferDiscordRoles(request);
                request.status = "COMPLETED";
                request.completedAt = new Date().toISOString();
                request.targetRank = result.targetRank;
            } catch (discordError) {
                console.error("Transfer Discord execution error:", discordError?.response?.data || discordError);
                request.status = "APPROVED_WAITING_EXECUTION";
                request.executionError = discordError?.response?.data?.message || discordError?.message || "Eroare Discord";
            }
        } else {
            request.status = "PENDING";
        }

        await saveTransferState();

        let dm = `📋 ACTUALIZARE TRANSFER\n\n${department === "POLITIE" ? "Conducerea Poliției" : "Conducerea DIICOT"} a ${decision === "APPROVED" ? "APROBAT" : "RESPINS"} cererea ta.`;
        if (request.status === "COMPLETED") {
            dm += `\n\n✅ Transferul a fost efectuat automat.\nNoul grad: ${request.targetRank}.`;
        } else if (request.status === "REJECTED") {
            dm += "\n\n❌ Cererea de transfer a fost închisă.";
        } else if (request.status === "APPROVED_WAITING_EXECUTION") {
            dm += "\n\n⚠️ Ambele conduceri au aprobat, dar modificarea rolurilor Discord trebuie reverificată.";
        } else {
            dm += "\n\nCererea așteaptă și decizia celeilalte conduceri.";
        }

        sendDiscordDM(String(request.userId), dm)
            .catch(err => console.warn("Transfer DM decision:", err?.message || err));

        return res.json({
            success: true,
            message: request.status === "COMPLETED"
                ? "Ambele conduceri au aprobat. Transferul a fost efectuat."
                : "Decizia a fost salvată.",
            request: publicTransferRequest(request, user)
        });
    } catch (error) {
        console.error("Transfer decision error:", error);
        return res.status(500).json({ error: "Decizia nu a putut fi salvată." });
    }
});





// ======================================================
// 404 API
// ======================================================

app.use(
    "/api",

    (
        req,
        res
    ) => {

        res
            .status(404)
            .json({
                error:
                    "Ruta API nu există."
            });
    }
);


// ======================================================
// ERROR HANDLER
// ======================================================

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Server Error:",
            error
        );


        if (
            error instanceof
            multer.MulterError
        ) {

            if (
                error.code ===
                "LIMIT_FILE_SIZE"
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "O imagine depășește limita de 8 MB."
                    });
            }


            if (
                error.code ===
                "LIMIT_FILE_COUNT"
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Poți încărca maximum 5 imagini."
                    });
            }


            return res
                .status(400)
                .json({
                    error:
                        error.message
                });
        }


        if (
            error?.message ===
            "Sunt acceptate doar imagini JPG, PNG și WEBP."
        ) {

            return res
                .status(400)
                .json({
                    error:
                        error.message
                });
        }


        if (
            res.headersSent
        ) {

            return next(
                error
            );
        }


        res
            .status(500)
            .json({
                error:
                    "A apărut o eroare internă pe server."
            });
    }
);



// ======================================================
// START SERVER (Node/Render) + EXPORT (Cloudflare Workers)
// ======================================================

if (process.env.CLOUDFLARE_WORKERS !== "1") {
    app.listen(
        PORT,
        () => {
            console.log(`Politie Command Center rulează pe portul ${PORT}`);
            console.log(`Discord Guild: ${GUILD_ID || "NECONFIGURAT"}`);
            console.log(`Supabase: ${SUPABASE_URL ? "CONFIGURAT" : "NECONFIGURAT"}`);
            configureB2CorsForDirectUpload();
            initMeetingAttendanceScheduler();
            initLeaveRoleScheduler();
        }
    );
}

module.exports = {
    app,
    configureB2CorsForDirectUpload,
    syncApprovedLeaveDiscordRoles,
    initMeetingAttendanceScheduler
};
