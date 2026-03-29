// ============ R2 Account Config Interface ============
export interface R2Account {
  accountId: string;
  accessKeyId: string;
  secretAccessKey: string;
  bucketName: string;
  label: string;
}

export interface Env {
  R2_ACC1_ACCOUNT_ID: string;
  R2_ACC1_ACCESS_KEY_ID: string;
  R2_ACC1_SECRET_ACCESS_KEY: string;
  R2_ACC1_BUCKET_NAME: string;
  R2_ACC2_ACCOUNT_ID: string;
  R2_ACC2_ACCESS_KEY_ID: string;
  R2_ACC2_SECRET_ACCESS_KEY: string;
  R2_ACC2_BUCKET_NAME: string;
}

const DOWNLOAD_LINKS_MAP: Record<string, string[]> = {
  "Account-1": [
    "https://kajarling.kajarling.ooguy.com/download",
    "https://lugyiapplication.nanmoelay.ooguy.com/download",
  ],
  "Account-2": [
    "https://lugyiappreel.carton-lugyiapp.gleeze.com/download",
    "https://lugi.samalay.ooguy.com/download",
  ],
};

// ============ Tuning Config ============
const MULTIPART_THRESHOLD = 5 * 1024 * 1024;      // 5MB — below this, simple PUT
const PART_SIZE = 10 * 1024 * 1024;                // 10MB per part (Worker memory-safe)
const CHUNK_SIZE = 80 * 1024 * 1024;               // 80MB per client chunk (under 100MB plan limit)
const MAX_RETRIES = 7;
const RETRY_BASE_DELAY_MS = 1500;
const INTER_PART_DELAY_MS = 150;
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
const INTER_ACCOUNT_DELAY_MS = 500;
const FETCH_TIMEOUT_MS = 120_000;

// ============ In-flight multipart upload sessions ============
// Stores active upload sessions for chunked uploads
// Key: sessionId, Value: session data per account
interface UploadSession {
  objectKey: string;
  contentType: string;
  accounts: {
    account: R2Account;
    uploadId: string;
    parts: { partNumber: number; etag: string }[];
    nextPartNumber: number;
  }[];
  totalSize: number;
  uploadedSize: number;
  createdAt: number;
}

// Global session store (lives as long as the isolate)
const uploadSessions = new Map<string, UploadSession>();

// Clean up old sessions (older than 30 min)
function cleanupSessions(): void {
  const now = Date.now();
  for (const [id, session] of uploadSessions) {
    if (now - session.createdAt > 30 * 60 * 1000) {
      uploadSessions.delete(id);
    }
  }
}

// ============ Build R2 accounts from env ============
export function getR2Accounts(env: Env): R2Account[] {
  return [
    {
      accountId: env.R2_ACC1_ACCOUNT_ID,
      accessKeyId: env.R2_ACC1_ACCESS_KEY_ID,
      secretAccessKey: env.R2_ACC1_SECRET_ACCESS_KEY,
      bucketName: env.R2_ACC1_BUCKET_NAME,
      label: "Account-1",
    },
    {
      accountId: env.R2_ACC2_ACCOUNT_ID,
      accessKeyId: env.R2_ACC2_ACCESS_KEY_ID,
      secretAccessKey: env.R2_ACC2_SECRET_ACCESS_KEY,
      bucketName: env.R2_ACC2_BUCKET_NAME,
      label: "Account-2",
    },
  ];
}

// ============ Utility Functions ============

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function generateUniqueFilename(extension: string): string {
  const timestamp = Date.now();
  const randomBytes = crypto.getRandomValues(new Uint8Array(8));
  const randomHex = arrayBufferToHex(randomBytes.buffer);
  return `${timestamp}_${randomHex}${extension}`;
}

function generateSessionId(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  return arrayBufferToHex(randomBytes.buffer);
}

function getExtension(filename: string, contentType?: string): string {
  const match = filename.match(/\.([a-zA-Z0-9]+)(\?.*)?$/);
  if (match) return `.${match[1].toLowerCase()}`;

  const mimeMap: Record<string, string> = {
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "video/x-matroska": ".mkv",
    "video/quicktime": ".mov",
    "video/x-msvideo": ".avi",
    "video/x-flv": ".flv",
    "audio/mpeg": ".mp3",
    "audio/mp4": ".m4a",
    "audio/ogg": ".ogg",
    "audio/wav": ".wav",
    "audio/flac": ".flac",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/x-rar-compressed": ".rar",
    "application/x-7z-compressed": ".7z",
    "application/gzip": ".gz",
    "application/json": ".json",
    "text/plain": ".txt",
    "text/html": ".html",
    "application/octet-stream": ".bin",
  };

  if (contentType) {
    const base = contentType.split(";")[0].trim().toLowerCase();
    if (mimeMap[base]) return mimeMap[base];
  }

  return ".mp4";
}

export function buildDownloadLinks(filename: string, accounts: R2Account[]): string[] {
  const links: string[] = [];
  for (const account of accounts) {
    const bases = DOWNLOAD_LINKS_MAP[account.label] || [];
    for (const base of bases) {
      links.push(`${base}/${filename}`);
    }
  }
  return links;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============ Fetch with Timeout ============

async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs: number = FETCH_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return res;
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      throw new Error(`Request timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ============ AWS Signature V4 (Web Crypto API) ============

async function hmacSHA256(
  key: ArrayBuffer | Uint8Array,
  message: string
): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(message)
  );
}

async function sha256(data: Uint8Array | string): Promise<string> {
  const encoded =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return arrayBufferToHex(hash);
}

async function getSignatureKey(
  key: string,
  dateStamp: string,
  region: string,
  service: string
): Promise<ArrayBuffer> {
  const kDate = await hmacSHA256(
    new TextEncoder().encode("AWS4" + key),
    dateStamp
  );
  const kRegion = await hmacSHA256(kDate, region);
  const kService = await hmacSHA256(kRegion, service);
  return await hmacSHA256(kService, "aws4_request");
}

// ============ Signed Request Builder ============

async function buildSignedHeaders(
  account: R2Account,
  method: string,
  objectKey: string,
  queryString: string,
  extraHeaders: Record<string, string>,
  payloadHash: string
): Promise<{ url: string; headers: Record<string, string> }> {
  const endpoint = `https://${account.accountId}.r2.cloudflarestorage.com`;
  const region = "auto";
  const service = "s3";

  const now = new Date();
  const amzDate = now
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");
  const dateStamp = amzDate.substring(0, 8);

  const encodedKey = encodeURIComponent(objectKey).replace(/%2F/g, "/");
  const canonicalUri = `/${account.bucketName}/${encodedKey}`;
  const host = `${account.accountId}.r2.cloudflarestorage.com`;

  const allHeaders: Record<string, string> = {
    ...extraHeaders,
    host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };

  const signedHeaderKeys = Object.keys(allHeaders).sort();
  const signedHeadersStr = signedHeaderKeys.join(";");
  const canonicalHeaders = signedHeaderKeys
    .map((k) => `${k}:${allHeaders[k]}\n`)
    .join("");

  const canonicalRequest = [
    method,
    canonicalUri,
    queryString,
    canonicalHeaders,
    signedHeadersStr,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256(canonicalRequest),
  ].join("\n");

  const signingKey = await getSignatureKey(
    account.secretAccessKey,
    dateStamp,
    region,
    service
  );
  const signatureBuffer = await hmacSHA256(signingKey, stringToSign);
  const signature = arrayBufferToHex(signatureBuffer);

  const authorization = `AWS4-HMAC-SHA256 Credential=${account.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  const fullUrl = `${endpoint}${canonicalUri}${queryString ? "?" + queryString : ""}`;

  return {
    url: fullUrl,
    headers: {
      ...allHeaders,
      Authorization: authorization,
    },
  };
}

// ============ Retry wrapper ============

async function withRetry<T>(
  label: string,
  fn: () => Promise<T>
): Promise<T> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      const errMsg = (err as Error).message || String(err);
      console.error(
        `[${label}] attempt ${attempt}/${MAX_RETRIES} failed: ${errMsg}`
      );
      if (attempt < MAX_RETRIES) {
        const base = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
        const jitter = base * 0.3 * (Math.random() * 2 - 1);
        const waitMs = Math.round(base + jitter);
        console.log(`[${label}] retrying in ${waitMs}ms...`);
        await delay(waitMs);
      } else {
        throw err;
      }
    }
  }
  throw new Error("unreachable");
}

// ============ Simple PUT upload ============

async function uploadSimplePut(
  account: R2Account,
  objectKey: string,
  body: Uint8Array,
  contentType: string
): Promise<void> {
  await withRetry(`${account.label} PUT`, async () => {
    const { url, headers } = await buildSignedHeaders(
      account,
      "PUT",
      objectKey,
      "",
      {
        "content-length": body.byteLength.toString(),
        "content-type": contentType,
      },
      UNSIGNED_PAYLOAD
    );

    const res = await fetchWithTimeout(url, {
      method: "PUT",
      headers,
      body,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${text}`);
    }
    await res.body?.cancel();
  });
}

// ============ Multipart Upload Primitives ============

async function initiateMultipart(
  account: R2Account,
  objectKey: string,
  contentType: string
): Promise<string> {
  return await withRetry(`${account.label} InitMultipart`, async () => {
    const emptyHash = await sha256("");

    const { url, headers } = await buildSignedHeaders(
      account,
      "POST",
      objectKey,
      "uploads=",
      { "content-type": contentType },
      emptyHash
    );

    const res = await fetchWithTimeout(url, { method: "POST", headers });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${text}`);
    }

    const xml = await res.text();
    const match = xml.match(/<UploadId>(.+?)<\/UploadId>/);
    if (!match) throw new Error("No UploadId in response");
    return match[1];
  });
}

async function uploadPart(
  account: R2Account,
  objectKey: string,
  uploadId: string,
  partNumber: number,
  partData: Uint8Array
): Promise<string> {
  return await withRetry(
    `${account.label} Part#${partNumber}`,
    async () => {
      const qs = `partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`;

      const { url, headers } = await buildSignedHeaders(
        account,
        "PUT",
        objectKey,
        qs,
        { "content-length": partData.byteLength.toString() },
        UNSIGNED_PAYLOAD
      );

      const res = await fetchWithTimeout(url, {
        method: "PUT",
        headers,
        body: partData,
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`${res.status} ${text}`);
      }

      const etag = res.headers.get("etag") || "";
      await res.body?.cancel();
      return etag;
    }
  );
}

async function completeMultipart(
  account: R2Account,
  objectKey: string,
  uploadId: string,
  parts: { partNumber: number; etag: string }[]
): Promise<void> {
  await withRetry(`${account.label} CompleteMultipart`, async () => {
    const xmlParts = parts
      .map(
        (p) =>
          `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`
      )
      .join("");
    const bodyStr = `<CompleteMultipartUpload>${xmlParts}</CompleteMultipartUpload>`;
    const bodyBytes = new TextEncoder().encode(bodyStr);
    const payloadHash = await sha256(bodyBytes);
    const qs = `uploadId=${encodeURIComponent(uploadId)}`;

    const { url, headers } = await buildSignedHeaders(
      account,
      "POST",
      objectKey,
      qs,
      {
        "content-length": bodyBytes.byteLength.toString(),
        "content-type": "application/xml",
      },
      payloadHash
    );

    const res = await fetchWithTimeout(url, {
      method: "POST",
      headers,
      body: bodyBytes,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${text}`);
    }
    await res.body?.cancel();
  });
}

async function abortMultipart(
  account: R2Account,
  objectKey: string,
  uploadId: string
): Promise<void> {
  try {
    const qs = `uploadId=${encodeURIComponent(uploadId)}`;
    const emptyHash = await sha256("");

    const { url, headers } = await buildSignedHeaders(
      account,
      "DELETE",
      objectKey,
      qs,
      {},
      emptyHash
    );

    const res = await fetchWithTimeout(url, { method: "DELETE", headers }, 30_000);
    await res.body?.cancel();
  } catch {
    // best-effort abort
  }
}

// ============================================================
// Stream from request body to R2 (for streaming uploads)
// ============================================================

async function streamRequestToOneAccount(
  account: R2Account,
  objectKey: string,
  stream: ReadableStream<Uint8Array>,
  contentType: string,
  expectedSize: number,
  onPartDone?: (partNum: number, uploaded: number) => void
): Promise<number> {
  if (expectedSize > 0 && expectedSize <= MULTIPART_THRESHOLD) {
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let totalLen = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      totalLen += value.byteLength;
    }
    const buf = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) {
      buf.set(c, offset);
      offset += c.byteLength;
    }
    await uploadSimplePut(account, objectKey, buf, contentType);
    return buf.byteLength;
  }

  const uploadId = await initiateMultipart(account, objectKey, contentType);
  console.log(`[${account.label}] Multipart initiated for direct upload`);

  const reader = stream.getReader();
  const parts: { partNumber: number; etag: string }[] = [];
  let partNumber = 0;
  let totalUploaded = 0;
  const partBuffer = new Uint8Array(PART_SIZE);
  let bufferOffset = 0;

  const flushPart = async (isFinal: boolean) => {
    if (bufferOffset === 0) return;
    partNumber++;
    const currentPartNum = partNumber;
    const currentSize = bufferOffset;

    const partData = new Uint8Array(bufferOffset);
    partData.set(partBuffer.subarray(0, bufferOffset));
    bufferOffset = 0;

    console.log(
      `[${account.label}] Part ${currentPartNum} (${(currentSize / 1024 / 1024).toFixed(1)} MB)...`
    );

    const etag = await uploadPart(account, objectKey, uploadId, currentPartNum, partData);
    parts.push({ partNumber: currentPartNum, etag });
    totalUploaded += currentSize;

    if (onPartDone) onPartDone(currentPartNum, totalUploaded);

    if (!isFinal) {
      await delay(INTER_PART_DELAY_MS);
    }
  };

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      let chunkOffset = 0;
      while (chunkOffset < value.byteLength) {
        const spaceLeft = PART_SIZE - bufferOffset;
        const copyLen = Math.min(spaceLeft, value.byteLength - chunkOffset);
        partBuffer.set(
          value.subarray(chunkOffset, chunkOffset + copyLen),
          bufferOffset
        );
        bufferOffset += copyLen;
        chunkOffset += copyLen;

        if (bufferOffset >= PART_SIZE) {
          await flushPart(false);
        }
      }
    }

    await flushPart(true);

    if (parts.length === 0) {
      throw new Error("No data received");
    }

    await completeMultipart(account, objectKey, uploadId, parts);
    console.log(
      `[${account.label}] Complete! ${parts.length} parts, ${(totalUploaded / 1024 / 1024).toFixed(1)} MB`
    );
    return totalUploaded;
  } catch (err) {
    console.error(`[${account.label}] Failed, aborting multipart...`);
    try { reader.cancel(); } catch { /* ignore */ }
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

// ============================================================
// Stream download from URL → multipart upload to ONE R2 account
// ============================================================

async function streamToOneAccount(
  account: R2Account,
  objectKey: string,
  remoteUrl: string,
  contentType: string,
  expectedSize: number,
  onProgress?: (info: {
    account: string;
    loaded: number;
    total: number;
    percent: number;
    partNum: number;
  }) => void
): Promise<number> {
  console.log(`[${account.label}] Starting download → upload for ${objectKey}`);

  const dlRes = await fetchWithTimeout(remoteUrl, {
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Accept-Encoding": "identity",
    },
    redirect: "follow",
  }, 300_000);

  if (!dlRes.ok) {
    throw new Error(`Download failed: ${dlRes.status} ${dlRes.statusText}`);
  }

  const actualSize = parseInt(dlRes.headers.get("content-length") || "0", 10) || expectedSize;

  if (actualSize > 0 && actualSize <= MULTIPART_THRESHOLD) {
    console.log(`[${account.label}] Small file — simple PUT`);
    const buf = new Uint8Array(await dlRes.arrayBuffer());
    await uploadSimplePut(account, objectKey, buf, contentType);
    return buf.byteLength;
  }

  const uploadId = await initiateMultipart(account, objectKey, contentType);
  console.log(`[${account.label}] Multipart initiated: ${uploadId.substring(0, 16)}...`);

  const reader = dlRes.body!.getReader();
  const parts: { partNumber: number; etag: string }[] = [];

  let partNumber = 0;
  let totalUploaded = 0;
  const partBuffer = new Uint8Array(PART_SIZE);
  let bufferOffset = 0;

  const flushPart = async (isFinal: boolean) => {
    if (bufferOffset === 0) return;
    partNumber++;
    const currentPartNum = partNumber;
    const currentSize = bufferOffset;

    const partData = new Uint8Array(bufferOffset);
    partData.set(partBuffer.subarray(0, bufferOffset));
    bufferOffset = 0;

    console.log(
      `[${account.label}] Part ${currentPartNum} (${(currentSize / 1024 / 1024).toFixed(1)} MB)...`
    );

    const etag = await uploadPart(account, objectKey, uploadId, currentPartNum, partData);
    parts.push({ partNumber: currentPartNum, etag });

    totalUploaded += currentSize;

    if (onProgress) {
      const percent = actualSize > 0
        ? Math.min(99, Math.round((totalUploaded / actualSize) * 100))
        : 0;
      onProgress({
        account: account.label,
        loaded: totalUploaded,
        total: actualSize,
        percent,
        partNum: currentPartNum,
      });
    }

    if (!isFinal) {
      await delay(INTER_PART_DELAY_MS);
    }
  };

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      let chunkOffset = 0;
      while (chunkOffset < value.byteLength) {
        const spaceLeft = PART_SIZE - bufferOffset;
        const copyLen = Math.min(spaceLeft, value.byteLength - chunkOffset);

        partBuffer.set(
          value.subarray(chunkOffset, chunkOffset + copyLen),
          bufferOffset
        );
        bufferOffset += copyLen;
        chunkOffset += copyLen;

        if (bufferOffset >= PART_SIZE) {
          await flushPart(false);
        }
      }
    }

    await flushPart(true);

    if (parts.length === 0) {
      throw new Error("No data downloaded");
    }

    await completeMultipart(account, objectKey, uploadId, parts);
    console.log(
      `[${account.label}] Complete! ${parts.length} parts, ${(totalUploaded / 1024 / 1024).toFixed(1)} MB`
    );

    return totalUploaded;
  } catch (err) {
    console.error(`[${account.label}] Failed, aborting multipart...`);
    try { reader.cancel(); } catch { /* ignore */ }
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

// ============================================================
// CHUNKED UPLOAD API — Client sends file in multiple HTTP requests
// This bypasses the Cloudflare request body size limit (100MB/200MB/500MB)
//
// Flow:
//   1. POST /upload/init     → returns sessionId + chunkSize
//   2. POST /upload/chunk    → sends each chunk (< plan limit)
//   3. POST /upload/complete → finalizes multipart on all accounts
//   4. POST /upload/abort    → cancels if error
// ============================================================

export async function handleChunkedInit(
  req: Request,
  env: Env
): Promise<Response> {
  cleanupSessions();

  const body = await req.json() as {
    filename: string;
    fileSize: number;
    contentType?: string;
  };

  if (!body.filename || !body.fileSize) {
    return new Response(JSON.stringify({ error: "filename and fileSize required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const accounts = getR2Accounts(env);
  const ext = getExtension(body.filename, body.contentType);
  const uniqueName = generateUniqueFilename(ext);
  const mime = body.contentType || "application/octet-stream";
  const sessionId = generateSessionId();

  console.log(`Chunked init: ${body.filename} → ${uniqueName} (${(body.fileSize / 1024 / 1024).toFixed(1)} MB)`);

  // If file is small enough for simple PUT, we don't need multipart
  if (body.fileSize <= MULTIPART_THRESHOLD) {
    const session: UploadSession = {
      objectKey: uniqueName,
      contentType: mime,
      accounts: accounts.map((acc) => ({
        account: acc,
        uploadId: "", // No multipart needed
        parts: [],
        nextPartNumber: 1,
      })),
      totalSize: body.fileSize,
      uploadedSize: 0,
      createdAt: Date.now(),
    };
    uploadSessions.set(sessionId, session);

    return new Response(
      JSON.stringify({
        sessionId,
        objectKey: uniqueName,
        chunkSize: body.fileSize, // Send entire file in one chunk
        totalChunks: 1,
        mode: "simple",
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  // Initiate multipart on all accounts sequentially
  const accountSessions: UploadSession["accounts"] = [];

  for (const account of accounts) {
    try {
      const uploadId = await initiateMultipart(account, uniqueName, mime);
      console.log(`[${account.label}] Multipart initiated: ${uploadId.substring(0, 16)}...`);
      accountSessions.push({
        account,
        uploadId,
        parts: [],
        nextPartNumber: 1,
      });
    } catch (err) {
      console.error(`[${account.label}] Failed to init multipart: ${(err as Error).message}`);
      // Abort already-initiated uploads
      for (const as of accountSessions) {
        await abortMultipart(as.account, uniqueName, as.uploadId);
      }
      return new Response(
        JSON.stringify({ error: `Failed to initialize upload on ${account.label}` }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  const session: UploadSession = {
    objectKey: uniqueName,
    contentType: mime,
    accounts: accountSessions,
    totalSize: body.fileSize,
    uploadedSize: 0,
    createdAt: Date.now(),
  };
  uploadSessions.set(sessionId, session);

  const totalChunks = Math.ceil(body.fileSize / CHUNK_SIZE);

  return new Response(
    JSON.stringify({
      sessionId,
      objectKey: uniqueName,
      chunkSize: CHUNK_SIZE,
      totalChunks,
      mode: "multipart",
    }),
    { headers: { "Content-Type": "application/json" } }
  );
}

export async function handleChunkedUpload(
  req: Request,
  env: Env
): Promise<Response> {
  const url = new URL(req.url);
  const sessionId = url.searchParams.get("sessionId");
  const chunkIndex = parseInt(url.searchParams.get("chunkIndex") || "0", 10);

  if (!sessionId) {
    return new Response(JSON.stringify({ error: "sessionId required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const session = uploadSessions.get(sessionId);
  if (!session) {
    return new Response(JSON.stringify({ error: "Session not found or expired" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Read the chunk data from request body
  const chunkData = new Uint8Array(await req.arrayBuffer());
  console.log(`Chunk ${chunkIndex} received: ${(chunkData.byteLength / 1024 / 1024).toFixed(1)} MB`);

  // Simple mode: small file, just buffer and upload on complete
  if (session.accounts[0].uploadId === "") {
    // For simple mode, store the data and upload on complete
    // Since it's small (< 5MB), just upload immediately to all accounts
    const errors: string[] = [];
    const successes: string[] = [];

    for (const accSession of session.accounts) {
      try {
        await uploadSimplePut(accSession.account, session.objectKey, chunkData, session.contentType);
        successes.push(accSession.account.label);
      } catch (err) {
        errors.push(`${accSession.account.label}: ${(err as Error).message}`);
      }
    }

    uploadSessions.delete(sessionId);

    if (successes.length === 0) {
      return new Response(
        JSON.stringify({ error: `All uploads failed: ${errors.join("; ")}` }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({
        done: true,
        filename: session.objectKey,
        size: chunkData.byteLength,
        links: buildDownloadLinks(session.objectKey, session.accounts.map((a) => a.account)),
        uploadedTo: successes,
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  // Multipart mode: split chunk into PART_SIZE pieces and upload to all accounts
  let offset = 0;
  while (offset < chunkData.byteLength) {
    const end = Math.min(offset + PART_SIZE, chunkData.byteLength);
    const partData = chunkData.subarray(offset, end);

    // Upload this part to all accounts sequentially
    for (const accSession of session.accounts) {
      const partNum = accSession.nextPartNumber;
      try {
        const etag = await uploadPart(
          accSession.account,
          session.objectKey,
          accSession.uploadId,
          partNum,
          partData
        );
        accSession.parts.push({ partNumber: partNum, etag });
        accSession.nextPartNumber++;
        console.log(
          `[${accSession.account.label}] Part ${partNum} uploaded (${(partData.byteLength / 1024 / 1024).toFixed(1)} MB)`
        );
      } catch (err) {
        console.error(
          `[${accSession.account.label}] Part ${partNum} failed: ${(err as Error).message}`
        );
        // Don't abort the whole session — other accounts might succeed
        // Mark this account as failed by setting uploadId to empty
        await abortMultipart(accSession.account, session.objectKey, accSession.uploadId);
        accSession.uploadId = "FAILED";
      }

      await delay(INTER_PART_DELAY_MS);
    }

    offset = end;
    session.uploadedSize += partData.byteLength;
  }

  const percent = session.totalSize > 0
    ? Math.min(99, Math.round((session.uploadedSize / session.totalSize) * 100))
    : 0;

  return new Response(
    JSON.stringify({
      done: false,
      chunkIndex,
      uploadedSize: session.uploadedSize,
      totalSize: session.totalSize,
      percent,
    }),
    { headers: { "Content-Type": "application/json" } }
  );
}

export async function handleChunkedComplete(
  req: Request,
  env: Env
): Promise<Response> {
  const body = await req.json() as { sessionId: string };

  if (!body.sessionId) {
    return new Response(JSON.stringify({ error: "sessionId required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const session = uploadSessions.get(body.sessionId);
  if (!session) {
    return new Response(JSON.stringify({ error: "Session not found or expired" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  const successes: string[] = [];
  const errors: string[] = [];

  for (const accSession of session.accounts) {
    if (accSession.uploadId === "FAILED" || accSession.uploadId === "") {
      errors.push(`${accSession.account.label}: previously failed`);
      continue;
    }

    if (accSession.parts.length === 0) {
      errors.push(`${accSession.account.label}: no parts uploaded`);
      await abortMultipart(accSession.account, session.objectKey, accSession.uploadId);
      continue;
    }

    try {
      await completeMultipart(
        accSession.account,
        session.objectKey,
        accSession.uploadId,
        accSession.parts
      );
      console.log(`[${accSession.account.label}] Multipart complete (${accSession.parts.length} parts)`);
      successes.push(accSession.account.label);
    } catch (err) {
      const msg = (err as Error).message || String(err);
      console.error(`[${accSession.account.label}] Complete failed: ${msg}`);
      errors.push(`${accSession.account.label}: ${msg}`);
      await abortMultipart(accSession.account, session.objectKey, accSession.uploadId);
    }
  }

  uploadSessions.delete(body.sessionId);

  if (successes.length === 0) {
    return new Response(
      JSON.stringify({ error: `All uploads failed: ${errors.join("; ")}` }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  return new Response(
    JSON.stringify({
      done: true,
      filename: session.objectKey,
      size: session.uploadedSize,
      links: buildDownloadLinks(session.objectKey, session.accounts.map((a) => a.account)),
      uploadedTo: successes,
    }),
    { headers: { "Content-Type": "application/json" } }
  );
}

export async function handleChunkedAbort(
  req: Request,
  env: Env
): Promise<Response> {
  const body = await req.json() as { sessionId: string };

  if (!body.sessionId) {
    return new Response(JSON.stringify({ error: "sessionId required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const session = uploadSessions.get(body.sessionId);
  if (session) {
    for (const accSession of session.accounts) {
      if (accSession.uploadId && accSession.uploadId !== "FAILED") {
        await abortMultipart(accSession.account, session.objectKey, accSession.uploadId);
      }
    }
    uploadSessions.delete(body.sessionId);
  }

  return new Response(
    JSON.stringify({ aborted: true }),
    { headers: { "Content-Type": "application/json" } }
  );
}

// ============ Handle Direct File Upload (small files only) ============
// For files under the Cloudflare plan limit

export async function handleUpload(
  req: Request,
  env: Env
): Promise<{
  filename: string;
  size: number;
  links: string[];
  uploadedTo: string[];
}> {
  const contentType = req.headers.get("content-type") || "";

  if (!contentType.includes("multipart/form-data")) {
    throw new Error("Unsupported content type");
  }

  const accounts = getR2Accounts(env);
  const formData = await req.formData();
  const file = formData.get("file") as File | null;
  if (!file) throw new Error("No file provided");

  const ext = getExtension(file.name, file.type);
  const uniqueName = generateUniqueFilename(ext);
  const mime = file.type || "application/octet-stream";
  const fileSize = file.size;

  console.log(
    `File upload: ${file.name} → ${uniqueName} (${(fileSize / 1024 / 1024).toFixed(1)} MB)`
  );

  const successes: string[] = [];
  const errors: string[] = [];

  // Upload to each account sequentially using streaming
  for (const account of accounts) {
    try {
      console.log(`[${account.label}] Starting upload (${(fileSize / 1024 / 1024).toFixed(1)} MB)`);

      const fileStream = file.stream() as ReadableStream<Uint8Array>;

      await streamRequestToOneAccount(
        account,
        uniqueName,
        fileStream,
        mime,
        fileSize,
        (partNum, uploaded) => {
          console.log(
            `[${account.label}] Part ${partNum}, ${(uploaded / 1024 / 1024).toFixed(1)} MB done`
          );
        }
      );

      console.log(`[${account.label}] Done`);
      successes.push(account.label);
    } catch (err) {
      const msg = (err as Error).message || String(err);
      console.error(`[${account.label}] Failed: ${msg}`);
      errors.push(`${account.label}: ${msg}`);
    }

    if (successes.length < accounts.length) {
      await delay(INTER_ACCOUNT_DELAY_MS);
    }
  }

  if (successes.length === 0) {
    throw new Error(`All R2 uploads failed: ${errors.join("; ")}`);
  }

  return {
    filename: uniqueName,
    size: fileSize,
    links: buildDownloadLinks(uniqueName, accounts),
    uploadedTo: successes,
  };
}

// ============================================================
// Handle Remote URL Upload — SEQUENTIAL per account
// ============================================================

export async function handleRemoteUpload(
  remoteUrl: string,
  env: Env,
  onProgress?: (progress: {
    loaded: number;
    total: number;
    percent: number;
    phase: string;
  }) => void
): Promise<{
  filename: string;
  size: number;
  links: string[];
  uploadedTo: string[];
}> {
  const accounts = getR2Accounts(env);

  if (onProgress)
    onProgress({ loaded: 0, total: 0, percent: 0, phase: "connecting" });

  // HEAD request to get file info
  let remoteContentType = "application/octet-stream";
  let contentLength = 0;

  try {
    const probeRes = await fetchWithTimeout(remoteUrl, {
      method: "HEAD",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      },
      redirect: "follow",
    }, 30_000);

    remoteContentType =
      probeRes.headers.get("content-type") || "application/octet-stream";
    contentLength = parseInt(
      probeRes.headers.get("content-length") || "0",
      10
    );
    await probeRes.body?.cancel();
  } catch (err) {
    console.warn(`HEAD request failed, will detect from GET: ${(err as Error).message}`);
  }

  let urlPath = "";
  try {
    urlPath = new URL(remoteUrl).pathname;
  } catch {
    /* ignore */
  }
  const ext = getExtension(urlPath || "file", remoteContentType);
  const uniqueName = generateUniqueFilename(ext);

  const expectedSizeMB =
    contentLength > 0
      ? (contentLength / 1024 / 1024).toFixed(1) + " MB"
      : "unknown size";
  console.log(`Remote upload: ${uniqueName} (expected ${expectedSizeMB})`);

  // ========== SMALL FILE: download once, upload sequentially ==========
  const isSmallFile = contentLength > 0 && contentLength <= MULTIPART_THRESHOLD;

  if (isSmallFile) {
    console.log("Small file — download once, upload sequentially");

    if (onProgress)
      onProgress({
        loaded: 0,
        total: contentLength,
        percent: 0,
        phase: "downloading",
      });

    const dlRes = await fetchWithTimeout(remoteUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      },
      redirect: "follow",
    }, 120_000);
    if (!dlRes.ok) throw new Error(`Download failed: ${dlRes.status}`);

    const buffer = new Uint8Array(await dlRes.arrayBuffer());

    if (onProgress)
      onProgress({
        loaded: buffer.byteLength,
        total: buffer.byteLength,
        percent: 30,
        phase: "uploading_to_r2",
      });

    const successes: string[] = [];
    const errors: string[] = [];

    for (let i = 0; i < accounts.length; i++) {
      const account = accounts[i];
      try {
        await uploadSimplePut(account, uniqueName, buffer, remoteContentType);
        console.log(`[${account.label}] Small file uploaded`);
        successes.push(account.label);
      } catch (err) {
        const msg = (err as Error).message || String(err);
        console.error(`[${account.label}] Failed: ${msg}`);
        errors.push(`${account.label}: ${msg}`);
      }

      if (onProgress) {
        const percent = 30 + Math.round(((i + 1) / accounts.length) * 70);
        onProgress({
          loaded: buffer.byteLength,
          total: buffer.byteLength,
          percent: Math.min(percent, 99),
          phase: `uploaded_${account.label}`,
        });
      }
    }

    if (successes.length === 0) {
      throw new Error(`All uploads failed: ${errors.join("; ")}`);
    }

    if (onProgress)
      onProgress({
        loaded: buffer.byteLength,
        total: buffer.byteLength,
        percent: 100,
        phase: "complete",
      });

    return {
      filename: uniqueName,
      size: buffer.byteLength,
      links: buildDownloadLinks(uniqueName, accounts),
      uploadedTo: successes,
    };
  }

  // ========== LARGE FILE: upload to accounts SEQUENTIALLY ==========

  console.log(`\nLarge file — uploading to ${accounts.length} accounts SEQUENTIALLY`);

  const successes: string[] = [];
  const errors: string[] = [];
  let finalSize = 0;

  for (let i = 0; i < accounts.length; i++) {
    const account = accounts[i];

    console.log(
      `\n========== [${account.label}] (${i + 1}/${accounts.length}) ==========`
    );

    try {
      const uploadedSize = await streamToOneAccount(
        account,
        uniqueName,
        remoteUrl,
        remoteContentType,
        contentLength,
        onProgress
          ? (info) => {
              const accountBasePercent = Math.round((i / accounts.length) * 100);
              const accountSharePercent = Math.round(100 / accounts.length);
              const accountProgress = Math.round(
                (info.percent / 100) * accountSharePercent
              );
              const overallPercent = Math.min(
                99,
                accountBasePercent + accountProgress
              );

              onProgress({
                loaded: info.loaded,
                total: info.total,
                percent: overallPercent,
                phase: `${info.account}_part_${info.partNum}`,
              });
            }
          : undefined
      );

      console.log(
        `[${account.label}] Success: ${(uploadedSize / 1024 / 1024).toFixed(1)} MB`
      );

      successes.push(account.label);
      if (uploadedSize > finalSize) finalSize = uploadedSize;
    } catch (err) {
      const msg = (err as Error).message || String(err);
      console.error(`[${account.label}] FAILED: ${msg}`);
      errors.push(`${account.label}: ${msg}`);
    }

    if (i < accounts.length - 1) {
      console.log(`Waiting ${INTER_ACCOUNT_DELAY_MS}ms before next account...`);
      await delay(INTER_ACCOUNT_DELAY_MS);
    }
  }

  if (successes.length === 0) {
    throw new Error(`All R2 uploads failed: ${errors.join("; ")}`);
  }

  if (onProgress) {
    onProgress({
      loaded: finalSize,
      total: finalSize,
      percent: 100,
      phase: "complete",
    });
  }

  console.log(
    `\nDone: ${successes.length}/${accounts.length} succeeded [${successes.join(", ")}]`
  );

  return {
    filename: uniqueName,
    size: finalSize,
    links: buildDownloadLinks(uniqueName, accounts),
    uploadedTo: successes,
  };
}
