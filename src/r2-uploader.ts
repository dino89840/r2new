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
const PART_SIZE = 10 * 1024 * 1024;                // 10MB per part (Worker-friendly)
const MAX_RETRIES = 7;
const RETRY_BASE_DELAY_MS = 1500;
const INTER_PART_DELAY_MS = 150;
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
const INTER_ACCOUNT_DELAY_MS = 500;
const FETCH_TIMEOUT_MS = 120_000;

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
// Stream download from URL → multipart upload to ONE R2 account
// Memory: only ONE part buffer (~10MB) at any time
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

  // If small enough for simple PUT
  if (actualSize > 0 && actualSize <= MULTIPART_THRESHOLD) {
    console.log(`[${account.label}] Small file — simple PUT`);
    const buf = new Uint8Array(await dlRes.arrayBuffer());
    await uploadSimplePut(account, objectKey, buf, contentType);
    return buf.byteLength;
  }

  // Initiate multipart
  const uploadId = await initiateMultipart(account, objectKey, contentType);
  console.log(`[${account.label}] Multipart initiated: ${uploadId.substring(0, 16)}...`);

  const reader = dlRes.body!.getReader();
  const parts: { partNumber: number; etag: string }[] = [];

  let partNumber = 0;
  let totalUploaded = 0;
  let partBuffer = new Uint8Array(PART_SIZE);
  let bufferOffset = 0;

  const flushPart = async (isFinal: boolean) => {
    if (bufferOffset === 0) return;
    partNumber++;
    const currentPartNum = partNumber;
    const currentSize = bufferOffset;

    const partData = new Uint8Array(bufferOffset);
    partData.set(partBuffer.subarray(0, bufferOffset));
    bufferOffset = 0; // Reset immediately so buffer can be reused

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

    // Flush remaining bytes
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
// Stream upload from request body to ONE R2 account
// ★ NEW: Streams directly from request — no full buffer in memory
// ============================================================

async function streamRequestToOneAccount(
  account: R2Account,
  objectKey: string,
  stream: ReadableStream<Uint8Array>,
  contentType: string,
  expectedSize: number,
  onPartDone?: (partNum: number, uploaded: number) => void
): Promise<number> {
  // For small files, read the whole thing (it's small anyway)
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

  // Multipart streaming upload
  const uploadId = await initiateMultipart(account, objectKey, contentType);
  console.log(`[${account.label}] Multipart initiated for direct upload`);

  const reader = stream.getReader();
  const parts: { partNumber: number; etag: string }[] = [];
  let partNumber = 0;
  let totalUploaded = 0;
  let partBuffer = new Uint8Array(PART_SIZE);
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

// ============ Handle Direct File Upload ============
// ★ CHANGED: Sequential upload using streams
// Account 1 streams from request, Account 2 uses stored parts
// For reliability, we buffer the data once and upload to each account sequentially
// This avoids the memory explosion of formData().arrayBuffer()

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

  // ★ For files under MULTIPART_THRESHOLD, buffer is fine (small)
  if (fileSize <= MULTIPART_THRESHOLD) {
    const buffer = new Uint8Array(await file.arrayBuffer());

    const successes: string[] = [];
    const errors: string[] = [];

    // Sequential uploads for small files
    for (const account of accounts) {
      try {
        await uploadSimplePut(account, uniqueName, buffer, mime);
        console.log(`[${account.label}] Done`);
        successes.push(account.label);
      } catch (err) {
        const msg = (err as Error).message || String(err);
        console.error(`[${account.label}] Failed: ${msg}`);
        errors.push(`${account.label}: ${msg}`);
      }
    }

    if (successes.length === 0) {
      throw new Error(`All R2 uploads failed: ${errors.join("; ")}`);
    }

    return {
      filename: uniqueName,
      size: buffer.byteLength,
      links: buildDownloadLinks(uniqueName, accounts),
      uploadedTo: successes,
    };
  }

  // ★ LARGE FILE: Stream-read from file, upload part-by-part to each account SEQUENTIALLY
  // We read the file into part-sized chunks and store them temporarily,
  // then upload to each account one at a time.
  // Max memory: ~10MB (one part at a time per account) + part ETags storage

  // Strategy: Read file stream → upload parts to Account-1 → re-read → upload parts to Account-2
  // Since File objects support .stream() which can be called multiple times,
  // we can stream to each account separately.

  const successes: string[] = [];
  const errors: string[] = [];

  for (const account of accounts) {
    try {
      console.log(`[${account.label}] Starting streaming multipart upload (${(fileSize / 1024 / 1024).toFixed(1)} MB)`);

      // Get a fresh stream for each account
      const fileStream = file.stream() as ReadableStream<Uint8Array>;

      await streamRequestToOneAccount(
        account,
        uniqueName,
        fileStream,
        mime,
        fileSize,
        (partNum, uploaded) => {
          console.log(
            `[${account.label}] Progress: part ${partNum}, ${(uploaded / 1024 / 1024).toFixed(1)} MB uploaded`
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

    // Small delay between accounts
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
// Handle Remote URL Upload
// ★ CHANGED: SEQUENTIAL — Upload to accounts one at a time
// Each account gets its OWN fresh download stream
// This avoids double-bandwidth and connection contention
//
// Per account: max 2 connections (1 download + 1 part upload)
// Memory: ~10MB (1 part buffer)
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

  // ========== LARGE FILE: upload to accounts SEQUENTIALLY, each with own download ==========

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
              // Calculate progress: each account gets an equal portion of the progress bar
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

    // Delay between accounts to let connections fully close
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
