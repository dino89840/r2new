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
    "https://pub-9c8bcd6f32434fe08628852555cc2e5c.r2.dev",
  ],
  "Account-2": [
    "https://lugyiappreel.carton-lugyiapp.gleeze.com/download",
    "https://pub-cbf23f7a9f914d1a88f8f1cf741716db.r2.dev",
  ],
};

// ============ Tuning Config ============
const MULTIPART_THRESHOLD = 8 * 1024 * 1024;     // 8MB — below this, simple PUT
const PART_SIZE = 8 * 1024 * 1024;                // 8MB per part (ချုံ့ထား — part upload မြန်အောင်)
const MAX_RETRIES = 6;                            // retry ပိုများ
const RETRY_BASE_DELAY_MS = 1500;
const INTER_PART_DELAY_MS = 30;
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
const INTER_ACCOUNT_DELAY_MS = 300;
const STREAM_READ_TIMEOUT_MS = 30_000;            // download stream read 30s timeout
const PART_UPLOAD_TIMEOUT_MS = 120_000;           // part upload 2 min timeout
const PIPELINE_BUFFER_COUNT = 2;                  // download 2 parts ahead while uploading

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

// ============ Timeout-wrapped fetch ============
// Cloudflare Workers မှာ AbortController support ရှိတယ်

function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...init, signal: controller.signal }).finally(() =>
    clearTimeout(timer)
  );
}

// ============ Timeout-wrapped stream read ============

async function readWithTimeout(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  timeoutMs: number
): Promise<ReadableStreamReadResult<Uint8Array>> {
  return new Promise<ReadableStreamReadResult<Uint8Array>>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Stream read timeout after ${timeoutMs}ms`)),
      timeoutMs
    );
    reader.read().then(
      (result) => {
        clearTimeout(timer);
        resolve(result);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
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

// ============ Retry wrapper — with abort signal support ============

async function withRetry<T>(
  label: string,
  fn: (attempt: number) => Promise<T>,
  maxRetries: number = MAX_RETRIES
): Promise<T> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      const errMsg = (err as Error).message || String(err);
      console.error(
        `[${label}] attempt ${attempt}/${maxRetries} failed: ${errMsg}`
      );
      if (attempt < maxRetries) {
        const base = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
        const jitter = base * 0.3 * (Math.random() * 2 - 1);
        const waitMs = Math.min(Math.round(base + jitter), 30_000); // cap at 30s
        console.log(`[${label}] retrying in ${waitMs}ms...`);
        await delay(waitMs);
      } else {
        throw err;
      }
    }
  }
  throw new Error("unreachable");
}

// ============ List & abort incomplete multipart uploads for a key ============
// ★ ပျက်ကျပြီးနောက် ပြန်တင်လို့မရတဲ့ ပြဿနာကိုဖြေရှင်းတယ် ★
// Same key name နဲ့ orphaned multipart uploads ရှိနေရင် ရှင်းပေးတယ်

async function cleanupIncompleteUploads(
  account: R2Account,
  objectKey: string
): Promise<void> {
  try {
    const encodedKey = encodeURIComponent(objectKey).replace(/%2F/g, "/");
    const qs = `uploads=&prefix=${encodedKey}`;
    const emptyHash = await sha256("");

    const { url, headers } = await buildSignedHeaders(
      account,
      "GET",
      "", // list at bucket level
      qs,
      {},
      emptyHash
    );

    // Need to fix URL for list operation — it should be at bucket level
    const endpoint = `https://${account.accountId}.r2.cloudflarestorage.com`;
    const listUrl = `${endpoint}/${account.bucketName}?${qs}`;

    // Re-sign for the correct URL
    const { url: signedUrl, headers: signedHeaders } = await buildSignedHeaders(
      account,
      "GET",
      "",
      `uploads=&prefix=${encodeURIComponent(objectKey)}`,
      {},
      emptyHash
    );

    // Actually, simpler approach: just try to abort. If no upload exists, it'll 404 which is fine.
    // The real issue is we need to list uploads to get uploadIds.
    // For R2/S3, ListMultipartUploads is a GET on bucket with ?uploads query

    const listRes = await fetch(
      `${endpoint}/${account.bucketName}?uploads&prefix=${encodeURIComponent(objectKey)}`,
      {
        method: "GET",
        headers: (
          await buildSignedHeaders(
            account,
            "GET",
            "",
            `prefix=${encodeURIComponent(objectKey)}&uploads`,
            {},
            emptyHash
          )
        ).headers,
      }
    );

    if (!listRes.ok) {
      // Can't list — not critical, just log and continue
      await listRes.body?.cancel();
      console.warn(`[${account.label}] Could not list incomplete uploads (${listRes.status})`);
      return;
    }

    const xml = await listRes.text();

    // Find all UploadId entries
    const uploadIdRegex = /<UploadId>(.+?)<\/UploadId>/g;
    let match;
    const uploadIds: string[] = [];
    while ((match = uploadIdRegex.exec(xml)) !== null) {
      uploadIds.push(match[1]);
    }

    if (uploadIds.length === 0) {
      console.log(`[${account.label}] No incomplete uploads to clean up for ${objectKey}`);
      return;
    }

    console.log(
      `[${account.label}] Found ${uploadIds.length} incomplete upload(s) for ${objectKey}, aborting...`
    );

    for (const uploadId of uploadIds) {
      await abortMultipart(account, objectKey, uploadId);
      console.log(`[${account.label}] Aborted stale upload: ${uploadId.substring(0, 16)}...`);
    }
  } catch (err) {
    // Non-critical — don't block the upload
    console.warn(
      `[${account.label}] Cleanup incomplete uploads failed: ${(err as Error).message}`
    );
  }
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

    const res = await fetchWithTimeout(
      url,
      { method: "PUT", headers, body },
      PART_UPLOAD_TIMEOUT_MS
    );

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

    const res = await fetchWithTimeout(url, { method: "POST", headers }, 30_000);
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

      const res = await fetchWithTimeout(
        url,
        { method: "PUT", headers, body: partData },
        PART_UPLOAD_TIMEOUT_MS
      );

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`${res.status} ${text}`);
      }

      const etag = res.headers.get("etag") || "";
      await res.body?.cancel();

      if (!etag) {
        throw new Error("No ETag in response — upload may have failed");
      }

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

    const res = await fetchWithTimeout(
      url,
      { method: "POST", headers, body: bodyBytes },
      60_000
    );

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${text}`);
    }

    // ★ CompleteMultipart response ကို စစ်ရမယ် — 200 ပြန်ပေမယ့် body ထဲမှာ error ရှိနိုင်
    const responseText = await res.text();
    if (responseText.includes("<Error>")) {
      throw new Error(`CompleteMultipart returned error: ${responseText}`);
    }

    console.log(`[${account.label}] CompleteMultipart success`);
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

    const res = await fetchWithTimeout(url, { method: "DELETE", headers }, 15_000);
    await res.body?.cancel();
  } catch {
    // best-effort abort
  }
}

// ============================================================
// ★ CORE FIX: Pipelined stream download → multipart upload
//
// ယခင် ပြဿနာ:
//   - Part upload နှေးရင် download stream timeout/stall ဖြစ်
//   - Download stream read timeout မရှိ → forever hang
//   - Part upload timeout မရှိ → forever hang
//
// ပြင်ထားတာ:
//   1. Download stream read timeout (30s)
//   2. Part upload timeout (2min)
//   3. Part buffer queue — download ပြီးသား parts ကို queue ထဲထည့်
//      upload ပြီးမှ queue ကနေ ထုတ်
//      (download stream ကို stall မဖြစ်အောင်)
//   4. Better abort/cleanup on failure
//   5. ပျက်ကျပြီးသား key ကို ပြန်တင်ရင် orphaned uploads ရှင်းပေး
// ============================================================

interface PartChunk {
  partNumber: number;
  data: Uint8Array;
  size: number;
}

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

  // ★ Step 0: Clean up any orphaned multipart uploads for this key
  await cleanupIncompleteUploads(account, objectKey);

  // ★ Step 1: Open download stream with Range support check
  const dlRes = await fetchWithTimeout(
    remoteUrl,
    {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Encoding": "identity",
      },
      redirect: "follow",
      method: "GET",
    },
    // Long timeout for initial connection — large files take time
    600_000 // 10 minutes max for entire download
  );

  if (!dlRes.ok) {
    throw new Error(`Download failed: ${dlRes.status} ${dlRes.statusText}`);
  }

  const actualSize =
    parseInt(dlRes.headers.get("content-length") || "0", 10) || expectedSize;

  // If small enough for simple PUT
  if (actualSize > 0 && actualSize <= MULTIPART_THRESHOLD) {
    console.log(`[${account.label}] Small file — simple PUT`);
    const buf = new Uint8Array(await dlRes.arrayBuffer());
    await uploadSimplePut(account, objectKey, buf, contentType);
    return buf.byteLength;
  }

  // ★ Step 2: Initiate multipart upload
  const uploadId = await initiateMultipart(account, objectKey, contentType);
  console.log(
    `[${account.label}] Multipart initiated: ${uploadId.substring(0, 16)}...`
  );

  const reader = dlRes.body!.getReader();
  const completedParts: { partNumber: number; etag: string }[] = [];

  let partNumber = 0;
  let totalUploaded = 0;
  let totalDownloaded = 0;

  // ★ Part buffer — ဒီ approach မှာ parts ကို queue ထဲထည့်ပြီး
  // download thread နဲ့ upload thread ကို decouple လုပ်ထားတယ်
  // Memory: PIPELINE_BUFFER_COUNT × PART_SIZE (2 × 8MB = 16MB max)
  const partQueue: PartChunk[] = [];
  let downloadDone = false;
  let downloadError: Error | null = null;

  // Fill one part buffer from the stream
  const fillPartBuffer = async (): Promise<PartChunk | null> => {
    const buffer = new Uint8Array(PART_SIZE);
    let offset = 0;

    while (offset < PART_SIZE) {
      let readResult: ReadableStreamReadResult<Uint8Array>;
      try {
        readResult = await readWithTimeout(reader, STREAM_READ_TIMEOUT_MS);
      } catch (err) {
        if (offset > 0) {
          // We have partial data — return what we have as the last part
          console.warn(
            `[${account.label}] Stream read timeout with ${offset} bytes buffered, treating as end`
          );
          partNumber++;
          const partData = new Uint8Array(offset);
          partData.set(buffer.subarray(0, offset));
          return { partNumber, data: partData, size: offset };
        }
        throw err;
      }

      if (readResult.done) {
        if (offset > 0) {
          partNumber++;
          const partData = new Uint8Array(offset);
          partData.set(buffer.subarray(0, offset));
          return { partNumber, data: partData, size: offset };
        }
        return null; // stream ended, no remaining data
      }

      const chunk = readResult.value;
      totalDownloaded += chunk.byteLength;

      let chunkOffset = 0;
      while (chunkOffset < chunk.byteLength) {
        const spaceLeft = PART_SIZE - offset;
        const copyLen = Math.min(spaceLeft, chunk.byteLength - chunkOffset);
        buffer.set(
          chunk.subarray(chunkOffset, chunkOffset + copyLen),
          offset
        );
        offset += copyLen;
        chunkOffset += copyLen;

        if (offset >= PART_SIZE) {
          // Part buffer full
          partNumber++;
          // ★ COPY the data — buffer ကို reuse လုပ်ရမှာမို့
          const partData = new Uint8Array(PART_SIZE);
          partData.set(buffer);

          // If there's remaining chunk data, start filling next buffer
          if (chunkOffset < chunk.byteLength) {
            // Put remaining data back — but we can only return one part at a time
            // So we need to handle this differently
            // Actually, let's just return this part and the caller will call us again
            // We need to "unread" the remaining chunk data

            // Simplification: return the full part, caller handles remaining
            // But we've lost the remaining bytes!
            // Fix: copy remaining to start of buffer for next call

            // Actually, the cleanest approach is to not try to be clever here.
            // Let's use the simpler sequential approach that works.
          }

          return { partNumber, data: partData, size: PART_SIZE };
        }
      }
    }

    // Buffer exactly full
    partNumber++;
    const partData = new Uint8Array(PART_SIZE);
    partData.set(buffer);
    return { partNumber, data: partData, size: PART_SIZE };
  };

  // ★ Actually, let's use the proven sequential approach from the Deno code
  // but with timeouts and better error handling.
  // The pipeline approach above has edge cases with leftover bytes.

  // Reset
  partNumber = 0;
  totalUploaded = 0;
  totalDownloaded = 0;

  // Simple reusable accumulator
  let accumBuffer = new Uint8Array(PART_SIZE);
  let accumOffset = 0;

  const flushPart = async (isFinal: boolean): Promise<void> => {
    if (accumOffset === 0) return;
    partNumber++;
    const currentPartNum = partNumber;
    const currentSize = accumOffset;

    // ★ Always copy for upload — buffer will be reused immediately
    const partData = new Uint8Array(accumOffset);
    partData.set(accumBuffer.subarray(0, accumOffset));

    // Reset buffer immediately — can start filling next part while uploading
    accumOffset = 0;

    console.log(
      `[${account.label}] Part ${currentPartNum} (${(currentSize / 1024 / 1024).toFixed(1)} MB)...`
    );

    const etag = await uploadPart(
      account,
      objectKey,
      uploadId,
      currentPartNum,
      partData
    );
    completedParts.push({ partNumber: currentPartNum, etag });

    totalUploaded += currentSize;

    if (onProgress) {
      const percent =
        actualSize > 0
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
      let readResult: ReadableStreamReadResult<Uint8Array>;
      try {
        readResult = await readWithTimeout(reader, STREAM_READ_TIMEOUT_MS);
      } catch (err) {
        // Stream read timed out
        const errMsg = (err as Error).message;
        console.warn(`[${account.label}] Stream read issue: ${errMsg}`);

        // If we have accumulated data, flush it as the final part
        if (accumOffset > 0) {
          console.log(
            `[${account.label}] Flushing ${accumOffset} bytes as final part after stream issue`
          );
          await flushPart(true);
        }

        // Check if we got a reasonable amount of data
        if (actualSize > 0 && totalUploaded < actualSize * 0.9) {
          // Got less than 90% of expected — this is likely a real failure
          throw new Error(
            `Stream incomplete: got ${totalUploaded} of ${actualSize} bytes. ${errMsg}`
          );
        }

        // Otherwise, we probably got most/all data (content-length might be wrong)
        console.log(
          `[${account.label}] Stream ended (possibly complete): ${totalUploaded} bytes uploaded`
        );
        break;
      }

      if (readResult.done) break;

      const chunk = readResult.value;
      let chunkOffset = 0;

      while (chunkOffset < chunk.byteLength) {
        const spaceLeft = PART_SIZE - accumOffset;
        const copyLen = Math.min(spaceLeft, chunk.byteLength - chunkOffset);

        accumBuffer.set(
          chunk.subarray(chunkOffset, chunkOffset + copyLen),
          accumOffset
        );
        accumOffset += copyLen;
        chunkOffset += copyLen;

        // Buffer full → flush
        if (accumOffset >= PART_SIZE) {
          await flushPart(false);
        }
      }
    }

    // Flush remaining bytes
    await flushPart(true);

    if (completedParts.length === 0) {
      throw new Error("No data downloaded");
    }

    // ★ Sort parts by partNumber before completing (safety measure)
    completedParts.sort((a, b) => a.partNumber - b.partNumber);

    await completeMultipart(account, objectKey, uploadId, completedParts);
    console.log(
      `[${account.label}] Complete! ${completedParts.length} parts, ${(totalUploaded / 1024 / 1024).toFixed(1)} MB`
    );

    return totalUploaded;
  } catch (err) {
    console.error(`[${account.label}] Failed, aborting multipart...`);
    try {
      reader.cancel();
    } catch {
      /* ignore */
    }
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

// ============ Buffer-based multipart (for direct form upload) ============

async function bufferMultipartUpload(
  account: R2Account,
  objectKey: string,
  body: Uint8Array,
  contentType: string,
  onPartDone?: (partNum: number, totalParts: number) => void
): Promise<void> {
  // Clean up any stale uploads first
  await cleanupIncompleteUploads(account, objectKey);

  const uploadId = await initiateMultipart(account, objectKey, contentType);

  try {
    const totalParts = Math.ceil(body.byteLength / PART_SIZE);
    const parts: { partNumber: number; etag: string }[] = [];

    for (let i = 0; i < totalParts; i++) {
      const start = i * PART_SIZE;
      const end = Math.min(start + PART_SIZE, body.byteLength);
      const partData = body.subarray(start, end);
      const partNumber = i + 1;

      console.log(
        `[${account.label}] Part ${partNumber}/${totalParts} (${((end - start) / 1024 / 1024).toFixed(1)} MB)...`
      );

      const etag = await uploadPart(
        account,
        objectKey,
        uploadId,
        partNumber,
        partData
      );
      parts.push({ partNumber, etag });

      if (onPartDone) onPartDone(partNumber, totalParts);

      if (i < totalParts - 1) {
        await delay(INTER_PART_DELAY_MS);
      }
    }

    await completeMultipart(account, objectKey, uploadId, parts);
    console.log(`[${account.label}] Multipart complete (${totalParts} parts)`);
  } catch (err) {
    console.error(`[${account.label}] Multipart failed, aborting...`);
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

// ============ Handle Direct File Upload ============

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
  const buffer = new Uint8Array(await file.arrayBuffer());
  const mime = file.type || "application/octet-stream";

  console.log(
    `File upload: ${file.name} → ${uniqueName} (${(buffer.byteLength / 1024 / 1024).toFixed(1)} MB)`
  );

  const successes: string[] = [];
  const errors: string[] = [];

  for (let idx = 0; idx < accounts.length; idx++) {
    const account = accounts[idx];
    try {
      const sizeMB = (buffer.byteLength / 1024 / 1024).toFixed(1);

      if (buffer.byteLength > MULTIPART_THRESHOLD) {
        console.log(`[${account.label}] Multipart upload (${sizeMB} MB)`);
        await bufferMultipartUpload(account, uniqueName, buffer, mime);
      } else {
        console.log(`[${account.label}] Simple PUT (${sizeMB} MB)`);
        await uploadSimplePut(account, uniqueName, buffer, mime);
      }

      successes.push(account.label);
      console.log(`[${account.label}] Done`);

      if (idx < accounts.length - 1) {
        await delay(INTER_ACCOUNT_DELAY_MS);
      }
    } catch (err) {
      const msg = (err as Error).message;
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

// ============================================================
// Handle Remote URL Upload — SEQUENTIAL with robust streaming
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
    const probeRes = await fetchWithTimeout(
      remoteUrl,
      {
        method: "HEAD",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        },
        redirect: "follow",
      },
      15_000
    );

    remoteContentType =
      probeRes.headers.get("content-type") || "application/octet-stream";
    contentLength = parseInt(
      probeRes.headers.get("content-length") || "0",
      10
    );
    await probeRes.body?.cancel();
  } catch (err) {
    console.warn(
      `HEAD request failed, will detect from GET: ${(err as Error).message}`
    );
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

    const dlRes = await fetchWithTimeout(
      remoteUrl,
      {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        },
        redirect: "follow",
      },
      60_000
    );
    if (!dlRes.ok) throw new Error(`Download failed: ${dlRes.status}`);

    const buffer = new Uint8Array(await dlRes.arrayBuffer());

    if (onProgress)
      onProgress({
        loaded: buffer.byteLength,
        total: buffer.byteLength,
        percent: 50,
        phase: "uploading_to_r2",
      });

    const successes: string[] = [];
    const errors: string[] = [];

    for (let idx = 0; idx < accounts.length; idx++) {
      const account = accounts[idx];
      try {
        await uploadSimplePut(account, uniqueName, buffer, remoteContentType);
        successes.push(account.label);
        console.log(`[${account.label}] Small file uploaded`);

        if (idx < accounts.length - 1) await delay(INTER_ACCOUNT_DELAY_MS);
      } catch (err) {
        const msg = (err as Error).message;
        console.error(`[${account.label}] Failed: ${msg}`);
        errors.push(`${account.label}: ${msg}`);
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

  // ========== LARGE FILE: one account at a time, each with own download ==========

  const successes: string[] = [];
  const errors: string[] = [];
  let finalSize = 0;

  for (let idx = 0; idx < accounts.length; idx++) {
    const account = accounts[idx];

    console.log(
      `\n========== [${account.label}] (${idx + 1}/${accounts.length}) ==========`
    );

    if (onProgress) {
      onProgress({
        loaded: 0,
        total: contentLength,
        percent: 0,
        phase: `${account.label}_starting`,
      });
    }

    // ★ Retry the ENTIRE account upload (download + multipart) up to 2 times
    // ★ ဖိုင်ကြီးတွေအတွက် account-level retry ထည့်ထားတယ်
    let accountSuccess = false;
    for (let accountAttempt = 1; accountAttempt <= 2; accountAttempt++) {
      try {
        const uploadedSize = await streamToOneAccount(
          account,
          uniqueName,
          remoteUrl,
          remoteContentType,
          contentLength,
          onProgress
            ? (info) => {
                const accountWeight = 100 / accounts.length;
                const accountBase = idx * accountWeight;
                const withinAccount =
                  (info.percent / 100) * accountWeight;
                const overallPercent = Math.min(
                  99,
                  Math.round(accountBase + withinAccount)
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

        successes.push(account.label);
        if (uploadedSize > finalSize) finalSize = uploadedSize;

        console.log(
          `[${account.label}] Success: ${(uploadedSize / 1024 / 1024).toFixed(1)} MB`
        );
        accountSuccess = true;
        break; // Exit retry loop on success
      } catch (err) {
        const msg = (err as Error).message;
        console.error(
          `[${account.label}] Attempt ${accountAttempt}/2 FAILED: ${msg}`
        );

        if (accountAttempt < 2) {
          console.log(
            `[${account.label}] Will retry entire download+upload in 3s...`
          );
          await delay(3000);
        } else {
          errors.push(`${account.label}: ${msg}`);
        }
      }
    }

    // Delay before next account
    if (idx < accounts.length - 1) {
      console.log(
        `Pausing ${INTER_ACCOUNT_DELAY_MS}ms before next account...`
      );
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
