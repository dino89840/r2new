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
const MULTIPART_THRESHOLD = 8 * 1024 * 1024;    // 8MB — below this, simple PUT
const PART_SIZE = 10 * 1024 * 1024;              // 10MB per part (smaller = faster flush, less timeout risk)
const MAX_RETRIES = 8;                           // more retries for large files
const RETRY_BASE_DELAY_MS = 1500;
const INTER_PART_DELAY_MS = 30;
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
const INTER_ACCOUNT_DELAY_MS = 300;
const DOWNLOAD_CHUNK_TIMEOUT_MS = 30000;         // 30s timeout per read chunk
const PIPELINE_BUFFER_COUNT = 2;                 // double-buffer: download next part while uploading current

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

// ============ Timeout-aware stream reader ============

function readWithTimeout(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  timeoutMs: number
): Promise<ReadableStreamReadResult<Uint8Array>> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(new Error(`Stream read timed out after ${timeoutMs}ms`));
      }
    }, timeoutMs);

    reader.read().then(
      (result) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve(result);
        }
      },
      (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
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

// ============ Retry wrapper with smarter backoff ============

async function withRetry<T>(
  label: string,
  fn: () => Promise<T>,
  maxRetries: number = MAX_RETRIES
): Promise<T> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      const errMsg = (err as Error).message || String(err);
      console.error(
        `[${label}] attempt ${attempt}/${maxRetries} failed: ${errMsg}`
      );
      if (attempt < maxRetries) {
        const base = RETRY_BASE_DELAY_MS * Math.pow(1.5, attempt - 1);
        const jitter = base * 0.3 * (Math.random() * 2 - 1);
        const waitMs = Math.min(30000, Math.round(base + jitter)); // cap at 30s
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

    const res = await fetch(url, {
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

    const res = await fetch(url, { method: "POST", headers });
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

      const res = await fetch(url, {
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

    const res = await fetch(url, {
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
  // Retry abort to ensure cleanup
  for (let attempt = 0; attempt < 3; attempt++) {
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

      const res = await fetch(url, { method: "DELETE", headers });
      await res.body?.cancel();

      if (res.ok || res.status === 404) {
        console.log(`[${account.label}] Multipart abort successful`);
        return;
      }
    } catch {
      // retry
    }
    if (attempt < 2) await delay(1000);
  }
  console.warn(`[${account.label}] Multipart abort may have failed — orphaned upload possible`);
}

// ============ Check if source supports Range requests ============

async function checkRangeSupport(remoteUrl: string): Promise<boolean> {
  try {
    const res = await fetch(remoteUrl, {
      method: "HEAD",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      },
      redirect: "follow",
    });
    const acceptRanges = res.headers.get("accept-ranges") || "";
    await res.body?.cancel();
    return acceptRanges.toLowerCase().includes("bytes");
  } catch {
    return false;
  }
}

// ============ Download a specific byte range from source ============

async function downloadRange(
  remoteUrl: string,
  start: number,
  end: number
): Promise<Uint8Array> {
  return await withRetry(`DownloadRange ${start}-${end}`, async () => {
    const res = await fetch(remoteUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Encoding": "identity",
        Range: `bytes=${start}-${end}`,
      },
      redirect: "follow",
    });

    if (!res.ok && res.status !== 206) {
      const text = await res.text();
      throw new Error(`Range download failed: ${res.status} ${text}`);
    }

    return new Uint8Array(await res.arrayBuffer());
  });
}

// ============================================================
// STRATEGY A: Range-based download+upload (most reliable for large files)
// Downloads each part independently using Range requests
// If one part fails, only that part needs to retry — not the whole file
// ============================================================

async function rangeBasedUploadToAccount(
  account: R2Account,
  objectKey: string,
  remoteUrl: string,
  contentType: string,
  totalSize: number,
  onProgress?: (info: {
    account: string;
    loaded: number;
    total: number;
    percent: number;
    partNum: number;
  }) => void
): Promise<number> {
  console.log(`[${account.label}] Range-based upload for ${objectKey} (${(totalSize / 1024 / 1024).toFixed(1)} MB)`);

  const uploadId = await initiateMultipart(account, objectKey, contentType);
  console.log(`[${account.label}] Multipart initiated: ${uploadId.substring(0, 16)}...`);

  const totalParts = Math.ceil(totalSize / PART_SIZE);
  const parts: { partNumber: number; etag: string }[] = [];
  let totalUploaded = 0;

  try {
    for (let i = 0; i < totalParts; i++) {
      const partNumber = i + 1;
      const start = i * PART_SIZE;
      const end = Math.min(start + PART_SIZE - 1, totalSize - 1);
      const expectedPartSize = end - start + 1;

      console.log(
        `[${account.label}] Part ${partNumber}/${totalParts}: bytes ${start}-${end} (${(expectedPartSize / 1024 / 1024).toFixed(1)} MB)`
      );

      // Download this part's range (with its own retries)
      const partData = await downloadRange(remoteUrl, start, end);

      if (partData.byteLength === 0) {
        throw new Error(`Part ${partNumber} downloaded 0 bytes`);
      }

      // Upload this part (with its own retries)
      const etag = await uploadPart(account, objectKey, uploadId, partNumber, partData);
      parts.push({ partNumber, etag });

      totalUploaded += partData.byteLength;

      if (onProgress) {
        const percent = Math.min(99, Math.round((totalUploaded / totalSize) * 100));
        onProgress({
          account: account.label,
          loaded: totalUploaded,
          total: totalSize,
          percent,
          partNum: partNumber,
        });
      }

      // Small delay between parts to be nice to both source and R2
      if (i < totalParts - 1) {
        await delay(INTER_PART_DELAY_MS);
      }
    }

    await completeMultipart(account, objectKey, uploadId, parts);
    console.log(
      `[${account.label}] Complete! ${parts.length} parts, ${(totalUploaded / 1024 / 1024).toFixed(1)} MB`
    );

    return totalUploaded;
  } catch (err) {
    console.error(`[${account.label}] Range-based upload failed, aborting multipart...`);
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

// ============================================================
// STRATEGY B: Stream-based with pipeline buffering + read timeout
// Used when source doesn't support Range requests
// Double-buffer: fills next part while uploading current
// ============================================================

async function streamPipelineToAccount(
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
  console.log(`[${account.label}] Stream-pipeline upload for ${objectKey}`);

  const dlRes = await fetch(remoteUrl, {
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Accept-Encoding": "identity",
    },
    redirect: "follow",
  });

  if (!dlRes.ok) {
    throw new Error(`Download failed: ${dlRes.status} ${dlRes.statusText}`);
  }

  const actualSize = parseInt(dlRes.headers.get("content-length") || "0", 10) || expectedSize;

  // Simple PUT for small files
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

  // Double buffer system: fill one while uploading the other
  const bufferA = new Uint8Array(PART_SIZE);
  const bufferB = new Uint8Array(PART_SIZE);
  let currentBuffer = bufferA;
  let bufferOffset = 0;
  let pendingUpload: Promise<void> | null = null;

  const flushPart = async (isFinal: boolean) => {
    if (bufferOffset === 0) return;

    partNumber++;
    const currentPartNum = partNumber;
    const currentSize = bufferOffset;

    // Create a copy of data to upload (so we can start filling next buffer)
    const partData = new Uint8Array(bufferOffset);
    partData.set(currentBuffer.subarray(0, bufferOffset));

    // Switch to other buffer for next part's data
    currentBuffer = currentBuffer === bufferA ? bufferB : bufferA;
    bufferOffset = 0;

    // Wait for any previous upload to finish before starting new one
    if (pendingUpload) {
      await pendingUpload;
      pendingUpload = null;
    }

    console.log(
      `[${account.label}] Part ${currentPartNum} (${(currentSize / 1024 / 1024).toFixed(1)} MB)...`
    );

    const uploadPromise = (async () => {
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
    })();

    if (isFinal) {
      // Final part: must wait for completion
      await uploadPromise;
    } else {
      // Non-final: let it run in background while we fill next buffer
      pendingUpload = uploadPromise;
    }
  };

  try {
    let consecutiveTimeouts = 0;

    while (true) {
      let result: ReadableStreamReadResult<Uint8Array>;
      try {
        result = await readWithTimeout(reader, DOWNLOAD_CHUNK_TIMEOUT_MS);
        consecutiveTimeouts = 0; // reset on success
      } catch (timeoutErr) {
        consecutiveTimeouts++;
        console.warn(
          `[${account.label}] Stream read timeout #${consecutiveTimeouts}`
        );

        if (consecutiveTimeouts >= 3) {
          throw new Error(
            `Stream read timed out ${consecutiveTimeouts} consecutive times — connection likely dead`
          );
        }
        // On first/second timeout, try reading again (stream might just be slow)
        continue;
      }

      if (result.done) break;

      const value = result.value;
      let chunkOffset = 0;
      while (chunkOffset < value.byteLength) {
        const spaceLeft = PART_SIZE - bufferOffset;
        const copyLen = Math.min(spaceLeft, value.byteLength - chunkOffset);

        currentBuffer.set(
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

    // Wait for any in-flight upload
    if (pendingUpload) {
      await pendingUpload;
      pendingUpload = null;
    }

    // Flush remaining bytes as final part
    await flushPart(true);

    if (parts.length === 0) {
      throw new Error("No data downloaded");
    }

    // Sort parts by number (they should be in order but just in case)
    parts.sort((a, b) => a.partNumber - b.partNumber);

    await completeMultipart(account, objectKey, uploadId, parts);
    console.log(
      `[${account.label}] Complete! ${parts.length} parts, ${(totalUploaded / 1024 / 1024).toFixed(1)} MB`
    );

    return totalUploaded;
  } catch (err) {
    console.error(`[${account.label}] Stream pipeline failed, aborting...`);
    try { reader.cancel(); } catch { /* ignore */ }
    if (pendingUpload) {
      try { await pendingUpload; } catch { /* ignore */ }
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

      const etag = await uploadPart(account, objectKey, uploadId, partNumber, partData);
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
// Handle Remote URL Upload — COMPLETELY REWRITTEN
//
// Key improvements:
// 1. Range-based strategy (preferred): downloads each part independently
//    — if part 25/38 fails, only that part retries, not the whole 600MB
//    — no long-lived stream connection that can timeout
// 2. Stream pipeline fallback: double-buffer + read timeout detection
//    — downloads next part while uploading current (keeps stream alive)
// 3. Robust abort: retries abort to prevent orphaned multipart uploads
// 4. Per-account fresh attempts: if Account-1 fails, Account-2 still tries
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

  // ===== Probe remote file =====
  let remoteContentType = "application/octet-stream";
  let contentLength = 0;
  let supportsRange = false;

  try {
    const probeRes = await fetch(remoteUrl, {
      method: "HEAD",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      },
      redirect: "follow",
    });

    remoteContentType =
      probeRes.headers.get("content-type") || "application/octet-stream";
    contentLength = parseInt(
      probeRes.headers.get("content-length") || "0",
      10
    );

    const acceptRanges = probeRes.headers.get("accept-ranges") || "";
    supportsRange = acceptRanges.toLowerCase().includes("bytes");

    await probeRes.body?.cancel();
  } catch (err) {
    console.warn(`HEAD request failed, will detect from GET: ${(err as Error).message}`);
  }

  // If HEAD didn't confirm Range support, do a quick verification
  if (!supportsRange && contentLength > MULTIPART_THRESHOLD) {
    supportsRange = await checkRangeSupport(remoteUrl);
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
  console.log(
    `Remote upload: ${uniqueName} (${expectedSizeMB}, range=${supportsRange ? "yes" : "no"})`
  );

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

    const dlRes = await fetch(remoteUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      },
      redirect: "follow",
    });
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

  // ========== LARGE FILE ==========

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

    // Build progress callback for this account
    const accountProgressCb = onProgress
      ? (info: { account: string; loaded: number; total: number; percent: number; partNum: number }) => {
          const accountWeight = 100 / accounts.length;
          const accountBase = idx * accountWeight;
          const withinAccount = (info.percent / 100) * accountWeight;
          const overallPercent = Math.min(99, Math.round(accountBase + withinAccount));

          onProgress({
            loaded: info.loaded,
            total: info.total,
            percent: overallPercent,
            phase: `${info.account}_part_${info.partNum}`,
          });
        }
      : undefined;

    try {
      let uploadedSize: number;

      if (supportsRange && contentLength > 0) {
        // ====== STRATEGY A: Range-based (best for large files) ======
        console.log(`[${account.label}] Using RANGE-BASED strategy`);
        uploadedSize = await rangeBasedUploadToAccount(
          account,
          uniqueName,
          remoteUrl,
          remoteContentType,
          contentLength,
          accountProgressCb
        );
      } else {
        // ====== STRATEGY B: Stream pipeline (fallback) ======
        console.log(`[${account.label}] Using STREAM-PIPELINE strategy`);
        uploadedSize = await streamPipelineToAccount(
          account,
          uniqueName,
          remoteUrl,
          remoteContentType,
          contentLength,
          accountProgressCb
        );
      }

      successes.push(account.label);
      if (uploadedSize > finalSize) finalSize = uploadedSize;

      console.log(
        `[${account.label}] Success: ${(uploadedSize / 1024 / 1024).toFixed(1)} MB`
      );

      if (idx < accounts.length - 1) {
        console.log(`Pausing ${INTER_ACCOUNT_DELAY_MS}ms before next account...`);
        await delay(INTER_ACCOUNT_DELAY_MS);
      }
    } catch (err) {
      const msg = (err as Error).message;
      console.error(`[${account.label}] FAILED: ${msg}`);
      errors.push(`${account.label}: ${msg}`);
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
