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
  WORKER_AUTH_SECRET?: string; // Internal auth token for self-invocation
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
const MULTIPART_THRESHOLD = 10 * 1024 * 1024;    // 10MB
const PART_SIZE = 25 * 1024 * 1024;              // 25MB per part — parts နည်းအောင်
const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 2000;
const INTER_PART_DELAY_MS = 50;
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

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
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
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

// ============ AWS Signature V4 ============

async function hmacSHA256(key: ArrayBuffer | Uint8Array, message: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message));
}

async function sha256(data: Uint8Array | string): Promise<string> {
  const encoded = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return arrayBufferToHex(hash);
}

async function getSignatureKey(key: string, dateStamp: string, region: string, service: string): Promise<ArrayBuffer> {
  const kDate = await hmacSHA256(new TextEncoder().encode("AWS4" + key), dateStamp);
  const kRegion = await hmacSHA256(kDate, region);
  const kService = await hmacSHA256(kRegion, service);
  return await hmacSHA256(kService, "aws4_request");
}

async function buildSignedHeaders(
  account: R2Account, method: string, objectKey: string, queryString: string,
  extraHeaders: Record<string, string>, payloadHash: string
): Promise<{ url: string; headers: Record<string, string> }> {
  const endpoint = `https://${account.accountId}.r2.cloudflarestorage.com`;
  const region = "auto";
  const service = "s3";
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.substring(0, 8);

  const encodedKey = encodeURIComponent(objectKey).replace(/%2F/g, "/");
  const canonicalUri = `/${account.bucketName}/${encodedKey}`;
  const host = `${account.accountId}.r2.cloudflarestorage.com`;

  const allHeaders: Record<string, string> = {
    ...extraHeaders, host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate,
  };

  const signedHeaderKeys = Object.keys(allHeaders).sort();
  const signedHeadersStr = signedHeaderKeys.join(";");
  const canonicalHeaders = signedHeaderKeys.map((k) => `${k}:${allHeaders[k]}\n`).join("");

  const canonicalRequest = [method, canonicalUri, queryString, canonicalHeaders, signedHeadersStr, payloadHash].join("\n");
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, await sha256(canonicalRequest)].join("\n");

  const signingKey = await getSignatureKey(account.secretAccessKey, dateStamp, region, service);
  const signatureBuffer = await hmacSHA256(signingKey, stringToSign);
  const authorization = `AWS4-HMAC-SHA256 Credential=${account.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${arrayBufferToHex(signatureBuffer)}`;

  return {
    url: `${endpoint}${canonicalUri}${queryString ? "?" + queryString : ""}`,
    headers: { ...allHeaders, Authorization: authorization },
  };
}

async function withRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt < MAX_RETRIES) {
        const waitMs = Math.round(RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1) + Math.random() * 500);
        console.log(`[${label}] retrying in ${waitMs}ms...`);
        await delay(waitMs);
      } else {
        throw err;
      }
    }
  }
  throw new Error("unreachable");
}

// ============ Upload Primitives ============

async function uploadSimplePut(account: R2Account, objectKey: string, body: Uint8Array, contentType: string): Promise<void> {
  await withRetry(`${account.label} PUT`, async () => {
    const { url, headers } = await buildSignedHeaders(account, "PUT", objectKey, "", { "content-length": body.byteLength.toString(), "content-type": contentType }, UNSIGNED_PAYLOAD);
    const res = await fetch(url, { method: "PUT", headers, body });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    await res.body?.cancel();
  });
}

async function initiateMultipart(account: R2Account, objectKey: string, contentType: string): Promise<string> {
  return await withRetry(`${account.label} InitMultipart`, async () => {
    const { url, headers } = await buildSignedHeaders(account, "POST", objectKey, "uploads=", { "content-type": contentType }, await sha256(""));
    const res = await fetch(url, { method: "POST", headers });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    const match = (await res.text()).match(/<UploadId>(.+?)<\/UploadId>/);
    if (!match) throw new Error("No UploadId in response");
    return match[1];
  });
}

async function uploadPart(account: R2Account, objectKey: string, uploadId: string, partNumber: number, partData: Uint8Array): Promise<string> {
  return await withRetry(`${account.label} Part#${partNumber}`, async () => {
    const qs = `partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId)}`;
    const { url, headers } = await buildSignedHeaders(account, "PUT", objectKey, qs, { "content-length": partData.byteLength.toString() }, UNSIGNED_PAYLOAD);
    const res = await fetch(url, { method: "PUT", headers, body: partData });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    const etag = res.headers.get("etag") || "";
    await res.body?.cancel();

    const cleanEtag = etag.replace(/"/g, "");
    return `"${cleanEtag}"`;
  });
}

async function completeMultipart(account: R2Account, objectKey: string, uploadId: string, parts: { partNumber: number; etag: string }[]): Promise<void> {
  await withRetry(`${account.label} CompleteMultipart`, async () => {
    const xmlParts = parts.map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`).join("");
    const bodyStr = `<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">${xmlParts}</CompleteMultipartUpload>`;
    const bodyBytes = new TextEncoder().encode(bodyStr);

    const { url, headers } = await buildSignedHeaders(account, "POST", objectKey, `uploadId=${encodeURIComponent(uploadId)}`, { "content-length": bodyBytes.byteLength.toString(), "content-type": "application/xml" }, await sha256(bodyBytes));
    const res = await fetch(url, { method: "POST", headers, body: bodyBytes });
    if (!res.ok) throw new Error(`Status: ${res.status}, Response: ${await res.text()}`);
    await res.body?.cancel();
  });
}

async function abortMultipart(account: R2Account, objectKey: string, uploadId: string): Promise<void> {
  try {
    const { url, headers } = await buildSignedHeaders(account, "DELETE", objectKey, `uploadId=${encodeURIComponent(uploadId)}`, {}, await sha256(""));
    const res = await fetch(url, { method: "DELETE", headers });
    await res.body?.cancel();
  } catch {}
}

// ============ Stream-based multipart upload for a SINGLE account ============
// DownloadStream -> Buffer chunks -> Upload parts sequentially
// Account တစ်ခုတည်းအတွက်သာ — subrequest budget ကို account တစ်ခုတည်းက သုံးသည်

async function streamToSingleAccount(
  account: R2Account,
  remoteUrl: string,
  objectKey: string,
  contentType: string,
  contentLength: number
): Promise<{ size: number }> {
  const fetchHeaders: Record<string, string> = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  };

  const dlRes = await fetch(remoteUrl, { headers: fetchHeaders, redirect: "follow" });
  if (!dlRes.ok) throw new Error(`Download failed: ${dlRes.status}`);

  const actualContentType = dlRes.headers.get("content-type") || contentType;

  // Small file — simple PUT
  if (contentLength > 0 && contentLength <= MULTIPART_THRESHOLD) {
    const buffer = new Uint8Array(await dlRes.arrayBuffer());
    await uploadSimplePut(account, objectKey, buffer, actualContentType);
    return { size: buffer.byteLength };
  }

  // Large file — streaming multipart
  const uploadId = await initiateMultipart(account, objectKey, actualContentType);
  const reader = dlRes.body!.getReader();

  let chunks: Uint8Array[] = [];
  let currentChunkSize = 0;
  let partNumber = 0;
  let totalUploaded = 0;
  const parts: { partNumber: number; etag: string }[] = [];

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      chunks.push(value);
      currentChunkSize += value.byteLength;

      if (currentChunkSize >= PART_SIZE) {
        partNumber++;
        const mergedBuffer = new Uint8Array(currentChunkSize);
        let offset = 0;
        for (const chunk of chunks) {
          mergedBuffer.set(chunk, offset);
          offset += chunk.byteLength;
        }

        const etag = await uploadPart(account, objectKey, uploadId, partNumber, mergedBuffer);
        parts.push({ partNumber, etag });

        totalUploaded += currentChunkSize;
        chunks = [];
        currentChunkSize = 0;

        if (partNumber < 999) await delay(INTER_PART_DELAY_MS);
      }
    }

    // Flush remaining
    if (currentChunkSize > 0) {
      partNumber++;
      const mergedBuffer = new Uint8Array(currentChunkSize);
      let offset = 0;
      for (const chunk of chunks) {
        mergedBuffer.set(chunk, offset);
        offset += chunk.byteLength;
      }

      const etag = await uploadPart(account, objectKey, uploadId, partNumber, mergedBuffer);
      parts.push({ partNumber, etag });
      totalUploaded += currentChunkSize;
      chunks = [];
      currentChunkSize = 0;
    }

    await completeMultipart(account, objectKey, uploadId, parts);
    return { size: totalUploaded };

  } catch (err) {
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

// ============ Handle Direct Form Upload ============

async function bufferMultipartUpload(
  account: R2Account, objectKey: string, body: Uint8Array, contentType: string, onPartDone?: (partNum: number, totalParts: number) => void
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

      const etag = await uploadPart(account, objectKey, uploadId, partNumber, partData);
      parts.push({ partNumber, etag });

      if (onPartDone) onPartDone(partNumber, totalParts);
      if (i < totalParts - 1) await delay(INTER_PART_DELAY_MS);
    }

    await completeMultipart(account, objectKey, uploadId, parts);
  } catch (err) {
    await abortMultipart(account, objectKey, uploadId);
    throw err;
  }
}

export async function handleUpload(req: Request, env: Env): Promise<{ filename: string; size: number; links: string[]; uploadedTo: string[] }> {
  const contentType = req.headers.get("content-type") || "";
  if (!contentType.includes("multipart/form-data")) throw new Error("Unsupported content type");

  const accounts = getR2Accounts(env);
  const formData = await req.formData();
  const file = formData.get("file") as File | null;
  if (!file) throw new Error("No file provided");

  const ext = getExtension(file.name, file.type);
  const uniqueName = generateUniqueFilename(ext);
  const buffer = new Uint8Array(await file.arrayBuffer());
  const mime = file.type || "application/octet-stream";

  const successes: string[] = [];
  const errors: string[] = [];

  for (const account of accounts) {
    try {
      if (buffer.byteLength > MULTIPART_THRESHOLD) {
        await bufferMultipartUpload(account, uniqueName, buffer, mime);
      } else {
        await uploadSimplePut(account, uniqueName, buffer, mime);
      }
      successes.push(account.label);
    } catch (err) {
      errors.push(`${account.label}: ${(err as Error).message}`);
    }
  }

  if (successes.length === 0) throw new Error(`All R2 uploads failed: ${errors.join("; ")}`);

  return { filename: uniqueName, size: buffer.byteLength, links: buildDownloadLinks(uniqueName, accounts), uploadedTo: successes };
}

// ============================================================
// Internal endpoint handler — Worker self-invoke for single account upload
// ============================================================

export async function handleInternalSingleAccountUpload(
  req: Request, env: Env
): Promise<Response> {
  try {
    const body = await req.json() as {
      remoteUrl: string;
      accountIndex: number;
      objectKey: string;
      contentType: string;
      contentLength: number;
    };

    const accounts = getR2Accounts(env);
    const account = accounts[body.accountIndex];
    if (!account) {
      return new Response(JSON.stringify({ success: false, error: "Invalid account index" }), { status: 400 });
    }

    const result = await streamToSingleAccount(
      account, body.remoteUrl, body.objectKey, body.contentType, body.contentLength
    );

    return new Response(JSON.stringify({
      success: true,
      label: account.label,
      size: result.size,
    }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({
      success: false,
      error: (err as Error).message,
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// ============================================================
// Handle Remote URL Upload — Self-invoke approach
// Main invocation: HEAD probe + dispatch sub-invocations (one per account)
// Each sub-invocation: independently downloads + streams upload to ONE account
// ============================================================

export async function handleRemoteUpload(
  remoteUrl: string,
  env: Env,
  selfUrl: string, // Worker's own URL e.g. "https://lugyipro.casacam.net"
  onProgress?: (progress: { loaded: number; total: number; percent: number; phase: string }) => void
): Promise<{ filename: string; size: number; links: string[]; uploadedTo: string[] }> {
  const accounts = getR2Accounts(env);
  if (onProgress) onProgress({ loaded: 0, total: 0, percent: 0, phase: "connecting" });

  let remoteContentType = "application/octet-stream";
  let contentLength = 0;

  const fetchHeaders: Record<string, string> = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  };

  // HEAD probe — 1 subrequest
  try {
    const probeRes = await fetch(remoteUrl, { method: "HEAD", headers: fetchHeaders, redirect: "follow" });
    remoteContentType = probeRes.headers.get("content-type") || remoteContentType;
    contentLength = parseInt(probeRes.headers.get("content-length") || "0", 10);
    await probeRes.body?.cancel();
  } catch (err) {
    console.warn(`HEAD request failed: ${(err as Error).message}`);
  }

  const uniqueName = generateUniqueFilename(getExtension(new URL(remoteUrl).pathname || "file", remoteContentType));

  if (onProgress) onProgress({ loaded: 0, total: contentLength, percent: 5, phase: "dispatching" });

  const authSecret = env.WORKER_AUTH_SECRET || "internal-worker-secret-key";

  // Dispatch parallel self-invocations — 1 subrequest per account (total 2)
  // Each sub-invocation is a NEW Worker invocation with its own 50 subrequest budget
  const results = await Promise.all(
    accounts.map(async (account, index) => {
      try {
        const res = await fetch(`${selfUrl}/__internal/upload-single-account`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Internal-Auth": authSecret,
          },
          body: JSON.stringify({
            remoteUrl,
            accountIndex: index,
            objectKey: uniqueName,
            contentType: remoteContentType,
            contentLength,
          }),
        });

        const data = await res.json() as { success: boolean; label?: string; size?: number; error?: string };
        return data;
      } catch (err) {
        return { success: false, error: `[${account.label}] Dispatch error: ${(err as Error).message}` };
      }
    })
  );

  const successes: string[] = [];
  const errors: string[] = [];
  let finalSize = 0;

  for (const r of results) {
    if (r.success && r.label) {
      successes.push(r.label);
      if (r.size && r.size > finalSize) finalSize = r.size;
    } else {
      errors.push(r.error || "Unknown error");
    }
  }

  if (successes.length === 0) {
    throw new Error(`Upload Process Failed: ${errors.join(" | ")}`);
  }

  if (onProgress) onProgress({ loaded: finalSize || contentLength, total: finalSize || contentLength, percent: 100, phase: "complete" });

  return {
    filename: uniqueName,
    size: finalSize || contentLength,
    links: buildDownloadLinks(uniqueName, accounts),
    uploadedTo: successes,
  };
}
