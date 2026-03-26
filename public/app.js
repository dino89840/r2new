// ===== Tab Switching =====
const tabs = document.querySelectorAll(".tab");
const tabContents = document.querySelectorAll(".tab-content");

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    tabContents.forEach((tc) => tc.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
    if (tab.dataset.tab === "history") renderHistory();
  });
});

// ===== Toast =====
function showToast(message, isError = false) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.className = "toast show" + (isError ? " error" : "");
  setTimeout(() => (toast.className = "toast"), 2500);
}

// ===== Helpers =====
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    showToast("Link copied!");
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("copied");
    }, 1200);
  });
}

// ===== Show Result =====
function showResult(data) {
  const area = document.getElementById("resultArea");
  document.getElementById("resultFilename").textContent = `File: ${data.filename}`;
  document.getElementById("resultSize").textContent = `Size: ${formatBytes(data.size)}`;

  // Account badges
  const accDiv = document.getElementById("resultAccounts");
  accDiv.innerHTML = "";
  if (data.uploadedTo) {
    data.uploadedTo.forEach((acc) => {
      const badge = document.createElement("span");
      badge.className = "acc-badge";
      badge.textContent = `✓ ${acc}`;
      accDiv.appendChild(badge);
    });
  }

  // Links
  const linksEl = document.getElementById("linksContainer");
  linksEl.innerHTML = "";
  data.links.forEach((link, i) => {
    const row = document.createElement("div");
    row.className = "link-row";

    const label = document.createElement("span");
    label.className = "link-label";
    label.textContent = `#${i + 1}`;

    const input = document.createElement("input");
    input.type = "text";
    input.value = link;
    input.readOnly = true;

    const btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.addEventListener("click", () => copyToClipboard(link, btn));

    row.appendChild(label);
    row.appendChild(input);
    row.appendChild(btn);
    linksEl.appendChild(row);
  });

  // Copy all btn
  document.getElementById("copyAllBtn").onclick = () => {
    const allLinks = data.links.join("\n");
    navigator.clipboard.writeText(allLinks).then(() => {
      showToast("All links copied!");
    });
  };

  area.style.display = "block";
  area.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ===== History =====
function getHistory() {
  try {
    return JSON.parse(localStorage.getItem("r2_upload_history") || "[]");
  } catch {
    return [];
  }
}

function saveToHistory(data) {
  const history = getHistory();
  history.unshift({
    filename: data.filename,
    size: data.size,
    links: data.links,
    uploadedTo: data.uploadedTo || [],
    timestamp: Date.now(),
  });
  if (history.length > 200) history.length = 200;
  localStorage.setItem("r2_upload_history", JSON.stringify(history));
}

function renderHistory() {
  const list = document.getElementById("historyList");
  const empty = document.getElementById("emptyHistory");
  const history = getHistory();

  list.innerHTML = "";

  if (history.length === 0) {
    empty.style.display = "block";
    return;
  }

  empty.style.display = "none";

  history.forEach((item) => {
    const div = document.createElement("div");
    div.className = "history-item";

    const date = new Date(item.timestamp);
    const accText = item.uploadedTo?.length ? ` — ${item.uploadedTo.join(", ")}` : "";

    let html = `
      <div class="h-name">${item.filename}</div>
      <div class="h-meta">${formatBytes(item.size)} — ${date.toLocaleString()}${accText}</div>
      <div class="h-links"></div>
    `;
    div.innerHTML = html;

    const linksDiv = div.querySelector(".h-links");
    item.links.forEach((link, i) => {
      const row = document.createElement("div");
      row.className = "link-row";

      const label = document.createElement("span");
      label.className = "link-label";
      label.textContent = `#${i + 1}`;

      const input = document.createElement("input");
      input.type = "text";
      input.value = link;
      input.readOnly = true;

      const btn = document.createElement("button");
      btn.className = "copy-btn";
      btn.textContent = "Copy";
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        copyToClipboard(link, btn);
      });

      row.appendChild(label);
      row.appendChild(input);
      row.appendChild(btn);
      linksDiv.appendChild(row);
    });

    list.appendChild(div);
  });
}

document.getElementById("clearHistoryBtn").addEventListener("click", () => {
  if (confirm("Clear all upload history?")) {
    localStorage.removeItem("r2_upload_history");
    renderHistory();
    showToast("History cleared");
  }
});

// ===== File Upload (XHR with progress) =====
const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");

dropZone.addEventListener("click", () => fileInput.click());

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});

dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files.length > 0) uploadFile(e.dataTransfer.files[0]);
});

fileInput.addEventListener("change", () => {
  if (fileInput.files.length > 0) uploadFile(fileInput.files[0]);
});

function uploadFile(file) {
  const progressArea = document.getElementById("fileProgressArea");
  const fileInfo = document.getElementById("fileInfo");
  const progressFill = document.getElementById("fileProgressFill");
  const progressText = document.getElementById("fileProgressText");
  const speedInfo = document.getElementById("fileSpeedInfo");
  const uploadStatus = document.getElementById("fileUploadStatus");
  const resultArea = document.getElementById("resultArea");

  resultArea.style.display = "none";
  progressArea.style.display = "block";
  fileInfo.textContent = `Uploading: ${file.name} (${formatBytes(file.size)})`;
  progressFill.style.width = "0%";
  progressText.textContent = "0%";
  speedInfo.textContent = "";
  uploadStatus.textContent = "";

  const formData = new FormData();
  formData.append("file", file);

  const xhr = new XMLHttpRequest();
  const startTime = Date.now();

  xhr.upload.addEventListener("progress", (e) => {
    if (e.lengthComputable) {
      const percent = Math.round((e.loaded / e.total) * 100);
      progressFill.style.width = percent + "%";
      progressText.textContent = percent + "%";

      const elapsed = (Date.now() - startTime) / 1000;
      if (elapsed > 0) {
        const speed = e.loaded / elapsed;
        const remaining = (e.total - e.loaded) / speed;
        speedInfo.textContent = `${formatBytes(e.loaded)} / ${formatBytes(e.total)} — ${formatBytes(speed)}/s — ~${Math.ceil(remaining)}s left`;
      }

      if (percent === 100) {
        uploadStatus.textContent = "⏳ Uploading to both R2 accounts...";
      }
    }
  });

  xhr.addEventListener("load", () => {
    if (xhr.status === 200) {
      const data = JSON.parse(xhr.responseText);
      speedInfo.textContent = "Complete!";
      uploadStatus.textContent = `✅ Uploaded to: ${data.uploadedTo?.join(", ") || "R2"}`;
      showResult(data);
      saveToHistory(data);
      showToast("File uploaded to both R2 accounts!");
    } else {
      let msg = "Upload failed";
      try { msg = JSON.parse(xhr.responseText).error || msg; } catch {}
      speedInfo.textContent = "";
      uploadStatus.textContent = "❌ " + msg;
      showToast(msg, true);
    }
  });

  xhr.addEventListener("error", () => {
    uploadStatus.textContent = "❌ Network error!";
    showToast("Network error!", true);
  });

  xhr.open("POST", "/api/upload");
  xhr.send(formData);
}

// ===== URL Upload (SSE progress) =====
const urlUploadBtn = document.getElementById("urlUploadBtn");
const remoteUrlInput = document.getElementById("remoteUrl");

urlUploadBtn.addEventListener("click", () => uploadFromUrl());
remoteUrlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") uploadFromUrl();
});

async function uploadFromUrl() {
  const url = remoteUrlInput.value.trim();
  if (!url) {
    showToast("Please enter a URL", true);
    return;
  }

  const progressArea = document.getElementById("urlProgressArea");
  const fileInfo = document.getElementById("urlFileInfo");
  const phaseBadge = document.getElementById("urlPhaseBadge");
  const progressFill = document.getElementById("urlProgressFill");
  const progressText = document.getElementById("urlProgressText");
  const speedInfo = document.getElementById("urlSpeedInfo");
  const resultArea = document.getElementById("resultArea");

  resultArea.style.display = "none";
  progressArea.style.display = "block";
  fileInfo.textContent = `URL: ${url}`;
  phaseBadge.textContent = "Connecting...";
  phaseBadge.className = "phase-badge connecting";
  progressFill.style.width = "0%";
  progressText.textContent = "0%";
  speedInfo.textContent = "";
  urlUploadBtn.disabled = true;

  try {
    const response = await fetch("/api/remote-upload-stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `Server error: ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    const startTime = Date.now();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        try {
          const data = JSON.parse(line.slice(6));

          if (data.type === "progress") {
            if (data.phase === "downloading") {
              phaseBadge.textContent = "⬇ Downloading from source...";
              phaseBadge.className = "phase-badge downloading";
            } else if (data.phase === "uploading_to_r2") {
              phaseBadge.textContent = "⬆ Uploading to both R2 accounts...";
              phaseBadge.className = "phase-badge uploading";
            } else if (data.phase === "connecting") {
              phaseBadge.textContent = "🔗 Connecting...";
              phaseBadge.className = "phase-badge connecting";
            }

            const percent = data.percent || 0;
            progressFill.style.width = percent + "%";
            progressText.textContent = percent + "%";

            if (data.loaded > 0) {
              const elapsed = (Date.now() - startTime) / 1000;
              if (elapsed > 0) {
                const speed = data.loaded / elapsed;
                const totalStr = data.total > 0 ? formatBytes(data.total) : "Unknown";
                const remaining = data.total > 0 ? (data.total - data.loaded) / speed : 0;
                const remainStr = data.total > 0 ? ` — ~${Math.ceil(remaining)}s left` : "";
                speedInfo.textContent = `${formatBytes(data.loaded)} / ${totalStr} — ${formatBytes(speed)}/s${remainStr}`;
              }
            }
          }

          if (data.type === "done") {
            progressFill.style.width = "100%";
            progressText.textContent = "100%";
            phaseBadge.textContent = "✅ Done!";
            phaseBadge.className = "phase-badge";
            phaseBadge.style.background = "rgba(74,222,128,0.2)";
            phaseBadge.style.color = "#4ade80";
            speedInfo.textContent = `Uploaded to: ${data.uploadedTo?.join(", ") || "R2"}`;
            showResult(data);
            saveToHistory(data);
            showToast("Uploaded to both R2 accounts!");
          }

          if (data.type === "error") {
            phaseBadge.textContent = "❌ Error";
            phaseBadge.className = "phase-badge";
            phaseBadge.style.background = "rgba(239,68,68,0.2)";
            phaseBadge.style.color = "#f87171";
            speedInfo.textContent = data.error;
            showToast(data.error, true);
          }
        } catch {}
      }
    }
  } catch (e) {
    speedInfo.textContent = e.message;
    phaseBadge.textContent = "❌ Error";
    phaseBadge.className = "phase-badge";
    phaseBadge.style.background = "rgba(239,68,68,0.2)";
    phaseBadge.style.color = "#f87171";
    showToast(e.message, true);
  } finally {
    urlUploadBtn.disabled = false;
  }
}
