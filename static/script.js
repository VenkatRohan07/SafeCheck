const tabButtons = document.querySelectorAll(".tab-btn");
const tabPanels = document.querySelectorAll(".tab-panel");
const resultBox = document.getElementById("result");
const loadingBox = document.getElementById("loading");

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    tabButtons.forEach((b) => b.classList.remove("active"));
    tabPanels.forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
    resultBox.classList.add("hidden");
    if (btn.dataset.tab === "history-tab") loadHistory();
  });
});

function showLoading(on) {
  loadingBox.classList.toggle("hidden", !on);
  if (on) resultBox.classList.add("hidden");
}

function renderResult(data) {
  resultBox.classList.remove("hidden");
  const verdict = data.verdict || "Unknown";
  let html = `<span class="verdict ${verdict}">${verdict}</span>`;
  html += `<div><strong>${data.target}</strong></div>`;
  if (data.sha256) html += `<div class="reasons">SHA-256: ${data.sha256}</div>`;

  if (data.reasons && data.reasons.length) {
    html += `<ul class="reasons">${data.reasons.map((r) => `<li>${r}</li>`).join("")}</ul>`;
  } else {
    html += `<div class="reasons">No engines flagged this.</div>`;
  }

  if (data.virustotal && !data.virustotal.error) {
    const vt = data.virustotal;
    html += `<div class="reasons">VirusTotal — malicious: ${vt.malicious ?? 0}, suspicious: ${vt.suspicious ?? 0}, harmless: ${vt.harmless ?? 0}</div>`;
  }

  resultBox.innerHTML = html;
}

// URL scan
document.getElementById("url-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = document.getElementById("url-input").value.trim();
  if (!url) return;
  showLoading(true);
  try {
    const res = await fetch("/scan/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    renderResult(data);
  } catch (err) {
    resultBox.classList.remove("hidden");
    resultBox.innerHTML = `<div class="reasons">Error: ${err.message}</div>`;
  } finally {
    showLoading(false);
  }
});

// File scan
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
let selectedFile = null;

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("drag");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("drag");
  if (e.dataTransfer.files.length) {
    selectedFile = e.dataTransfer.files[0];
    dropzone.querySelector("p").textContent = selectedFile.name;
  }
});
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) {
    selectedFile = fileInput.files[0];
    dropzone.querySelector("p").textContent = selectedFile.name;
  }
});

document.getElementById("file-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!selectedFile) {
    alert("Choose a file first");
    return;
  }
  const formData = new FormData();
  formData.append("file", selectedFile);
  showLoading(true);
  try {
    const res = await fetch("/scan/file", { method: "POST", body: formData });
    const data = await res.json();
    renderResult(data);
  } catch (err) {
    resultBox.classList.remove("hidden");
    resultBox.innerHTML = `<div class="reasons">Error: ${err.message}</div>`;
  } finally {
    showLoading(false);
  }
});

// History
async function loadHistory() {
  const res = await fetch("/history");
  const rows = await res.json();
  const tbody = document.querySelector("#history-table tbody");
  tbody.innerHTML = rows
    .map(
      (r) =>
        `<tr><td>${r.target}</td><td>${r.target_type}</td><td>${r.verdict}</td><td>${new Date(
          r.scanned_at
        ).toLocaleString()}</td></tr>`
    )
    .join("");
}

document.getElementById("refresh-history").addEventListener("click", loadHistory);
