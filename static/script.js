const tabButtons = document.querySelectorAll(".tab-btn");
const tabPanels = document.querySelectorAll(".tab-panel");
const resultBox = document.getElementById("result");
const loadingBox = document.getElementById("loading");

function formatDateTime(isoString) {
  const d = new Date(isoString);
  const pad = (n) => String(n).padStart(2, "0");
  const date = `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return `${date} ${time}`;
}

// Footer year
const footerYear = document.getElementById("footer-year");
if (footerYear) footerYear.textContent = new Date().getFullYear();

// Security news feed
async function loadNews() {
  const list = document.getElementById("news-list");
  try {
    const res = await fetch("/news");
    const articles = await res.json();
    if (!articles.length) {
      list.innerHTML = `<li class="news-empty">No news available right now.</li>`;
      return;
    }
    list.innerHTML = articles
      .map(
        (a) =>
          `<li><a href="${a.url}" target="_blank" rel="noopener noreferrer">${a.title}</a> <span class="news-source">— ${a.source}</span></li>`
      )
      .join("");
  } catch (err) {
    list.innerHTML = `<li class="news-empty">Couldn't load news right now.</li>`;
  }
}
loadNews();

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    tabButtons.forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });
    tabPanels.forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");
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
  const verdict = data.verdict || "Unknown";
  resultBox.className = `result ${verdict}`;

  let html = `<span class="verdict ${verdict}">${verdict}</span>`;
  html += `<div class="result-target">${data.target}</div>`;

  if (data.reasons && data.reasons.length) {
    html += `<ul class="reasons">${data.reasons.map((r) => `<li>${r}</li>`).join("")}</ul>`;
  } else {
    html += `<div class="meta-line">No engines flagged this.</div>`;
  }

  if (data.sha256) {
    html += `<div class="meta-line">SHA-256: ${data.sha256}</div>`;
  }

  if (data.virustotal && !data.virustotal.error) {
    const vt = data.virustotal;
    html += `<div class="meta-line">VirusTotal — malicious: ${vt.malicious ?? 0}, suspicious: ${vt.suspicious ?? 0}, harmless: ${vt.harmless ?? 0}</div>`;
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
    resultBox.className = "result";
    resultBox.innerHTML = `<div class="meta-line">Error: ${err.message}</div>`;
  } finally {
    showLoading(false);
  }
});

// File scan
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
let selectedFile = null;

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
});
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
    dropzone.querySelector(".drop-label").textContent = selectedFile.name;
  }
});
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) {
    selectedFile = fileInput.files[0];
    dropzone.querySelector(".drop-label").textContent = selectedFile.name;
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
    resultBox.className = "result";
    resultBox.innerHTML = `<div class="meta-line">Error: ${err.message}</div>`;
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
        `<tr><td>${r.target}</td><td>${r.target_type}</td><td class="verdict-cell ${r.verdict}">${r.verdict}</td><td>${formatDateTime(r.scanned_at)}</td></tr>`
    )
    .join("");
}

document.getElementById("refresh-history").addEventListener("click", loadHistory);
