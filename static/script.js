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

// Footer typing animation — loops continuously at a moderate pace
const FOOTER_TEXT = `© ${new Date().getFullYear()} SafeCheck — built by V V Rohan Sasi Vardhan`;
const footerTyped = document.getElementById("footer-typed");
const TYPE_SPEED = 70;   // ms per character while typing
const ERASE_SPEED = 35;  // ms per character while erasing
const HOLD_TIME = 1800;  // pause once fully typed, before erasing

function runTypingLoop() {
  let i = 0;
  let typing = true;

  function step() {
    if (typing) {
      i++;
      footerTyped.textContent = FOOTER_TEXT.slice(0, i);
      if (i >= FOOTER_TEXT.length) {
        typing = false;
        setTimeout(step, HOLD_TIME);
        return;
      }
      setTimeout(step, TYPE_SPEED);
    } else {
      i--;
      footerTyped.textContent = FOOTER_TEXT.slice(0, i);
      if (i <= 0) {
        typing = true;
        setTimeout(step, 500);
        return;
      }
      setTimeout(step, ERASE_SPEED);
    }
  }
  step();
}

if (footerTyped) {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    footerTyped.textContent = FOOTER_TEXT;
  } else {
    runTypingLoop();
  }
}

// Security news — one full article at a time, auto-rotating
let newsArticles = [];
let newsIndex = 0;
let newsRotationTimer = null;

function renderNewsArticle() {
  const container = document.getElementById("news-article");
  if (!container) return;

  if (!newsArticles.length) {
    container.innerHTML = `<div class="news-empty">No cybersecurity news available right now.</div>`;
    return;
  }

  const a = newsArticles[newsIndex];
  const dateStr = a.published_at
    ? new Date(a.published_at).toLocaleDateString()
    : "";

  const dots = newsArticles
    .map((_, idx) => `<span class="news-dot${idx === newsIndex ? " active" : ""}"></span>`)
    .join("");

  container.innerHTML = `
    <h3 class="news-title"><a href="${a.url}" target="_blank" rel="noopener noreferrer">${a.title}</a></h3>
    <p class="news-description">${a.description || "No summary available for this article."}</p>
    <div class="news-meta">
      <span>${a.source}${dateStr ? " · " + dateStr : ""}</span>
      <span class="news-dots">${dots}</span>
    </div>
  `;
}

async function loadNews() {
  try {
    const res = await fetch("/news");
    newsArticles = await res.json();
    newsIndex = 0;
    renderNewsArticle();

    if (newsRotationTimer) clearInterval(newsRotationTimer);
    if (newsArticles.length > 1) {
      newsRotationTimer = setInterval(() => {
        newsIndex = (newsIndex + 1) % newsArticles.length;
        renderNewsArticle();
      }, 8000);
    }
  } catch (err) {
    const container = document.getElementById("news-article");
    if (container) container.innerHTML = `<div class="news-empty">Couldn't load news right now.</div>`;
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
