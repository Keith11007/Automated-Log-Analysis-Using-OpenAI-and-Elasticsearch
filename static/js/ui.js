// Renders reusable UI pieces such as status text, stat filters, selected-log details, and analysis output.
import { $, esc, prettySeverity, sev, state } from "./state.js";

export function setStatus(message, tone = "normal") {
  $("statusPill").textContent = message;
  $("statusPill").dataset.tone = tone;
}

export function setAiStatus(message, tone = "normal") {
  const color = tone === "error" ? "#b64034" : tone === "busy" ? "#3367b0" : "#627086";
  $("aiStatus").textContent = message;
  $("aiStatus").style.color = color;
}

export function setAbuseIpStatus(message, tone = "normal") {
  const target = $("abuseIpStatus");
  target.textContent = message;
  target.dataset.tone = tone;
}

export function setBusy(buttonId, isBusy, busyText) {
  const button = $(buttonId);
  // Save the original label once, then restore it after the async action ends.
  if (!button.dataset.label) button.dataset.label = button.textContent;
  button.disabled = isBusy;
  button.textContent = isBusy ? busyText : button.dataset.label;
}

export function updateSource(source, label, count = 0) {
  // These labels are repeated in a few places so the user always knows which
  // data source the current results came from.
  const filterLabel = state.severityFilter ? `${prettySeverity(state.severityFilter)} ` : "";
  $("sourcePill").textContent = `Source: ${source}`;
  $("labelPill").textContent = `Label: ${label}`;
  $("logMeta").textContent = `${label} - showing ${count} ${filterLabel}logs`;
  $("sidebarSource").textContent = label;
  $("sidebarSourceDetail").textContent = source === "none" ? "Connect to Elasticsearch or upload a file to begin." : `Active source: ${source}`;
}

export function renderStats(data = {}) {
  $("totalLogs").textContent = data.total_logs ?? 0;
  $("criticalCount").textContent = data.critical_count ?? 0;
  $("highCount").textContent = data.high_count ?? 0;
  $("warningCount").textContent = data.warning_count ?? 0;

  // The stat cards are also filter buttons, so their active state follows the
  // shared severity filter.
  document.querySelectorAll("[data-severity-filter]").forEach(button => {
    const filter = button.dataset.severityFilter || "";
    const isActive = filter === state.severityFilter;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-pressed", String(isActive));
  });
}

export function renderSelected() {
  if (!state.selected) {
    $("selectedLog").innerHTML = '<div class="empty-state">Select a log from the results list to inspect it here.</div>';
    return;
  }
  const reasons = state.selected.reasons?.length ? state.selected.reasons.join(", ") : "No specific category reasons were attached to this log.";
  // Values are escaped because log messages can contain arbitrary text.
  $("selectedLog").innerHTML = `
    <div class="detail-block"><h4>Severity</h4><div><span class="badge ${sev(state.selected.classification)}">${esc(state.selected.classification)}</span></div></div>
    <div class="detail-block"><h4>Category Source</h4><div>OpenAI</div></div>
    <div class="detail-block"><h4>Message</h4><div>${esc(state.selected.message)}</div></div>
    <div class="detail-block"><h4>Context</h4><div>IP: ${esc(state.selected.ip)}<br>Source: ${esc(state.selected.source)}<br>Time: ${esc(state.selected.timestamp)}</div></div>
    <div class="detail-block"><h4>Reasons</h4><div>${esc(reasons)}</div></div>
  `;
}

function formatInline(text) {
  // Support only the small Markdown subset OpenAI is instructed to use here.
  return esc(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

function renderAnalysis(text) {
  // This is a small Markdown-like renderer, not a full parser.
  const lines = String(text || "").replace(/\r/g, "").split("\n");
  const html = [];
  let paragraph = [];
  let listType = null;
  let listItems = [];
  let listStart = 1;

  function flushParagraph() {
    if (!paragraph.length) return;
    html.push(`<p>${formatInline(paragraph.join(" "))}</p>`);
    paragraph = [];
  }

  function flushList() {
    if (!listItems.length || !listType) return;
    const tag = listType === "ol" ? "ol" : "ul";
    const start = listType === "ol" && listStart !== 1 ? ` start="${listStart}"` : "";
    html.push(`<${tag}${start}>${listItems.join("")}</${tag}>`);
    listType = null;
    listItems = [];
    listStart = 1;
  }

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!line) {
      flushParagraph();
      flushList();
      continue;
    }

    const headingMatch = line.match(/^(#{1,4})\s+(.*)$/);
    if (headingMatch) {
      // Convert Markdown headings into slightly smaller HTML headings so they
      // fit inside the right-hand analysis card.
      flushParagraph();
      flushList();
      const level = Math.min(headingMatch[1].length + 1, 6);
      html.push(`<h${level}>${formatInline(headingMatch[2])}</h${level}>`);
      continue;
    }

    const orderedMatch = line.match(/^(\d+)\.\s+(.*)$/);
    if (orderedMatch) {
      flushParagraph();
      if (listType !== "ol") {
        flushList();
        listType = "ol";
        listStart = Number(orderedMatch[1]);
      }
      listItems.push(`<li>${formatInline(orderedMatch[2])}</li>`);
      continue;
    }

    const bulletMatch = line.match(/^[-*]\s+(.*)$/);
    if (bulletMatch) {
      flushParagraph();
      if (listType !== "ul") {
        flushList();
        listType = "ul";
      }
      listItems.push(`<li>${formatInline(bulletMatch[1])}</li>`);
      continue;
    }

    flushList();
    paragraph.push(line);
  }

  flushParagraph();
  flushList();

  if (!html.length) {
    return '<div class="empty-state">No analysis returned.</div>';
  }

  return `<div class="analysis-report">${html.join("")}</div>`;
}

export function setAnalysisOutput(message, tone = "normal") {
  const output = $("analysisOutput");
  if (tone === "error") {
    // Error output is plain escaped text, not Markdown.
    output.innerHTML = `<div class="analysis-error">${esc(message)}</div>`;
    return;
  }
  output.innerHTML = renderAnalysis(message);
}

function abuseTone(score) {
  // Map the numeric confidence score to the CSS color bands.
  if (score >= 60) return "high";
  if (score >= 25) return "warning";
  return "normal";
}

function abuseValue(value, fallback = "Unknown") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

export function renderAbuseIpResult(data = null, errorMessage = "") {
  const target = $("abuseIpResult");

  if (errorMessage) {
    target.innerHTML = `<div class="analysis-error">${esc(errorMessage)}</div>`;
    return;
  }

  if (!data) {
    target.innerHTML = '<div class="empty-state">No IP checked yet.</div>';
    return;
  }

  const score = Number(data.abuse_confidence_score ?? 0);
  const countryDisplay = [data.country_flag, abuseValue(data.country_name, "")].filter(Boolean).join(" ") || "Unknown";
  const cityDisplay = abuseValue(data.city);
  const summary = data.is_found
    ? `${abuseValue(data.ip)} was found in the AbuseIPDB database.`
    : `${abuseValue(data.ip)} was not found in the AbuseIPDB database.`;
  const reportLabel = data.total_reports === 1 ? "time" : "times";

  // Build display rows in data first, then render them in one template.
  const rows = [
    ["ISP", abuseValue(data.isp)],
    ["Usage Type", abuseValue(data.usage_type)],
    ["ASN", abuseValue(data.asn)],
    ["Domain Name", abuseValue(data.domain)],
    ["Country", countryDisplay],
    ["City", cityDisplay],
  ];

  target.innerHTML = `
    <div class="abuse-summary">
      <div>
        <strong>${esc(summary)}</strong>
        <p>This IP was reported ${esc(data.total_reports)} ${esc(reportLabel)}. Confidence of abuse is ${esc(score)}%.</p>
      </div>
      <div class="abuse-score" data-level="${esc(abuseTone(score))}">${esc(score)}%</div>
    </div>
    <div class="abuse-grid">
      ${rows.map(([label, value]) => `
        <div class="abuse-kv">
          <span>${esc(label)}</span>
          <strong>${esc(value)}</strong>
        </div>
      `).join("")}
    </div>
  `;
}
