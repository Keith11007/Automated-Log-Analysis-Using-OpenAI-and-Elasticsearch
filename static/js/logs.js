// Renders log result cards and keeps the optional selected-log panel in sync.
import { $, esc, sev, state } from "./state.js";
import { renderSelected, updateSource } from "./ui.js";

export function pickLog(id) {
  // Store the full log object aand only its id,
  state.selected = state.logs.find(log => String(log.id) === String(id)) || null;
  document.querySelectorAll("#logList .log-item").forEach(card => card.classList.toggle("active", card.dataset.id === String(id)));
  renderSelected();
}

export function clearSelectedLog() {
  state.selected = null;
  document.querySelectorAll("#logList .log-item").forEach(card => card.classList.remove("active"));
  renderSelected();
}

export function renderLogs(payload) {
  // Rebuild the list from scratch so selection always tracks the currently visible results.
  const logs = payload.logs || [];
  const previousSelectedId = state.selected?.id;
  state.logs = logs;
  updateSource(payload.source, payload.source_label || payload.source, logs.length);

  if (!logs.length) {
    clearSelectedLog();
    $("logList").innerHTML = `<div class="empty-state">${payload.error || "No logs are available for the current source."}</div>`;
    return;
  }

  $("logList").innerHTML = logs.map(log => `
    <div class="log-item" data-id="${esc(log.id)}">
      <div class="log-head">
        <span class="badge ${sev(log.classification)}">${esc(log.classification)}</span>
        <div class="muted">${esc(log.timestamp)}</div>
      </div>
      <div class="log-message">${esc(log.message)}</div>
      <div class="log-meta">
        <div class="meta-chip">IP: ${esc(log.ip)}</div>
        <div class="meta-chip">Source: ${esc(log.source)}</div>
      </div>
    </div>
  `).join("");

  // Event listeners 
  document.querySelectorAll("#logList .log-item").forEach(card => card.addEventListener("click", () => pickLog(card.dataset.id)));
  if (previousSelectedId && logs.some(log => String(log.id) === String(previousSelectedId))) {
    pickLog(previousSelectedId);
  } else {
    clearSelectedLog();
  }
}
