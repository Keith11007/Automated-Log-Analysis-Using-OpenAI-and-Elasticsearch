// Coordinates API requests and user actions for loading logs, filtering categories, and asking OpenAI.
import { API, LIMIT, $, prettySeverity, state } from "./state.js";
import { renderLogs } from "./logs.js";
import { renderAbuseIpResult, renderStats, setAbuseIpStatus, setAiStatus, setAnalysisOutput, setBusy, setStatus } from "./ui.js";

export async function requestJson(url, options = {}) {
  // Centralizing fetch keeps error handling consistent for every button action.
  const response = await fetch(url, options);
  let data = {};
  try { data = await response.json(); } catch {}
  if (!response.ok) throw new Error(data.message || `Request failed with status ${response.status}`);
  return data;
}

function buildLogsUrl() {
  // Keep all active dashboard filters in one request builder.
  const params = new URLSearchParams({ limit: String(LIMIT) });
  const query = $("searchInput").value.trim();
  if (query) params.set("q", query);
  if (state.severityFilter) params.set("severity", state.severityFilter);
  return `${API}/get-logs?${params.toString()}`;
}

export async function refresh(showStatus = true) {
  // Reload both the log list and the summary cards from the current source.
  try {
    const [logsData, statsData] = await Promise.all([
      requestJson(buildLogsUrl()),
      requestJson(`${API}/stats`)
    ]);

    renderLogs(logsData);
    renderStats(statsData);

    if (!showStatus) return;
    if (statsData.error) {
      setStatus(statsData.error, "error");
      $("notesBox").textContent = statsData.error;
    } else if (logsData.source === "none") {
      setStatus("No data source selected.", "busy");
      $("notesBox").textContent = "Connect to Elasticsearch or upload logs to begin.";
    } else if (state.logs.length) {
      const filterLabel = state.severityFilter ? `${prettySeverity(state.severityFilter)} ` : "";
      setStatus(`Loaded ${state.logs.length} ${filterLabel}logs from ${logsData.source_label}.`);
      $("notesBox").textContent = `Current source ${logsData.source_label} has ${state.logs.length} ${filterLabel}logs loaded and ready for review.`;
    } else if (state.severityFilter) {
      setStatus(`No ${prettySeverity(state.severityFilter)} logs found in ${logsData.source_label}.`, "busy");
      $("notesBox").textContent = `Try a different category or clear the filter to see all logs from ${logsData.source_label}.`;
    } else {
      setStatus(`No logs found in ${logsData.source_label}.`, "busy");
      $("notesBox").textContent = logsData.error || `No logs were returned from ${logsData.source_label}.`;
    }
  } catch (error) {
    setStatus(error.message || "Unable to refresh the dashboard.", "error");
    $("notesBox").textContent = error.message || "Unable to refresh the dashboard.";
  }
}

export async function setSeverityFilter(category) {
  // Clicking the active category again clears the filter.
  const allowed = new Set(["critical", "high", "warning"]);
  const nextFilter = allowed.has(category) ? category : "";
  state.severityFilter = state.severityFilter === nextFilter ? "" : nextFilter;
  await refresh(true);
}

export async function connectElasticsearch() {
  setBusy("connectBtn", true, "Connecting...");
  setStatus("Connecting to Elasticsearch...", "busy");
  try {
    const payload = {
      url: $("esUrl").value.trim(),
      index: $("esIndex").value.trim() || "logs-*",
      username: $("esUser").value.trim(),
      password: $("esPassword").value
    };
    const data = await requestJson(`${API}/connect-elasticsearch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (data.config) {
      // Echo the server's normalized config back into the form. This is where
      // a host like `localhost:9200` becomes the actual URL that worked.
      $("esUrl").value = data.config.url || $("esUrl").value;
      $("esIndex").value = data.config.index || $("esIndex").value;
      $("esUser").value = data.config.username || $("esUser").value;
    }

    state.severityFilter = "";
    $("searchInput").value = "";
    await refresh(false);
    setStatus(data.message, data.connected ? "normal" : "error");
    $("notesBox").textContent = data.details ? `${data.message} Details: ${data.details}` : data.message;
  } catch (error) {
    setStatus(error.message || "Elasticsearch connection failed.", "error");
    $("notesBox").textContent = error.message || "Elasticsearch connection failed.";
  } finally {
    setBusy("connectBtn", false, "Connecting...");
  }
}

export async function uploadLogs() {
  if (!$("fileInput").files.length) {
    setStatus("Choose a file before uploading.", "error");
    return;
  }
  setBusy("uploadBtn", true, "Uploading...");
  setStatus(`Uploading ${$("fileInput").files[0].name}...`, "busy");
  try {
    const form = new FormData();
    // FormData lets Flask receive the upload through `request.files`.
    form.append("file", $("fileInput").files[0]);
    const data = await requestJson(`${API}/upload-logs`, { method: "POST", body: form });
    state.severityFilter = "";
    $("searchInput").value = "";
    await refresh(false);
    setStatus(data.message, "normal");
    $("notesBox").textContent = data.message;
  } catch (error) {
    setStatus(error.message || "Upload failed.", "error");
    $("notesBox").textContent = error.message || "Upload failed.";
  } finally {
    setBusy("uploadBtn", false, "Uploading...");
  }
}

export async function checkAbuseIp() {
  const ip = $("abuseIpInput").value.trim();
  if (!ip) {
    setAbuseIpStatus("Enter an IP address first.", "error");
    renderAbuseIpResult(null, "Enter an IP address first.");
    return;
  }

  setBusy("abuseLookupBtn", true, "Checking...");
  setAbuseIpStatus(`Checking ${ip} against AbuseIPDB...`, "busy");

  try {
    const data = await requestJson(`${API}/abuseipdb-check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });

    renderAbuseIpResult(data);
    const reportLabel = data.total_reports === 1 ? "report" : "reports";
    // Scores above 25 are called out visually because they deserve review even
    // when they are not severe enough to be blocked automatically.
    setAbuseIpStatus(
      data.is_found
        ? `${data.ip} returned ${data.total_reports} ${reportLabel} with ${data.abuse_confidence_score}% confidence.`
        : `${data.ip} returned no recent AbuseIPDB reports.`,
      Number(data.abuse_confidence_score ?? 0) >= 25 ? "busy" : "normal"
    );
  } catch (error) {
    renderAbuseIpResult(null, error.message || "AbuseIPDB lookup failed.");
    setAbuseIpStatus(error.message || "AbuseIPDB lookup failed.", "error");
  } finally {
    setBusy("abuseLookupBtn", false, "Checking...");
  }
}

export async function analyzeWithOpenAI() {
  // The analysis request includes the current filters so the answer matches the visible log set.
  const hasLogContext = state.logs.length > 0;
  setBusy("askBtn", true, "Asking...");
  setStatus(hasLogContext ? "Running OpenAI analysis..." : "Sending prompt to OpenAI...", "busy");
  setAiStatus(state.selected ? "Sending the selected log and current logs to OpenAI..." : hasLogContext ? "Sending the current logs to OpenAI..." : "Sending your prompt without log context...", "busy");
  try {
    const data = await requestJson(`${API}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        // Send the selected card and active filters so the backend can rebuild
        // the same context before calling OpenAI.
        query: $("queryInput").value.trim(),
        log: state.selected,
        severity: state.severityFilter,
        search: $("searchInput").value.trim()
      })
    });

    if (data.ai_used && data.response) {
      setAnalysisOutput(data.response);
      setAiStatus(`OpenAI response completed with model ${data.model}.`);
      setStatus(data.source === "none" ? "OpenAI response completed." : `Analysis completed for ${data.source_label}.`);
    } else {
      setAnalysisOutput(data.ai_error || "OpenAI did not return a response.", "error");
      setAiStatus(data.ai_error || "OpenAI did not return a response.", "error");
      setStatus(data.ai_error || "OpenAI analysis failed.", "error");
    }
  } catch (error) {
    setAnalysisOutput(error.message || "OpenAI analysis failed.", "error");
    setAiStatus(error.message || "OpenAI analysis failed.", "error");
    setStatus(error.message || "OpenAI analysis failed.", "error");
  } finally {
    setBusy("askBtn", false, "Asking...");
  }
}
