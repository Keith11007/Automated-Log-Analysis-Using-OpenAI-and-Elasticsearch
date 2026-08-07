import { $ } from "./js/state.js";
import { analyzeWithOpenAI, checkAbuseIp, connectElasticsearch, refresh, setSeverityFilter, uploadLogs } from "./js/actions.js";
import { renderSelected } from "./js/ui.js";

// all events

$("connectBtn").addEventListener("click", connectElasticsearch);
$("uploadBtn").addEventListener("click", uploadLogs);
$("abuseLookupBtn").addEventListener("click", checkAbuseIp);
$("searchBtn").addEventListener("click", () => refresh(true));
$("refreshBtn").addEventListener("click", () => refresh(true));
$("askBtn").addEventListener("click", analyzeWithOpenAI);
$("abuseIpInput").addEventListener("keydown", event => { if (event.key === "Enter") checkAbuseIp(); });
$("searchInput").addEventListener("keydown", event => { if (event.key === "Enter") refresh(true); });
$("queryInput").addEventListener("keydown", event => { if ((event.ctrlKey || event.metaKey) && event.key === "Enter") analyzeWithOpenAI(); });
document.querySelectorAll("[data-severity-filter]").forEach(button => {
  button.addEventListener("click", () => setSeverityFilter(button.dataset.severityFilter || ""));
});


renderSelected();
refresh(true);
