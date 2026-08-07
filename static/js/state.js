export const API = window.location.origin;
export const LIMIT = 500;

// current app state
export const state = { logs: [], selected: null, severityFilter: "" };

export const $ = id => document.getElementById(id);
// XSS protection
export const esc = value => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
export const sev = value => value ? String(value).toLowerCase() : "info";
export const prettySeverity = value => ({ critical: "critical", high: "high risk", warning: "warning" }[value] || "all");
