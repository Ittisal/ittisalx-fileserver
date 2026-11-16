const $ = s => document.querySelector(s);
async function api(url, body) {
  const r = await fetch(url, body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && !url.includes("login")) location.href = "/login";
  if (!r.ok) throw new Error(data.error || "Something went wrong. Please try again.");
  return data;
}
function say(el, text, ok) { el.textContent = text; el.className = "msg " + (ok ? "ok" : "err"); }
function fmtSize(b) {
  if (b < 1024) return b + " B";
  const u = ["KB", "MB", "GB", "TB"]; let i = -1;
  do { b /= 1024; i++; } while (b >= 1024 && i < 3);
  return b.toFixed(b < 10 ? 1 : 0) + " " + u[i];
}
async function logout() { await api("/api/logout", {}); location.href = "/login"; }
