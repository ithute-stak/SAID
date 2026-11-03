// SAID controlled admin prototype. Never save credentials to browser storage.
let bearerToken = "";
const byId = (id) => document.getElementById(id);
const show = (id, data) => { byId(id).textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2); };
const clean = (value) => String(value).trim();
function payload(form) {
  return Object.fromEntries(new FormData(form).entries());
}
async function request(path, method = "GET", body = undefined) {
  if (!bearerToken) throw new Error("Connect using an institutional bearer token first.");
  const response = await fetch(path, {
    method, credentials: "omit", cache: "no-store",
    headers: { Authorization: "Bearer " + bearerToken, ...(body ? { "Content-Type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
  let data = null;
  try { data = await response.json(); } catch { /* response may not be JSON */ }
  if (!response.ok) {
    // Don't print raw server exceptions or tokens in the operator UI.
    const generic = response.status === 401 ? "Session rejected or expired. Reconnect." :
                    response.status === 403 ? "Your role does not permit this operation." :
                    response.status === 404 ? "Record not found or inaccessible." :
                    response.status === 409 ? "Conflicting or duplicate record." :
                    response.status === 422 ? "Please check the submitted fields." :
                    "Request failed (" + response.status + ").";
    throw new Error(generic);
  }
  return data;
}
function handle(formId, resultId, action) {
  const form = byId(formId);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    show(resultId, "Processing...");
    try { show(resultId, await action(payload(form))); }
    catch (e) { show(resultId, e.message || "Operation failed."); }
  });
}
byId("connect-form").addEventListener("submit", (event) => {
  event.preventDefault();
  bearerToken = byId("token").value.trim();
  byId("token").value = "";
  byId("connection-indicator").textContent = bearerToken ? "Token loaded in memory" : "Disconnected";
});
byId("disconnect").addEventListener("click", () => {
  bearerToken = "";
  byId("token").value = "";
  byId("connection-indicator").textContent = "Disconnected";
});
handle("lookup-form", "lookup-result", (p) => request("/api/v1/devices/" + encodeURIComponent(clean(p.device_id))));
handle("register-form", "register-result", (p) => request("/api/v1/devices", "POST", p));
handle("report-form", "report-result", (p) => request("/api/v1/devices/" + encodeURIComponent(clean(p.device_id)) + "/theft-reports", "POST", {incident_reference: clean(p.incident_reference)}));
handle("claim-form", "claim-result", (p) => request("/api/v1/ownership/claims/" + encodeURIComponent(clean(p.claim_id))));
handle("create-claim-form", "create-claim-result", (p) => request("/api/v1/ownership/claims", "POST", p));
handle("review-form", "review-result", (p) => request("/api/v1/ownership/claims/" + encodeURIComponent(clean(p.claim_id)) + "/review", "POST", {decision: p.decision}));
