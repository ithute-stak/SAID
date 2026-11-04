// Controlled SAID Intelligence UI: bearer token kept only in tab memory.
let token = "";
let selectedCase = null;
let cases = [];
const el = id => document.getElementById(id);
const write = (id, value) => { el(id).textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2); };
const formData = node => Object.fromEntries(new FormData(node).entries());
const prefix = "/api/v1/ceir/sandbox";
async function api(path, method="GET", body) {
  if (!token) throw Error("Connect with an authorized central SAID token.");
  const response = await fetch(path, {
    method, credentials: "omit", cache: "no-store",
    headers: {"Authorization": "Bearer " + token, ...(body ? {"Content-Type": "application/json"} : {})},
    ...(body ? {body: JSON.stringify(body)} : {})
  });
  if (!response.ok) {
    const message = response.status === 401 ? "Session expired or unauthorized." :
      response.status === 403 ? "Central SAID authorization required." :
      response.status === 404 ? "Case not found or inaccessible." :
      response.status === 409 ? "Case state changed. Refresh and retry." :
      response.status === 422 ? "Check the decision and reference." :
      "Request failed (" + response.status + ").";
    throw Error(message);
  }
  return response.json();
}
function clearDetail() {
  selectedCase = null;
  write("selected", "Select an investigation from the queue.");
  for (const id of ["signals","provenance","history"]) write(id,"No case selected.");
  el("assess").disabled = true; el("submit-review").disabled = true;
}
function displayQueue() {
  const tbody = el("case-rows"); tbody.replaceChildren();
  write("count-total", String(cases.length));
  write("count-pending", String(cases.filter(c => c.status === "pending_human_review").length));
  write("count-reviewed", String(cases.filter(c => c.status !== "pending_human_review").length));
  for (const c of cases) {
    const tr = document.createElement("tr");
    if (selectedCase?.id === c.id) tr.className = "active-case";
    const shortId = document.createElement("td"); shortId.textContent = c.id;
    const state = document.createElement("td"); state.textContent = c.status.replaceAll("_"," ");
    state.className = c.reviewed ? "status-reviewed" : "status-pending";
    const review = document.createElement("td"); review.textContent = c.reviewed ? "Recorded" : "Pending";
    const action = document.createElement("td"), button = document.createElement("button");
    button.type = "button"; button.textContent = "Inspect";
    button.addEventListener("click", () => selectCase(c));
    action.append(button); tr.append(shortId,state,review,action); tbody.append(tr);
  }
  write("queue-message", cases.length ? "Loaded " + cases.length + " mock investigations." :
    "No mock investigations have been recorded.");
}
async function refresh() {
  try {
    cases = await api(prefix + "/intelligence/investigations");
    displayQueue();
    if (selectedCase) {
      const match = cases.find(c => c.id === selectedCase.id);
      if (match) await selectCase(match);
      else clearDetail();
    }
  } catch (error) { write("queue-message",error.message); }
}
async function selectCase(c) {
  selectedCase = c; displayQueue();
  write("selected", "Case " + c.id + " — " + c.status.replaceAll("_", " "));
  el("assess").disabled = false;
  el("submit-review").disabled = c.status !== "pending_human_review";
  const observationId = encodeURIComponent(c.observation_id);
  try {
    const [signals,history] = await Promise.all([
      api(prefix + "/quality/observations/" + observationId),
      api(prefix + "/intelligence/observations/" + observationId + "/assessments")
    ]);
    write("signals",signals);
    write("history",history.length ? history : "No assessments recorded.");
    try {
      write("provenance",await api(prefix + "/intelligence/observations/" +
        observationId + "/provenance"));
    } catch { write("provenance","No provenance recorded or provenance inaccessible."); }
  } catch (error) {
    write("signals",error.message);
    write("history","Unable to load assessment history.");
    el("assess").disabled = true; el("submit-review").disabled = true;
  }
}
el("connect").addEventListener("submit", async event => {
  event.preventDefault();
  token = formData(event.currentTarget).token.trim();
  event.currentTarget.reset();
  write("connection",token ? "Token loaded in this tab only." : "Disconnected");
  if (token) await refresh();
});
el("disconnect").addEventListener("click", () => {
  token = ""; el("connect").reset(); cases = []; clearDetail();
  write("connection","Disconnected");
  for (const id of ["count-total","count-pending","count-reviewed"]) write(id,"—");
  el("case-rows").replaceChildren();
  write("queue-message","Connect to load cases.");
});
el("refresh").addEventListener("click",refresh);
el("assess").addEventListener("click", async () => {
  if (!selectedCase) return;
  try {
    await api(prefix + "/intelligence/observations/" +
      encodeURIComponent(selectedCase.observation_id) + "/assessments", "POST");
    await selectCase(selectedCase);
  } catch (error) { write("review-status",error.message); }
});
el("review").addEventListener("submit", async event => {
  event.preventDefault();
  if (!selectedCase || selectedCase.status !== "pending_human_review") return;
  try {
    const decision = formData(event.currentTarget);
    const result = await api(prefix + "/quality/investigations/" +
      encodeURIComponent(selectedCase.id) + "/review", "POST", decision);
    write("review-status", "Sandbox decision recorded: " + result.status +
      ". No network action taken.");
    event.currentTarget.reset(); await refresh();
  } catch (error) { write("review-status",error.message); }
});
