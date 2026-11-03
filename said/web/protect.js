// Prototype only. The access token remains in tab memory and is cleared on disconnect.
let token = "";
const el = id => document.getElementById(id);
const display = (id, message) => { el(id).textContent = message; };
const data = form => Object.fromEntries(new FormData(form).entries());

async function api(path, method = "GET", body) {
  if (!token) throw new Error("Connect with a citizen bearer token first.");
  const response = await fetch(path, {
    method, cache: "no-store", credentials: "omit",
    headers: { Authorization: "Bearer " + token, ...(body ? {"Content-Type":"application/json"} : {}) },
    ...(body ? {body: JSON.stringify(body)} : {})
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error("Your citizen session was rejected.");
    if (response.status === 403) throw new Error("The token does not have citizen access.");
    if (response.status === 404) throw new Error("This request does not belong to your account.");
    if (response.status === 422) throw new Error("Check the category and opaque reference.");
    throw new Error("Request unsuccessful (" + response.status + ").");
  }
  return response.json();
}
async function load() {
  display("inquiries", "Loading...");
  try {
    const rows = await api("/api/v1/protect/requests");
    const container = el("inquiries");
    container.replaceChildren();
    if (!rows.length) { container.textContent = "No inquiries submitted."; return; }
    for (const row of rows) {
      const item = document.createElement("div"); item.className = "item";
      const title = document.createElement("strong"); title.textContent = row.category.replaceAll("_", " ");
      const ref = document.createElement("span"); ref.textContent = "Reference: " + row.device_reference;
      const state = document.createElement("small"); state.textContent = "Status: " + row.status;
      item.append(title,ref,state); container.append(item);
    }
  } catch (error) { display("inquiries", error.message); }
}
el("connect").addEventListener("submit", event => {
  event.preventDefault();
  token = data(event.currentTarget).token.trim();
  event.currentTarget.reset();
  display("session", token ? "Test token loaded in this tab only." : "Disconnected");
});
el("disconnect").addEventListener("click", () => {
  token = ""; el("connect").reset(); display("session", "Disconnected");
  display("inquiries", "Connect to see your inquiries.");
});
el("new").addEventListener("submit", async event => {
  event.preventDefault(); display("result", "Submitting...");
  try {
    const result = await api("/api/v1/protect/requests", "POST", data(event.currentTarget));
    display("result", "Inquiry created: " + result.id + " — " + result.status);
    event.currentTarget.reset();
    await load();
  } catch (error) { display("result", error.message); }
});
el("load").addEventListener("click", load);
