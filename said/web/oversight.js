// SAID Oversight offline console — no credentials persisted.
let bearer = "";
const el = id => document.getElementById(id);
const show = (id, value) => {el(id).textContent = typeof value === "string" ? value : JSON.stringify(value,null,2);};
const payload = form => Object.fromEntries(new FormData(form).entries());
const ROOT="/api/v1/ceir/sandbox";
async function api(path, method="GET", body) {
  if (!bearer) throw Error("Connect an authorized central token first.");
  const response = await fetch(ROOT+path,{method,cache:"no-store",credentials:"omit",
    headers:{"Authorization":"Bearer "+bearer,...(body?{"Content-Type":"application/json"}:{})},
    ...(body?{body:JSON.stringify(body)}:{})});
  if (!response.ok) throw Error(response.status === 403 ? "Supervisor/auditor permission required." :
    response.status === 401 ? "Authentication failed." :
    response.status === 404 ? "Record not found." :
    response.status === 409 ? "Record conflict or integrity check failed." :
    "Request unsuccessful ("+response.status+").");
  return response.json();
}
async function refresh() {
  try {
    const [summary, appeals]=await Promise.all([api("/oversight/summary"),api("/appeals")]);
    show("total",summary.appeals_in_page);show("pending",summary.pending_appeals_in_page);
    show("holds-count",summary.active_holds_in_page);
    show("appeals", appeals.length?appeals:"No appeal records in current page.");
  } catch (e) {show("appeals",e.message);}
}
el("connect").addEventListener("submit", async e=>{e.preventDefault();bearer=payload(e.currentTarget).token.trim();e.currentTarget.reset();show("connection",bearer?"Token in memory only.":"Disconnected");if(bearer)await refresh();});
el("disconnect").addEventListener("click",()=>{bearer="";el("connect").reset();for(const id of ["total","pending","holds-count"])show(id,"—");show("connection","Disconnected");show("appeals","Connect to load appeal records.");});
el("refresh").addEventListener("click",refresh);
function submitForm(formId,resultId,makeRequest){
  el(formId).addEventListener("submit",async e=>{e.preventDefault();show(resultId,"Processing...");
    try {show(resultId,await makeRequest(payload(e.currentTarget)));e.currentTarget.reset();}
    catch(error){show(resultId,error.message);}
  });
}
submitForm("checkpoint","checkpoint-result",p=>api("/oversight/checkpoints","POST",p));
submitForm("verify","verify-result",p=>api("/oversight/checkpoints/"+encodeURIComponent(p.investigation_id)));
submitForm("hold","hold-result",p=>api("/oversight/holds","POST",p));
el("preview").addEventListener("click",async()=>{try{show("preview-result",await api("/governance/retention/preview"));}catch(e){show("preview-result",e.message);}});
