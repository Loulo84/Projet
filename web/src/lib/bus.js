// src/lib/bus.js
export const bus = new EventTarget();
let es = null;

function isPublicPath(){
  const p = location.pathname;
  return p === "/" || p.startsWith("/login") || p.startsWith("/signup");
}

function normalizeApiBase() {
  const RAW = (import.meta.env.VITE_API_URL || "").trim();
  if (!RAW) return "http://127.0.0.1:4000/api";
  const noTrail = RAW.replace(/\/+$/,"");
  return noTrail.endsWith("/api") ? noTrail : `${noTrail}/api`;
}

function candidates(){
  const primary = normalizeApiBase();                  // ex: http://127.0.0.1:4000/api
  const fallback = "http://127.0.0.1:4000/api";       // secours local
  return [primary, fallback];
}

export function connectSSE(){
  if (es || isPublicPath()) return;
  const [first, second] = candidates();

  const tryConnect = (base) => {
    try{
      const src = `${base.replace(/\/+$/,"")}/events`;
      const s = new EventSource(src, { withCredentials: true });

      const forward = (ev)=>(e)=>{
        let d=null; try{ d=JSON.parse(e.data||"{}"); }catch{}
        bus.dispatchEvent(new CustomEvent(ev,{ detail:d }));
        if (ev!=="data-changed")
          bus.dispatchEvent(new CustomEvent("data-changed",{ detail:{ from:ev, ...d }}));
      };

      ["hello","ping","data-changed","payment:ok","payment:failed"].forEach((ev)=>s.addEventListener(ev, forward(ev)));
      s.addEventListener("error", () => {});
      s.onerror = () => {};

      es = s;
      return true;
    }catch{ return false; }
  };

  if (!tryConnect(first)) { tryConnect(second); }
}
export function emitDataChanged(d){ bus.dispatchEvent(new CustomEvent("data-changed",{ detail:d })); }
export function disconnectSSE(){ try{ es?.close(); }catch{} es=null; }
