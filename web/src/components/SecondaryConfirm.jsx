import { useState } from "react";

export default function SecondaryConfirm({ scope, onConfirmed, children }) {
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState("");
  const [loading, setLoading] = useState(false);

  async function confirm() {
    setLoading(true);
    try {
      const r = await fetch("/api/secondary/confirm", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ passwordSecondary: pw, scope })
      }).then(r=>r.json());
      if (r.ok && r.token) { setOpen(false); setPw(""); await onConfirmed(r.token); }
      else alert(r.error || "Erreur");
    } finally { setLoading(false); }
  }

  return (
    <>
      <span onClick={()=>setOpen(true)} style={{display:"inline-block"}}>{children}</span>
      {open && (
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.4)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:9999}}>
          <div style={{background:"#fff",padding:16,width:360,borderRadius:8}}>
            <h3>Confirmation requise</h3>
            <p>Entrez le mot de passe secondaire pour “{scope}”.</p>
            <input type="password" value={pw} onChange={e=>setPw(e.target.value)} style={{width:"100%",padding:8,margin:"12px 0"}} />
            <div style={{display:"flex",gap:8,justifyContent:"flex-end"}}>
              <button onClick={()=>setOpen(false)} disabled={loading}>Annuler</button>
              <button onClick={confirm} disabled={loading || !pw}>Confirmer</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
