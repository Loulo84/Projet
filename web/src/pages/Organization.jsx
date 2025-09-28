import React, { useEffect, useState } from "react";
import { useToast } from "@/ui/Toast";
import { api } from "@/api";

const ROLES = ["OWNER","ADMIN","AGENT","ACCOUNTANT","VIEWER"];

export default function Organization(){
  const toast = useToast();
  const [orgs, setOrgs] = useState([]);
  const [members, setMembers] = useState([]);
  const [invite, setInvite] = useState({ email:"", role:"VIEWER" });
  const [keys, setKeys] = useState([]);
  const [newKeyName, setNewKeyName] = useState("");
  const [loading, setLoading] = useState(true);

  async function load(){
    setLoading(true);
    try{
      const [o, m, k] = await Promise.all([
        api.orgList(),
        api.memberList(),
        api.apiKeysList()
      ]);
      setOrgs(o||[]);
      setMembers(m||[]);
      setKeys(k||[]);
    } finally { setLoading(false); }
  }
  useEffect(()=>{ load(); }, []);

  async function addMember(){
    if(!invite.email) return;
    try{
      await api.memberAdd(invite.email, invite.role);
      setInvite({ email:"", role:"VIEWER" });
      await load();
      toast?.success("Membre ajouté/mis à jour");
    }catch(e){ toast?.error(e?.response?.data?.error || "Erreur ajout membre"); }
  }
  async function removeMember(userId){
    try{ await api.memberRemove(userId); await load(); }
    catch(e){ toast?.error(e?.response?.data?.error || "Erreur suppression"); }
  }

  async function createKey(){
    if(!newKeyName.trim()) return;
    try{
      const { token } = await api.apiKeysCreate(newKeyName.trim());
      await load();
      setNewKeyName("");
      toast?.success(`Clé créée : ${token}`);
    }catch(e){ toast?.error(e?.response?.data?.error || "Erreur création clé"); }
  }
  async function deleteKey(id){
    try{ await api.apiKeysDelete(id); await load(); }
    catch(e){ toast?.error(e?.response?.data?.error || "Erreur suppression clé"); }
  }

  return (
    <div className="max-w-5xl mx-auto p-4 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Organisation</h1>
        {loading && <div className="text-sm">Chargement…</div>}
        {!loading && orgs[0] && <div className="text-sm text-gray-600">Org active : <b>{orgs[0].name}</b></div>}
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {/* Membres */}
        <section className="rounded border p-4">
          <div className="font-semibold mb-3">Membres</div>
          <div className="space-y-2">
            {members.map(m=>(
              <div key={m.user_id} className="flex items-center justify-between border rounded px-3 py-2">
                <div>
                  <div className="font-medium">{m.name || m.email}</div>
                  <div className="text-xs text-gray-600">{m.email}</div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-0.5 rounded border">{m.role}</span>
                  <button onClick={()=>removeMember(m.user_id)} className="text-sm rounded border px-2 py-1 hover:bg-gray-50">
                    Retirer
                  </button>
                </div>
              </div>
            ))}
            {members.length===0 && <div className="text-sm text-gray-500">Aucun membre.</div>}
          </div>

          <div className="mt-4 grid grid-cols-[1fr,140px,auto] gap-2">
            <input className="rounded border px-3 py-2" placeholder="Email" value={invite.email}
              onChange={(e)=>setInvite(s=>({ ...s, email:e.target.value }))}/>
            <select className="rounded border px-3 py-2" value={invite.role}
              onChange={(e)=>setInvite(s=>({ ...s, role:e.target.value }))}>
              {ROLES.map(r=><option key={r} value={r}>{r}</option>)}
            </select>
            <button onClick={addMember} className="rounded bg-gray-900 text-white px-3 py-2 hover:bg-black">
              Inviter / Mettre à jour
            </button>
          </div>
        </section>

        {/* API Keys */}
        <section className="rounded border p-4">
          <div className="font-semibold mb-3">API Keys</div>
          <div className="space-y-2">
            {keys.map(k=>(
              <div key={k.id} className="flex items-center justify-between border rounded px-3 py-2">
                <div>
                  <div className="font-medium">{k.name}</div>
                  <div className="text-xs text-gray-600">
                    Créée : {new Date(k.created_at).toLocaleString()}
                    {k.last_used_at && <> — Dernier usage : {new Date(k.last_used_at).toLocaleString()}</>}
                  </div>
                </div>
                <button onClick={()=>deleteKey(k.id)} className="text-sm rounded border px-2 py-1 hover:bg-gray-50">Supprimer</button>
              </div>
            ))}
            {keys.length===0 && <div className="text-sm text-gray-500">Aucune clé.</div>}
          </div>

          <div className="mt-4 flex gap-2">
            <input className="flex-1 rounded border px-3 py-2" placeholder="Nom de la clé"
              value={newKeyName} onChange={(e)=>setNewKeyName(e.target.value)}/>
            <button onClick={createKey} className="rounded bg-gray-900 text-white px-3 py-2 hover:bg-black">
              Créer
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}
