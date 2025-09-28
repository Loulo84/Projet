import React, { useCallback, useRef, useState } from "react";
import { Upload } from "lucide-react";

export default function ImageUploader({ onFiles }) {
  const inputRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);

  const openPicker = () => inputRef.current?.click();

  const onDrop = useCallback((e) => {
    e.preventDefault(); e.stopPropagation(); setDragOver(false);
    const files = e.dataTransfer?.files; if (files?.length) onFiles(files);
  }, [onFiles]);

  const onBrowse = (e) => {
    const files = e.target.files; if (files?.length) onFiles(files);
    e.target.value = "";
  };

  return (
    <div
      onDragOver={(e)=>{ e.preventDefault(); setDragOver(true); }}
      onDragLeave={()=>setDragOver(false)}
      onDrop={onDrop}
      className={`rounded-xl border-2 border-dashed p-6 text-center cursor-pointer transition
        ${dragOver ? "bg-emerald-50 border-emerald-400" : "bg-white hover:bg-gray-50"}
      `}
      onClick={openPicker}
    >
      <Upload className="w-8 h-8 mx-auto mb-2" />
      <div className="font-medium">Glisser-déposer vos images ici</div>
      <div className="text-sm text-gray-600">ou cliquez pour sélectionner</div>
      <input ref={inputRef} type="file" accept="image/*" multiple className="hidden" onChange={onBrowse} />
    </div>
  );
}
