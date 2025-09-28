import React, { useRef, useState, useEffect } from "react";

export default function ModalDraggable({ open, onClose, title, children, footer }) {
  const dialogRef = useRef(null);
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const drag = useRef({ active: false, startX: 0, startY: 0, origX: 0, origY: 0 });

  useEffect(() => {
    if (!open) {
      setPos({ x: 0, y: 0 });
    }
  }, [open]);

  const onMouseDown = (e) => {
    drag.current = {
      active: true,
      startX: e.clientX,
      startY: e.clientY,
      origX: pos.x,
      origY: pos.y,
    };
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  };

  const onMouseMove = (e) => {
    if (!drag.current.active) return;
    const dx = e.clientX - drag.current.startX;
    const dy = e.clientY - drag.current.startY;
    setPos({ x: drag.current.origX + dx, y: drag.current.origY + dy });
  };

  const onMouseUp = () => {
    drag.current.active = false;
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      {/* overlay */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      {/* modal */}
      <div
        ref={dialogRef}
        className="absolute left-1/2 top-1/2 min-w-[340px] max-w-[90vw] rounded-2xl bg-white shadow-2xl"
        style={{ transform: `translate(calc(-50% + ${pos.x}px), calc(-50% + ${pos.y}px))` }}
      >
        {/* header (draggable) */}
        <div
          className="cursor-move select-none rounded-t-2xl bg-gray-100 px-4 py-3 font-semibold flex items-center justify-between"
          onMouseDown={onMouseDown}
        >
          <span>{title}</span>
          <button className="text-gray-500 hover:text-gray-700" onClick={onClose}>✕</button>
        </div>

        {/* content */}
        <div className="px-4 py-4">
          {children}
        </div>

        {/* footer */}
        {footer && (
          <div className="px-4 pb-4 pt-2 flex justify-end gap-2">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
