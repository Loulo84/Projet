// src/lib/image.js
export async function compressImageFile(file, { maxSize = 2000, quality = 0.85 } = {}) {
  if (!file || !file.type?.startsWith("image/")) return file;
  const img = await new Promise((res, rej) => {
    const i = new Image();
    i.onload = () => res(i);
    i.onerror = rej;
    i.src = URL.createObjectURL(file);
  });
  let { width, height } = img;
  const scale = Math.min(1, maxSize / Math.max(width, height));
  const w = Math.round(width * scale);
  const h = Math.round(height * scale);

  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, w, h);

  const type = file.type === "image/png" ? "image/png" : "image/jpeg";
  const blob = await new Promise((res) => canvas.toBlob(res, type, quality));
  if (!blob) return file;
  return new File([blob], file.name.replace(/\.(png|jpe?g|webp)$/i, type==="image/png"?".png":".jpg"), { type });
}
