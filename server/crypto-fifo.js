// server/crypto-fifo.js — utilitaire FIFO d’allocation USDC (helper pur)

module.exports = function allocateUSDCFIFO(invoicesAsc, amountMicroInitial) {
  let left = Math.max(0, Number(amountMicroInitial || 0));
  const allocations = [];

  for (const inv of invoicesAsc) {
    const due = Number(inv.amount_usdc_micro || 0);
    const paid = Number(inv.paid_usdc_micro || 0);
    const rest = Math.max(due - paid, 0);
    if (rest <= 0) { allocations.push({ id: inv.id, applied: 0 }); continue; }
    const take = Math.min(rest, left);
    allocations.push({ id: inv.id, applied: take });
    left -= take;
    if (left <= 0) break;
  }
  return { allocations, leftover: left };
};
