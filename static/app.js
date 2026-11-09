"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const price = Number(document.body.dataset.pricePerDocument || 100);
  const total = document.getElementById("total-amount");
  const checkboxes = document.querySelectorAll('input[name="documents"]');
  if (!total || checkboxes.length === 0) return;

  const updateTotal = () => {
    const amount = [...checkboxes].reduce((sum, checkbox) => {
      const copies = document.querySelector(`input[name="copies_${checkbox.value}"]`);
      if (copies) copies.disabled = !checkbox.checked;
      if (!checkbox.checked) return sum;
      const quantity = Math.max(1, Math.min(10, Number.parseInt(copies?.value || "1", 10) || 1));
      return sum + quantity * price;
    }, 0);
    total.value = `PHP ${amount.toFixed(2)}`;
    total.textContent = total.value;
  };

  checkboxes.forEach((checkbox) => checkbox.addEventListener("change", updateTotal));
  document.querySelectorAll('input[name^="copies_"]').forEach((input) => {
    input.addEventListener("input", updateTotal);
    input.addEventListener("change", updateTotal);
  });
  updateTotal();
});
