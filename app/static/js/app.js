/* Client-side UX helpers (CSP-compliant external script; zero inline handlers). */
(function () {
  "use strict";

  // 1. Live password strength feedback on registration page
  const passwordInput = document.querySelector('input[data-password-meter="true"]');
  const meterEl = document.getElementById("password-strength-meter");

  if (passwordInput && meterEl) {
    passwordInput.addEventListener("input", function () {
      const value = passwordInput.value;
      if (!value) {
        meterEl.textContent = "";
        meterEl.className = "strength-meter";
        return;
      }

      let score = 0;
      if (value.length >= 10) score += 1;
      if (/[A-Z]/.test(value)) score += 1;
      if (/[a-z]/.test(value)) score += 1;
      if (/[0-9]/.test(value)) score += 1;
      if (/[^A-Za-z0-9]/.test(value)) score += 1;

      if (score <= 2) {
        meterEl.textContent = "Password strength: Weak";
        meterEl.className = "strength-meter strength-weak";
      } else if (score <= 4) {
        meterEl.textContent = "Password strength: Moderate (add length/symbols)";
        meterEl.className = "strength-meter strength-medium";
      } else {
        meterEl.textContent = "Password strength: Strong";
        meterEl.className = "strength-meter strength-strong";
      }
    });
  }

  // 2. Confirmation dialogs on destructive forms
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      const message = form.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  // 3. Copy-to-clipboard buttons on the Lab Guide page
  document.querySelectorAll("button[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      const text = button.getAttribute("data-copy") || "";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          const original = button.textContent;
          button.textContent = "Copied!";
          window.setTimeout(function () {
            button.textContent = original;
          }, 1500);
        });
      }
    });
  });
})();
