(function () {
  "use strict";

  /* ------------------------------------------------------------------ *
   * Shared helpers
   * ------------------------------------------------------------------ */
  const $ = (id) => document.getElementById(id);

  function algorithmData() {
    const el = document.getElementById("algorithmData");
    if (!el) return [];
    try {
      return JSON.parse(el.textContent);
    } catch (e) {
      return [];
    }
  }

  const ALGORITHMS = algorithmData();
  const ALGO_BY_ID = {};
  ALGORITHMS.forEach((a) => (ALGO_BY_ID[a.id] = a));

  async function callApi(endpoint, payload) {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    let data;
    try {
      data = await res.json();
    } catch (e) {
      throw new Error("Unexpected server response.");
    }
    if (!res.ok || !data.success) {
      throw new Error(data.error || "Request failed.");
    }
    return data;
  }

  function setStatus(el, message, isError) {
    el.textContent = message;
    el.classList.remove("is-success", "is-error");
    if (message) el.classList.add(isError ? "is-error" : "is-success");
  }

  function updateCharCount(el, text) {
    const n = (text || "").length;
    el.textContent = `${n} character${n === 1 ? "" : "s"}`;
  }

  function downloadText(filename, text) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async function copyToClipboard(text, btn) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const original = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => (btn.textContent = original), 1200);
    } catch (e) {
      // Clipboard API may be unavailable (e.g. insecure context); fail silently.
    }
  }

  function renderAlgoInfo(container, algo) {
    if (!algo) {
      container.innerHTML = "";
      return;
    }
    const badgeClass =
      algo.security === "Recommended"
        ? "ok"
        : algo.security === "Broken"
        ? "danger"
        : algo.security && algo.security.startsWith("Not encryption")
        ? "neutral"
        : "warn";

    container.innerHTML = `
      <span class="algo-info__badge badge badge--${badgeClass}" style="display:inline-block;">${algo.security}</span>
      <p class="algo-info__desc">${algo.description}</p>
      <div class="algo-info__row"><span>Type</span><strong>${algo.type}</strong></div>
      <div class="algo-info__row"><span>Key</span><strong>${algo.key}</strong></div>
    `;
  }

  /* ------------------------------------------------------------------ *
   * Navigation: tabs + mobile menu
   * ------------------------------------------------------------------ */
  function applyTheme(theme) {
    const resolvedTheme = theme === "dark" ? "dark" : "light";
    document.body.setAttribute("data-theme", resolvedTheme);

    const toggle = $("themeToggle");
    if (toggle) {
      const isDark = resolvedTheme === "dark";
      toggle.classList.toggle("is-dark", isDark);
      const label = toggle.querySelector(".theme-toggle__label");
      const icon = toggle.querySelector(".theme-toggle__icon");
      if (label) label.textContent = isDark ? "White" : "Black";
      if (icon) icon.textContent = isDark ? "☾" : "☀";
      toggle.setAttribute("aria-label", isDark ? "Switch to white theme" : "Switch to black theme");
    }

    try {
      localStorage.setItem("jcrypt-theme", resolvedTheme);
    } catch (e) {
      // Ignore storage errors in restricted environments.
    }
  }

  function initThemeToggle() {
    let preferredTheme = "light";
    try {
      preferredTheme = localStorage.getItem("jcrypt-theme") || "light";
    } catch (e) {
      preferredTheme = "light";
    }

    applyTheme(preferredTheme);

    const toggle = $("themeToggle");
    if (!toggle) return;

    toggle.addEventListener("click", () => {
      const currentTheme = document.body.getAttribute("data-theme") === "dark" ? "dark" : "light";
      applyTheme(currentTheme === "dark" ? "light" : "dark");
    });
  }

  function initNav() {
    const toggle = $("navToggle");
    const nav = document.querySelector(".site-nav");
    if (toggle && nav) {
      toggle.addEventListener("click", () => {
        const open = nav.classList.toggle("is-open");
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
    }

    const tabButtons = document.querySelectorAll(".tab-btn");
    const panels = document.querySelectorAll(".panel-section");
    if (!tabButtons.length) return;

    function activateTab(name) {
      tabButtons.forEach((b) => b.classList.toggle("is-active", b.dataset.tab === name));
      panels.forEach((p) => p.classList.toggle("is-active", p.dataset.panel === name));
    }

    tabButtons.forEach((btn) => {
      btn.addEventListener("click", () => activateTab(btn.dataset.tab));
    });

    // Nav links use #anchors that match panel ids — switch tabs on click too.
    document.querySelectorAll('.site-nav__link[href*="#"]').forEach((link) => {
      link.addEventListener("click", () => {
        const hash = link.getAttribute("href").split("#")[1];
        if (hash && document.querySelector(`.panel-section[data-panel="${hash}"]`)) {
          activateTab(hash);
          nav && nav.classList.remove("is-open");
        }
      });
    });

    if (window.location.hash) {
      const hash = window.location.hash.slice(1);
      if (document.querySelector(`.panel-section[data-panel="${hash}"]`)) {
        activateTab(hash);
      }
    }
  }

  /* ------------------------------------------------------------------ *
   * Encrypt / Decrypt workspace
   * ------------------------------------------------------------------ */
  function initCryptoWorkspace() {
    const algoSelect = $("cryptoAlgorithm");
    if (!algoSelect) return;

    const opButtons = document.querySelectorAll("#cryptoOperation .segmented__btn");
    const paramsWrap = $("cryptoParams");
    const infoWrap = $("cryptoAlgoInfo");
    const input = $("cryptoInput");
    const output = $("cryptoOutput");
    const inputCount = $("cryptoInputCount");
    const outputCount = $("cryptoOutputCount");
    const status = $("cryptoStatus");
    const nonceWrap = $("cryptoNonceOutputWrap");
    const nonceField = $("cryptoNonceOutput");
    const statOperation = $("statOperation");
    const statAlgorithm = $("statAlgorithm");
    const statInputChars = $("statInputChars");
    const statOutputChars = $("statOutputChars");

    let operation = "encrypt";

    const AEAD = new Set(["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-poly1305"]);

    function fieldTemplate(id, label, opts) {
      opts = opts || {};
      const mono = opts.mono ? " field__control--mono" : "";
      const placeholder = opts.placeholder || "";
      const value = opts.value !== undefined ? opts.value : "";
      const type = opts.type || "text";
      if (opts.withGenerate) {
        return `
          <div class="field">
            <span class="field__label">${label}</span>
            <div class="field-with-action">
              <input type="text" id="${id}" class="field__control${mono}" placeholder="${placeholder}" value="${value}">
              <button type="button" class="btn btn--secondary btn--small" data-generate-for="${id}">Generate</button>
            </div>
          </div>`;
      }
      return `
        <div class="field">
          <span class="field__label">${label}</span>
          <input type="${type}" id="${id}" class="field__control${mono}" placeholder="${placeholder}" value="${value}">
        </div>`;
    }

    function renderParams() {
      const algoId = algoSelect.value;
      paramsWrap.innerHTML = "";

      if (AEAD.has(algoId)) {
        paramsWrap.insertAdjacentHTML(
          "beforeend",
          fieldTemplate("paramKey", "Key (Base64)", {
            mono: true,
            placeholder: "Paste or generate a key",
            withGenerate: true,
          })
        );
        if (operation === "decrypt") {
          paramsWrap.insertAdjacentHTML(
            "beforeend",
            fieldTemplate("paramNonce", "Nonce (Base64)", {
              mono: true,
              placeholder: "Nonce returned when encrypting",
            })
          );
        }
      } else if (algoId === "fernet") {
        paramsWrap.insertAdjacentHTML(
          "beforeend",
          fieldTemplate("paramKey", "Fernet Key", {
            mono: true,
            placeholder: "Paste or generate a key",
            withGenerate: true,
          })
        );
      } else if (algoId === "caesar") {
        paramsWrap.insertAdjacentHTML(
          "beforeend",
          fieldTemplate("paramShift", "Shift", { type: "number", value: "3" })
        );
      } else if (algoId === "vigenere") {
        paramsWrap.insertAdjacentHTML(
          "beforeend",
          fieldTemplate("paramKey", "Key (letters only)", { placeholder: "e.g. LEMON" })
        );
      } else if (algoId === "affine") {
        paramsWrap.insertAdjacentHTML(
          "beforeend",
          `<div class="field__row">
             ${fieldTemplate("paramA", "a", { type: "number", value: "5" })}
             ${fieldTemplate("paramB", "b", { type: "number", value: "8" })}
           </div>`
        );
      }
      // rot13 / atbash: no parameters

      paramsWrap.querySelectorAll("[data-generate-for]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const targetId = btn.dataset.generateFor;
          btn.disabled = true;
          const original = btn.textContent;
          btn.textContent = "…";
          try {
            const data = await callApi("/api/generate-key", { algorithm: algoId });
            $(targetId).value = data.result;
          } catch (e) {
            setStatus(status, e.message, true);
          } finally {
            btn.disabled = false;
            btn.textContent = original;
          }
        });
      });
    }

    function updateStats() {
      const algo = ALGO_BY_ID[algoSelect.value];
      statOperation.textContent = operation === "encrypt" ? "Encrypt" : "Decrypt";
      statAlgorithm.textContent = algo ? algo.name : "—";
      statInputChars.textContent = (input.value || "").length;
      statOutputChars.textContent = (output.value || "").length;
    }

    function refreshAll() {
      renderParams();
      renderAlgoInfo(infoWrap, ALGO_BY_ID[algoSelect.value]);
      nonceWrap.style.display = "none";
      updateCharCount(inputCount, input.value);
      updateCharCount(outputCount, output.value);
      updateStats();
    }

    algoSelect.addEventListener("change", refreshAll);

    opButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        opButtons.forEach((b) => b.classList.remove("is-active"));
        btn.classList.add("is-active");
        operation = btn.dataset.value;
        renderParams();
        nonceWrap.style.display = "none";
        updateStats();
      });
    });

    input.addEventListener("input", () => {
      updateCharCount(inputCount, input.value);
      updateStats();
    });

    $("cryptoRunBtn").addEventListener("click", async () => {
      const algoId = algoSelect.value;
      const text = input.value;
      setStatus(status, "", false);
      nonceWrap.style.display = "none";

      const payload = { algorithm: algoId, text: text };

      if (AEAD.has(algoId)) {
        payload.key = ($("paramKey") || {}).value || "";
        if (operation === "decrypt") payload.nonce = ($("paramNonce") || {}).value || "";
      } else if (algoId === "fernet") {
        payload.key = ($("paramKey") || {}).value || "";
      } else if (algoId === "caesar") {
        payload.shift = ($("paramShift") || {}).value || "0";
      } else if (algoId === "vigenere") {
        payload.key = ($("paramKey") || {}).value || "";
      } else if (algoId === "affine") {
        payload.a = ($("paramA") || {}).value || "0";
        payload.b = ($("paramB") || {}).value || "0";
      }

      const runBtn = $("cryptoRunBtn");
      runBtn.disabled = true;
      try {
        const endpoint = operation === "encrypt" ? "/api/encrypt" : "/api/decrypt";
        const data = await callApi(endpoint, payload);
        output.value = data.result;
        if (operation === "encrypt" && data.nonce) {
          nonceField.value = data.nonce;
          nonceWrap.style.display = "block";
        }
        setStatus(status, "Operation successful.", false);
      } catch (e) {
        output.value = "";
        setStatus(status, e.message, true);
      } finally {
        runBtn.disabled = false;
        updateCharCount(outputCount, output.value);
        updateStats();
      }
    });

    $("cryptoClearBtn").addEventListener("click", () => {
      input.value = "";
      output.value = "";
      nonceWrap.style.display = "none";
      setStatus(status, "", false);
      updateCharCount(inputCount, "");
      updateCharCount(outputCount, "");
      updateStats();
    });

    $("cryptoCopyBtn").addEventListener("click", (e) => copyToClipboard(output.value, e.target));
    $("cryptoNonceCopyBtn").addEventListener("click", (e) => copyToClipboard(nonceField.value, e.target));
    $("cryptoDownloadBtn").addEventListener("click", () => {
      if (output.value) downloadText("jcrypt-result.txt", output.value);
    });

    refreshAll();
  }

  /* ------------------------------------------------------------------ *
   * Hash workspace
   * ------------------------------------------------------------------ */
  function initHashWorkspace() {
    const algoSelect = $("hashAlgorithm");
    if (!algoSelect) return;

    const infoWrap = $("hashAlgoInfo");
    const input = $("hashInput");
    const output = $("hashOutput");
    const inputCount = $("hashInputCount");
    const outputCount = $("hashOutputCount");
    const status = $("hashStatus");

    function refresh() {
      renderAlgoInfo(infoWrap, ALGO_BY_ID[algoSelect.value]);
    }

    algoSelect.addEventListener("change", refresh);

    input.addEventListener("input", () => updateCharCount(inputCount, input.value));

    $("hashRunBtn").addEventListener("click", async () => {
      setStatus(status, "", false);
      const runBtn = $("hashRunBtn");
      runBtn.disabled = true;
      try {
        const data = await callApi("/api/hash", {
          algorithm: algoSelect.value,
          text: input.value,
        });
        output.value = data.result;
        setStatus(
          status,
          `Operation successful — ${data.details.length_bits}-bit digest (${data.details.status}).`,
          false
        );
      } catch (e) {
        output.value = "";
        setStatus(status, e.message, true);
      } finally {
        runBtn.disabled = false;
        updateCharCount(outputCount, output.value);
      }
    });

    $("hashClearBtn").addEventListener("click", () => {
      input.value = "";
      output.value = "";
      setStatus(status, "", false);
      updateCharCount(inputCount, "");
      updateCharCount(outputCount, "");
    });

    $("hashCopyBtn").addEventListener("click", (e) => copyToClipboard(output.value, e.target));
    $("hashDownloadBtn").addEventListener("click", () => {
      if (output.value) downloadText("jcrypt-hash.txt", output.value);
    });

    refresh();
  }

  /* ------------------------------------------------------------------ *
   * Encode / Decode workspace
   * ------------------------------------------------------------------ */
  function initEncodeWorkspace() {
    const methodSelect = $("encodeMethod");
    if (!methodSelect) return;

    const opButtons = document.querySelectorAll("#encodeOperation .segmented__btn");
    const infoWrap = $("encodeAlgoInfo");
    const input = $("encodeInput");
    const output = $("encodeOutput");
    const inputCount = $("encodeInputCount");
    const outputCount = $("encodeOutputCount");
    const status = $("encodeStatus");

    let operation = "encode";

    function refresh() {
      renderAlgoInfo(infoWrap, ALGO_BY_ID[methodSelect.value]);
    }

    methodSelect.addEventListener("change", refresh);

    opButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        opButtons.forEach((b) => b.classList.remove("is-active"));
        btn.classList.add("is-active");
        operation = btn.dataset.value;
      });
    });

    input.addEventListener("input", () => updateCharCount(inputCount, input.value));

    $("encodeRunBtn").addEventListener("click", async () => {
      setStatus(status, "", false);
      const runBtn = $("encodeRunBtn");
      runBtn.disabled = true;
      try {
        const endpoint = operation === "encode" ? "/api/encode" : "/api/decode";
        const data = await callApi(endpoint, {
          method: methodSelect.value,
          text: input.value,
        });
        output.value = data.result;
        setStatus(status, "Operation successful.", false);
      } catch (e) {
        output.value = "";
        setStatus(status, e.message, true);
      } finally {
        runBtn.disabled = false;
        updateCharCount(outputCount, output.value);
      }
    });

    $("encodeClearBtn").addEventListener("click", () => {
      input.value = "";
      output.value = "";
      setStatus(status, "", false);
      updateCharCount(inputCount, "");
      updateCharCount(outputCount, "");
    });

    $("encodeCopyBtn").addEventListener("click", (e) => copyToClipboard(output.value, e.target));
    $("encodeDownloadBtn").addEventListener("click", () => {
      if (output.value) downloadText("jcrypt-encoded.txt", output.value);
    });

    refresh();
  }

  document.addEventListener("DOMContentLoaded", () => {
    initThemeToggle();
    initNav();
    initCryptoWorkspace();
    initHashWorkspace();
    initEncodeWorkspace();
  });
})();
