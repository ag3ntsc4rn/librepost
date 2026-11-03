// Small UI helpers. Loaded as a same-origin file because the CSP forbids inline scripts.
(() => {
  "use strict";

  const ENV_KEY = "librepost.env";

  // Tabs: <div data-tabs> holding buttons with data-tab="x" and panels with data-panel="x".
  document.addEventListener("click", (event) => {
    const tab = event.target.closest("[data-tab]");
    if (!tab) return;
    const tabs = tab.closest("[data-tabs]");
    const name = tab.dataset.tab;
    for (const button of tabs.querySelectorAll(":scope > .tab-list [data-tab]")) {
      button.setAttribute("aria-selected", String(button.dataset.tab === name));
    }
    for (const panel of tabs.querySelectorAll(":scope > [data-panel]")) {
      panel.hidden = panel.dataset.panel !== name;
    }
  });

  // Highlight the open request in the sidebar.
  document.addEventListener("click", (event) => {
    const link = event.target.closest(".req-link");
    if (!link) return;
    event.preventDefault();
    for (const other of document.querySelectorAll(".req-link.active")) other.classList.remove("active");
    link.classList.add("active");
  });

  // Ctrl/Cmd+Enter sends, Ctrl/Cmd+S saves.
  document.addEventListener("keydown", (event) => {
    if (!(event.ctrlKey || event.metaKey)) return;
    let id = null;
    if (event.key === "Enter") id = "send";
    else if (event.key === "s" || event.key === "S") id = "save";
    const button = id && document.getElementById(id);
    if (!button) return;
    event.preventDefault();
    button.click();
  });

  // Tab inserts two spaces in text areas instead of leaving the field.
  document.addEventListener("keydown", (event) => {
    const area = event.target;
    if (event.key !== "Tab" || event.shiftKey || area.tagName !== "TEXTAREA") return;
    event.preventDefault();
    area.setRangeText("  ", area.selectionStart, area.selectionEnd, "end");
  });

  // After a successful import, clear what was pasted: it may contain credentials.
  document.addEventListener("htmx:afterRequest", (event) => {
    const form = event.target.closest && event.target.closest("form.import");
    if (!form || !event.detail.successful) return;
    if (!document.querySelector("#import-result .import-summary")) return;
    form.reset();
  });

  // Remember the chosen environment in this browser only.
  document.addEventListener("DOMContentLoaded", () => {
    const select = document.getElementById("env");
    if (!select) return;
    try {
      const saved = localStorage.getItem(ENV_KEY);
      if (saved !== null && [...select.options].some((o) => o.value === saved)) select.value = saved;
    } catch (_) { /* storage unavailable */ }
    select.addEventListener("change", () => {
      try { localStorage.setItem(ENV_KEY, select.value); } catch (_) { /* storage unavailable */ }
    });
  });
})();
