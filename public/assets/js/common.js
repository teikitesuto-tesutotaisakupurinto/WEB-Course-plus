import { Auth } from "./auth.js";

export function initializeSidebar() {
  const toggle = document.querySelector("#sidebarToggle");
  const sidebar = document.querySelector(".sidebar");

  if (!toggle || !sidebar) return;

  toggle.addEventListener("click", () => {
    sidebar.classList.toggle("collapsed");
  });
}

export function initializeLogout() {
  document.querySelectorAll("[data-logout]").forEach(button => {
    button.addEventListener("click", async () => {
      button.disabled = true;

      try {
        await Auth.logout();
      } catch (error) {
        button.disabled = false;
        alert("ログアウトに失敗しました。");
      }
    });
  });
}

export function showError(container, message) {
  if (!container) return;

  container.innerHTML = "";

  const element = document.createElement("div");
  element.className = "error-message";
  element.textContent = message;

  container.appendChild(element);
}

export function formatDate(value) {
  if (!value) return "-";

  const date = value.toDate
    ? value.toDate()
    : new Date(value);

  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(date);
}

export function formatDateTime(value) {
  if (!value) return "-";

  const date = value.toDate
    ? value.toDate()
    : new Date(value);

  return new Intl.DateTimeFormat("ja-JP", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(date);
}

document.addEventListener("DOMContentLoaded", () => {
  initializeSidebar();
  initializeLogout();
});
