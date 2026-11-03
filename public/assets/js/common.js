// public/assets/js/common.js
import { auth } from "/assets/js/firebase.js";
import { signOut } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

const SESSION_KEY = "wcp_session_id";
const API_BASE = "";

let heartbeatTimer = null;

export function getSessionId() {
  return localStorage.getItem(SESSION_KEY) || "";
}

export function setSessionId(value) {
  if (!value) {
    localStorage.removeItem(SESSION_KEY);
    return;
  }
  localStorage.setItem(SESSION_KEY, value);
}

export function initializeSidebar() {
  const sidebar = document.querySelector(".app-sidebar, #appSidebar");
  const toggleButtons = document.querySelectorAll("[data-sidebar-toggle]");

  if (!sidebar) return;

  toggleButtons.forEach(button => {
    button.addEventListener("click", () => {
      document.body.classList.toggle("sidebar-open");
      sidebar.classList.toggle("is-open");
    });
  });

  document.addEventListener("click", event => {
    if (
      window.innerWidth <= 800 &&
      sidebar.classList.contains("is-open") &&
      !sidebar.contains(event.target) &&
      !event.target.closest("[data-sidebar-toggle]")
    ) {
      sidebar.classList.remove("is-open");
      document.body.classList.remove("sidebar-open");
    }
  });

  document.querySelectorAll(".sidebar-link[href]").forEach(link => {
    const current = new URL(location.href);
    const target = new URL(link.href, location.origin);

    if (current.pathname === target.pathname) {
      link.classList.add("active");
    }
  });
}

export function renderFooter() {
  const footer = document.getElementById("app-footer");
  if (!footer) return;

  footer.textContent =
    "© 2026 定期テスト対策プリント運営事務局. All Rights Reserved.";
}

export function showMessage(message, type = "info", targetId = "message") {
  const target = document.getElementById(targetId);
  if (!target) return;

  target.textContent = String(message || "");
  target.className = `message message-${type}`;
  target.hidden = false;
}

export function hideMessage(targetId = "message") {
  const target = document.getElementById(targetId);
  if (!target) return;

  target.hidden = true;
  target.textContent = "";
}

export function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

// 既存ページとの互換用
export const escapeHtml = escapeHTML;

export async function apiFetch(path, options = {}) {
  const user = auth.currentUser;

  if (!user) {
    throw new Error("ログインしてください。");
  }

  const idToken = await user.getIdToken();

  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${idToken}`);

  const sessionId = getSessionId();
  if (sessionId) {
    headers.set("X-Session-Id", sessionId);
  }

  if (
    options.body &&
    !(options.body instanceof FormData) &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "same-origin"
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok || result.success === false) {
    if (response.status === 401 || response.status === 403) {
      if (result.code === "SESSION_REVOKED") {
        setSessionId("");
        await signOut(auth).catch(() => {});
        location.replace("/login.html?reason=session");
      }
    }

    throw new Error(
      result.message || `通信に失敗しました。(${response.status})`
    );
  }

  return result;
}

export async function registerDeviceSession() {
  const user = auth.currentUser;
  if (!user) throw new Error("ログインしてください。");

  let sessionId = getSessionId();

  if (!sessionId) {
    sessionId = crypto.randomUUID();
    setSessionId(sessionId);
  }

  const result = await apiFetch("/api/sessions/register", {
    method: "POST",
    body: JSON.stringify({
      sessionId,
      deviceName: navigator.userAgent.slice(0, 180)
    })
  });

  if (!result.success) {
    throw new Error(result.message || "端末登録に失敗しました。");
  }

  startSessionHeartbeat();
  return result;
}

export function startSessionHeartbeat() {
  stopSessionHeartbeat();

  const sendHeartbeat = async () => {
    if (!auth.currentUser || !getSessionId()) return;

    try {
      await apiFetch("/api/sessions/heartbeat", {
        method: "POST",
        body: JSON.stringify({
          sessionId: getSessionId()
        })
      });
    } catch (error) {
      console.error("セッション確認エラー:", error);
      if (/端末|セッション|ログイン/.test(error.message)) {
        stopSessionHeartbeat();
        setSessionId("");
        await signOut(auth).catch(() => {});
        location.replace("/login.html?reason=session");
      }
    }
  };

  sendHeartbeat();
  heartbeatTimer = window.setInterval(sendHeartbeat, 30000);
}

export function stopSessionHeartbeat() {
  if (heartbeatTimer !== null) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

export function initializeLogout() {
  document.querySelectorAll("[data-logout]").forEach(button => {
    button.addEventListener("click", async () => {
      if (button.disabled) return;

      button.disabled = true;
      const originalText = button.textContent;
      button.textContent = "ログアウト中...";

      try {
        const sessionId = getSessionId();

        if (auth.currentUser && sessionId) {
          await apiFetch("/api/sessions/logout", {
            method: "POST",
            body: JSON.stringify({ sessionId })
          }).catch(error => {
            console.warn("サーバー側ログアウト通知:", error);
          });
        }

        stopSessionHeartbeat();
        setSessionId("");
        await signOut(auth);

        location.replace("/login.html");
      } catch (error) {
        console.error(error);
        button.disabled = false;
        button.textContent = originalText;
        showMessage("ログアウトに失敗しました。もう一度お試しください。", "error");
      }
    });
  });
}

export function initializeCommonLayout() {
  initializeSidebar();
  initializeLogout();
  renderFooter();
}
