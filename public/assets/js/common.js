
import { auth } from "/assets/js/firebase.js";

import {
  signOut
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

const SESSION_KEY = "web-course-plus-device-session";

let heartbeatTimer = null;
let heartbeatRunning = false;
let logoutInProgress = false;

/* ========================================
   端末セッション
======================================== */

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

export function createSessionId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }

  return `${Date.now()}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
}

/* ========================================
   日時変換
======================================== */

export function toDate(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value.toDate === "function") {
    const date = value.toDate();
    return date instanceof Date && !Number.isNaN(date.getTime())
      ? date
      : null;
  }

  if (typeof value === "number" || typeof value === "string") {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  if (typeof value === "object" && value.seconds !== undefined) {
    const date = new Date(
      Number(value.seconds) * 1000 +
      Math.floor(Number(value.nanoseconds || 0) / 1000000)
    );

    return Number.isNaN(date.getTime()) ? null : date;
  }

  return null;
}

export function formatDate(value) {
  const date = toDate(value);

  if (!date) return "-";

  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(date);
}

export function formatDateTime(value) {
  const date = toDate(value);

  if (!date) return "-";

  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

export function formatTime(value) {
  const date = toDate(value);

  if (!date) return "-";

  return new Intl.DateTimeFormat("ja-JP", {
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

/* ========================================
   サイドバー
======================================== */

export function initializeSidebar() {
  const sidebar = document.querySelector(
    ".app-sidebar, #appSidebar"
  );

  const toggleButtons = document.querySelectorAll(
    "[data-sidebar-toggle]"
  );

  if (!sidebar) return;

  toggleButtons.forEach(button => {
    if (button.dataset.sidebarInitialized === "true") return;

    button.dataset.sidebarInitialized = "true";

    button.addEventListener("click", event => {
      event.preventDefault();

      const opened = sidebar.classList.toggle("is-open");

      document.body.classList.toggle("sidebar-open", opened);

      button.setAttribute("aria-expanded", String(opened));
    });
  });

  document.addEventListener("click", event => {
    if (window.innerWidth > 800) return;

    if (
      sidebar.classList.contains("is-open") &&
      !sidebar.contains(event.target) &&
      !event.target.closest("[data-sidebar-toggle]")
    ) {
      sidebar.classList.remove("is-open");
      document.body.classList.remove("sidebar-open");

      toggleButtons.forEach(button => {
        button.setAttribute("aria-expanded", "false");
      });
    }
  });

  document.querySelectorAll(
    ".sidebar-link[href], .nav-link[href]"
  ).forEach(link => {
    try {
      const current = new URL(location.href);
      const target = new URL(link.href, location.origin);

      if (current.pathname === target.pathname) {
        link.classList.add("active");
      }
    } catch (error) {
      console.warn("メニューURLの確認に失敗しました。", error);
    }
  });

  window.addEventListener("resize", () => {
    if (window.innerWidth > 800) {
      sidebar.classList.remove("is-open");
      document.body.classList.remove("sidebar-open");
    }
  });
}

/* ========================================
   フッター
======================================== */

export function renderFooter() {
  const footer = document.getElementById("app-footer");

  if (!footer) return;

  footer.textContent =
    "© 2026 定期テスト対策プリント運営事務局. All Rights Reserved.";
}

/* ========================================
   メッセージ
======================================== */

export function showMessage(
  message,
  type = "info",
  targetId = "message"
) {
  const target = document.getElementById(targetId);

  if (!target) return;

  target.textContent = String(message ?? "");
  target.className = `message message-${type}`;
  target.hidden = false;
}

export function hideMessage(targetId = "message") {
  const target = document.getElementById(targetId);

  if (!target) return;

  target.hidden = true;
  target.textContent = "";
}

/* ========================================
   HTMLエスケープ
======================================== */

export function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    };

    return entities[character];
  });
}

export const escapeHtml = escapeHTML;

/* ========================================
   API通信
======================================== */

export async function apiFetch(path, options = {}) {
  const user = auth.currentUser;

  if (!user) {
    throw new Error("ログインしてください。");
  }

  const token = await user.getIdToken();

  const headers = new Headers(options.headers || {});

  headers.set("Authorization", `Bearer ${token}`);

  const sessionId = getSessionId();

  if (sessionId) {
    headers.set("X-Session-Id", sessionId);
  }

  if (
    options.body &&
    !(options.body instanceof FormData) &&
    !(options.body instanceof URLSearchParams) &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "same-origin",
    cache: "no-store"
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok || result.success === false) {
    const error = new Error(
      result.error ||
      result.message ||
      `通信に失敗しました。(HTTP ${response.status})`
    );

    error.status = response.status;
    error.code = result.code || "";

    if (
      response.status === 401 ||
      result.code === "SESSION_REVOKED" ||
      result.code === "SESSION_EXPIRED"
    ) {
      await forceLogout();
    }

    throw error;
  }

  return result;
}

/* ========================================
   強制ログアウト
======================================== */

export async function forceLogout() {
  if (logoutInProgress) return;

  logoutInProgress = true;

  stopSessionHeartbeat();
  setSessionId("");

  try {
    await signOut(auth);
  } catch (error) {
    console.warn("Firebaseログアウト処理:", error);
  }

  if (location.pathname !== "/login.html") {
    location.replace("/login.html?reason=session");
  }
}

/* ========================================
   端末セッション登録
======================================== */

export async function registerDeviceSession() {
  const user = auth.currentUser;

  if (!user) {
    throw new Error("ログインしてください。");
  }

  let sessionId = getSessionId();

  if (!sessionId) {
    sessionId = createSessionId();
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
    throw new Error(
      result.error || result.message || "端末登録に失敗しました。"
    );
  }

  startSessionHeartbeat();

  return result;
}

/* ========================================
   セッション定期確認
======================================== */

export function startSessionHeartbeat() {
  stopSessionHeartbeat();

  if (!auth.currentUser || !getSessionId()) return;

  const heartbeat = async () => {
    if (heartbeatRunning) return;
    if (!auth.currentUser || !getSessionId()) return;

    heartbeatRunning = true;

    try {
      await apiFetch("/api/sessions/heartbeat", {
        method: "POST",
        body: JSON.stringify({
          sessionId: getSessionId()
        })
      });
    } catch (error) {
      console.error("端末セッション確認エラー:", error);

      if (
        error.status === 401 ||
        error.status === 403 ||
        error.code === "SESSION_REVOKED" ||
        error.code === "SESSION_EXPIRED"
      ) {
        await forceLogout();
      }
    } finally {
      heartbeatRunning = false;
    }
  };

  heartbeat();

  heartbeatTimer = window.setInterval(
    heartbeat,
    30 * 1000
  );
}

export function stopSessionHeartbeat() {
  if (heartbeatTimer !== null) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }

  heartbeatRunning = false;
}

/* ========================================
   ログアウト
======================================== */

export function initializeLogout() {
  document.querySelectorAll("[data-logout]").forEach(button => {
    if (button.dataset.logoutInitialized === "true") return;

    button.dataset.logoutInitialized = "true";

    button.addEventListener("click", async event => {
      event.preventDefault();

      if (button.disabled || logoutInProgress) return;

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
        console.error("ログアウトエラー:", error);

        button.disabled = false;
        button.textContent = originalText;

        showMessage(
          "ログアウトに失敗しました。もう一度お試しください。",
          "error"
        );
      }
    });
  });
}

/* ========================================
   共通初期化
======================================== */

export function initializeCommonLayout() {
  initializeSidebar();
  initializeLogout();
  renderFooter();
}
