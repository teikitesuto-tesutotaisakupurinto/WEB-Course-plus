
import { auth } from "/assets/js/firebase.js";

import {
  signOut
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

const SESSION_KEY = "web-course-plus-device-session";
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{16,100}$/;

let heartbeatTimer = null;
let heartbeatRunning = false;
let logoutInProgress = false;
let sessionRegistered = false;

/* ========================================
   端末セッション
======================================== */

export function getSessionId() {
  const value = String(
    localStorage.getItem(SESSION_KEY) || ""
  ).trim();

  if (!SESSION_ID_PATTERN.test(value)) {
    localStorage.removeItem(SESSION_KEY);
    sessionRegistered = false;
    return "";
  }

  return value;
}

export function setSessionId(value) {
  const sessionId = String(value || "").trim();

  if (!SESSION_ID_PATTERN.test(sessionId)) {
    localStorage.removeItem(SESSION_KEY);
    sessionRegistered = false;
    return;
  }

  localStorage.setItem(SESSION_KEY, sessionId);
}

export function createSessionId() {
  if (
    typeof crypto !== "undefined" &&
    typeof crypto.randomUUID === "function"
  ) {
    return crypto.randomUUID();
  }

  const random = () => {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);

    return Array.from(bytes)
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");
  };

  return random();
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

  // セッション登録API以外ではID必須
  const isRegisterApi = path === "/api/sessions/register";

  if (!isRegisterApi && !sessionId) {
    throw new Error(
      "端末セッションIDがありません。ログインし直してください。"
    );
  }

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

  stopSessionHeartbeat();
  sessionRegistered = false;

  let sessionId = getSessionId();

  if (!sessionId) {
    sessionId = createSessionId();
    setSessionId(sessionId);
  }

  if (!SESSION_ID_PATTERN.test(sessionId)) {
    throw new Error("端末セッションIDを生成できませんでした。");
  }

  const token = await user.getIdToken();

  const headers = new Headers({
    "Authorization": `Bearer ${token}`,
    "X-Session-Id": sessionId,
    "Content-Type": "application/json"
  });

  const response = await fetch("/api/sessions/register", {
    method: "POST",
    headers,
    body: JSON.stringify({
      sessionId,
      deviceName: navigator.userAgent.slice(0, 180)
    }),
    credentials: "same-origin",
    cache: "no-store"
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok || result.success === false) {
    throw new Error(
      result.error ||
      result.message ||
      "端末登録に失敗しました。"
    );
  }

  sessionRegistered = true;

  startSessionHeartbeat();

  return result;
}

/* ========================================
   セッション定期確認
======================================== */

export function startSessionHeartbeat() {
  stopSessionHeartbeat();

  if (
    !auth.currentUser ||
    !getSessionId() ||
    !sessionRegistered
  ) {
    return;
  }

  const heartbeat = async () => {
    if (heartbeatRunning) return;

    if (
      !auth.currentUser ||
      !getSessionId() ||
      !sessionRegistered
    ) {
      return;
    }

    heartbeatRunning = true;

    try {
      const sessionId = getSessionId();

      await apiFetch("/api/sessions/heartbeat", {
        method: "POST",
        body: JSON.stringify({ sessionId })
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
        sessionRegistered = false;

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
