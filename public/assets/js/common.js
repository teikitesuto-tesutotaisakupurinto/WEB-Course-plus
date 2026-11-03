import { auth } from "/assets/js/firebase.js";
import { signOut } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

const SESSION_KEY = "wcp_session_id";
const API_BASE = "";

let heartbeatTimer = null;
let heartbeatRunning = false;

/* ==============================
   セッション管理
============================== */

export function getSessionId() {
  return sessionStorage.getItem(SESSION_KEY) ||
         localStorage.getItem(SESSION_KEY) ||
         "";
}

export function setSessionId(value) {
  if (!value) {
    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_KEY);
    return;
  }

  localStorage.setItem(SESSION_KEY, value);
}

export function createSessionId() {
  if (crypto.randomUUID) {
    return crypto.randomUUID();
  }

  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

/* ==============================
   サイドバー
============================== */

export function initializeSidebar() {
  const sidebar = document.querySelector(
    ".app-sidebar, #appSidebar"
  );

  const toggleButtons = document.querySelectorAll(
    "[data-sidebar-toggle], .menu-toggle"
  );

  if (!sidebar) return;

  toggleButtons.forEach(button => {
    if (button.dataset.sidebarInitialized === "true") return;

    button.dataset.sidebarInitialized = "true";

    button.addEventListener("click", event => {
      event.preventDefault();

      sidebar.classList.toggle("is-open");
      document.body.classList.toggle("sidebar-open");

      button.setAttribute(
        "aria-expanded",
        sidebar.classList.contains("is-open") ? "true" : "false"
      );
    });
  });

  document.addEventListener("click", event => {
    if (window.innerWidth > 800) return;

    const clickedInsideSidebar = sidebar.contains(event.target);

    const clickedToggle = event.target.closest(
      "[data-sidebar-toggle], .menu-toggle"
    );

    if (!clickedInsideSidebar && !clickedToggle) {
      sidebar.classList.remove("is-open");
      document.body.classList.remove("sidebar-open");

      toggleButtons.forEach(button => {
        button.setAttribute("aria-expanded", "false");
      });
    }
  });

  window.addEventListener("resize", () => {
    if (window.innerWidth > 800) {
      sidebar.classList.remove("is-open");
      document.body.classList.remove("sidebar-open");
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
      console.warn("メニューURL確認エラー:", error);
    }
  });
}

/* ==============================
   フッター
============================== */

export function renderFooter() {
  const footer = document.getElementById("app-footer");

  if (!footer) return;

  footer.textContent =
    "© 2026 定期テスト対策プリント運営事務局. All Rights Reserved.";
}

/* ==============================
   メッセージ表示
============================== */

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

/* ==============================
   HTMLエスケープ
============================== */

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

/* ==============================
   日付・時刻
============================== */

export function formatDate(value) {
  if (!value) return "-";

  const date = value?.toDate
    ? value.toDate()
    : new Date(value);

  if (Number.isNaN(date.getTime())) return "-";

  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(date);
}

export function formatDateTime(value) {
  if (!value) return "-";

  const date = value?.toDate
    ? value.toDate()
    : new Date(value);

  if (Number.isNaN(date.getTime())) return "-";

  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

export function formatTime(value) {
  if (!value) return "-";

  const date = value?.toDate
    ? value.toDate()
    : new Date(value);

  if (Number.isNaN(date.getTime())) return "-";

  return new Intl.DateTimeFormat("ja-JP", {
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

/* ==============================
   API通信
============================== */

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
    !(options.body instanceof URLSearchParams) &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "same-origin"
  });

  const result = await response.json().catch(() => ({
    success: false,
    message: "サーバーから正しい応答を受信できませんでした。"
  }));

  if (!response.ok || result.success === false) {
    const error = new Error(
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

/* ==============================
   強制ログアウト
============================== */

export async function forceLogout() {
  stopSessionHeartbeat();
  setSessionId("");

  await signOut(auth).catch(() => {});

  if (location.pathname !== "/login.html") {
    location.replace("/login.html?reason=session");
  }
}

/* ==============================
   端末セッション登録
============================== */

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

  try {
    const result = await apiFetch("/api/sessions/register", {
      method: "POST",
      body: JSON.stringify({
        sessionId,
        deviceName: navigator.userAgent.slice(0, 180)
      })
    });

    if (!result.success) {
      throw new Error(
        result.message || "端末登録に失敗しました。"
      );
    }

    startSessionHeartbeat();

    return result;

  } catch (error) {
    console.error("端末登録エラー:", error);
    throw error;
  }
}

/* ==============================
   セッション定期確認
============================== */

export function startSessionHeartbeat() {
  stopSessionHeartbeat();

  if (!auth.currentUser || !getSessionId()) return;

  const sendHeartbeat = async () => {
    if (heartbeatRunning) return;
    if (!auth.currentUser) return;
    if (!getSessionId()) return;

    heartbeatRunning = true;

    try {
      await apiFetch("/api/sessions/heartbeat", {
        method: "POST",
        body: JSON.stringify({
          sessionId: getSessionId()
        })
      });

    } catch (error) {
      console.error("セッション確認エラー:", error);

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

  sendHeartbeat();

  heartbeatTimer = window.setInterval(
    sendHeartbeat,
    30000
  );
}

export function stopSessionHeartbeat() {
  if (heartbeatTimer !== null) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }

  heartbeatRunning = false;
}

/* ==============================
   ログアウト
============================== */

export function initializeLogout() {
  document.querySelectorAll(
    "[data-logout], .logout-button, .logout"
  ).forEach(button => {
    if (button.dataset.logoutInitialized === "true") return;

    button.dataset.logoutInitialized = "true";

    button.addEventListener("click", async event => {
      event.preventDefault();

      if (button.disabled) return;

      button.disabled = true;

      const originalText = button.textContent;

      button.textContent = "ログアウト中...";

      try {
        const sessionId = getSessionId();

        if (auth.currentUser && sessionId) {
          await apiFetch("/api/sessions/logout", {
            method: "POST",
            body: JSON.stringify({
              sessionId
            })
          }).catch(error => {
            console.warn(
              "サーバー側ログアウト通知:",
              error
            );
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

/* ==============================
   共通初期化
============================== */

export function initializeCommonLayout() {
  initializeSidebar();
  initializeLogout();
  renderFooter();
}
