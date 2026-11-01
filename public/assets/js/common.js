
import { auth, db } from "./firebase.js";

import {
  signOut,
  onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

// ========================================
// 共通定数
// ========================================

export const APP_NAME = "WEB Course-plus";

export const FOOTER_TEXT =
  "© 2026 定期テスト対策プリント運営事務局. All Rights Reserved.";

// ========================================
// HTMLエスケープ
// ========================================

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

// ========================================
// 日付表示
// ========================================

export function formatDate(value) {
  const date = toDate(value);

  if (!date) return "-";

  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "long",
    day: "numeric"
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

export function toDate(value) {
  if (!value) return null;

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value.toDate === "function") {
    const result = value.toDate();

    return Number.isNaN(result.getTime()) ? null : result;
  }

  const result = new Date(value);

  return Number.isNaN(result.getTime()) ? null : result;
}

// ========================================
// メッセージ表示
// ========================================

export function showMessage(message, type = "info", targetId = "message") {
  const target = document.getElementById(targetId);

  if (!target) {
    console.warn(message);
    return;
  }

  const allowedTypes = [
    "info",
    "success",
    "danger",
    "warning"
  ];

  const safeType = allowedTypes.includes(type) ? type : "info";

  target.className = `alert alert-${safeType}`;
  target.textContent = message;
  target.classList.remove("hidden");
}

export function clearMessage(targetId = "message") {
  const target = document.getElementById(targetId);

  if (!target) return;

  target.textContent = "";
  target.className = "hidden";
}

// ========================================
// ローディング
// ========================================

export function setLoading(button, loading, loadingText = "処理中...") {
  if (!button) return;

  if (loading) {
    button.dataset.originalText = button.textContent;
    button.disabled = true;
    button.textContent = loadingText;
  } else {
    button.disabled = false;

    if (button.dataset.originalText !== undefined) {
      button.textContent = button.dataset.originalText;
      delete button.dataset.originalText;
    }
  }
}

// ========================================
// ログアウト
// ========================================

export async function logout() {
  try {
    await signOut(auth);
    window.location.replace("/login.html");
  } catch (error) {
    console.error("[Logout]", error);
    showMessage("ログアウトに失敗しました。", "danger");
  }
}

export function initializeLogout() {
  document.querySelectorAll("[data-logout]").forEach(button => {
    button.addEventListener("click", logout);
  });
}

// ========================================
// サイドバー
// ========================================

export function initializeSidebar() {
  const app = document.querySelector(".app");
  const toggle = document.querySelector("[data-sidebar-toggle]");

  if (!app || !toggle) return;

  const collapsed = window.matchMedia("(max-width: 768px)").matches;

  if (collapsed) {
    app.classList.add("sidebar-collapsed");
  }

  toggle.addEventListener("click", () => {
    app.classList.toggle("sidebar-collapsed");
  });

  document.querySelectorAll(".sidebar-link").forEach(link => {
    const linkPath = new URL(link.href, window.location.origin).pathname;

    if (linkPath === window.location.pathname) {
      link.classList.add("active");
    }
  });
}

// ========================================
// ログインユーザー取得
// ========================================

export function waitForAuth() {
  return new Promise(resolve => {
    const unsubscribe = onAuthStateChanged(auth, user => {
      unsubscribe();
      resolve(user);
    });
  });
}

export async function getUserProfile(uid) {
  const userRef = doc(db, "users", uid);
  const snapshot = await getDoc(userRef);

  if (!snapshot.exists()) {
    throw new Error("利用者情報が登録されていません。");
  }

  return {
    uid,
    ...snapshot.data()
  };
}

// ========================================
// ロール別アクセス制御
// ========================================

export async function requireRole(allowedRoles) {
  const user = await waitForAuth();

  if (!user) {
    window.location.replace("/login.html");
    return null;
  }

  try {
    const profile = await getUserProfile(user.uid);

    if (profile.status !== "active") {
      await signOut(auth);
      window.location.replace("/login.html");
      return null;
    }

    if (!allowedRoles.includes(profile.role)) {
      window.location.replace("/login.html");
      return null;
    }

    return {
      user,
      profile
    };

  } catch (error) {
    console.error("[Access Control]", error);

    window.location.replace("/login.html");
    return null;
  }
}

// ========================================
// API通信
// ========================================

export async function apiRequest(endpoint, options = {}) {
  const user = auth.currentUser;

  if (!user) {
    throw new Error("ログインしてください。");
  }

  const idToken = await user.getIdToken();

  const response = await fetch(endpoint, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${idToken}`,
      ...(options.headers || {})
    }
  });

  let result;

  try {
    result = await response.json();
  } catch {
    throw new Error("サーバーから正しい応答を受信できませんでした。");
  }

  if (!response.ok || result.success === false) {
    throw new Error(
      result.message || "通信に失敗しました。"
    );
  }

  return result;
}

// ========================================
// システム状態
// ========================================

export async function getSystemStatus() {
  const response = await fetch("/api/system/status");

  if (!response.ok) {
    throw new Error("システム状態を取得できません。");
  }

  return response.json();
}

// ========================================
// 共通フッター
// ========================================

export function renderFooter(targetId = "app-footer") {
  const footer = document.getElementById(targetId);

  if (!footer) return;

  footer.className = "app-footer";
  footer.textContent = FOOTER_TEXT;
}

// ========================================
// 初期化
// ========================================

document.addEventListener("DOMContentLoaded", () => {
  initializeSidebar();
  initializeLogout();
  renderFooter();
});
