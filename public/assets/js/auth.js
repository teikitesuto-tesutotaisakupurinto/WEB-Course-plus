
import { auth, db, authPersistenceReady } from "./firebase.js";

import {
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

// ========================================
// 認証状態の取得
// ========================================

export async function getCurrentUser() {
  await authPersistenceReady;

  return new Promise((resolve, reject) => {
    const unsubscribe = onAuthStateChanged(
      auth,
      user => {
        unsubscribe();
        resolve(user);
      },
      error => {
        unsubscribe();
        reject(error);
      }
    );
  });
}

// ========================================
// ユーザープロフィール取得
// ========================================

export async function getProfile(uid) {
  if (!uid) {
    throw new Error("ユーザーIDが指定されていません。");
  }

  const profileRef = doc(db, "users", uid);
  const snapshot = await getDoc(profileRef);

  if (!snapshot.exists()) {
    throw new Error("利用者情報が登録されていません。");
  }

  const profile = snapshot.data();

  return {
    uid,
    ...profile
  };
}

// ========================================
// ログインユーザーとプロフィール
// ========================================

export async function getAuthenticatedProfile() {
  await authPersistenceReady;

  const user = await getCurrentUser();

  if (!user) {
    return null;
  }

  const profile = await getProfile(user.uid);

  if (profile.status !== "active") {
    throw new Error("このアカウントは利用できません。");
  }

  return {
    user,
    profile
  };
}

// ========================================
// ロール別アクセス制御
// ========================================

export async function requireRole(expectedRole) {
  try {
    const result = await getAuthenticatedProfile();

    if (!result) {
      window.location.replace("/login.html");
      return null;
    }

    const { user, profile } = result;

    const allowedRoles = Array.isArray(expectedRole)
      ? expectedRole
      : [expectedRole];

    if (!allowedRoles.includes(profile.role)) {
      if (profile.role === "admin") {
        window.location.replace("/admin/dashboard.html");
      } else if (profile.role === "teacher") {
        window.location.replace("/teacher/dashboard.html");
      } else if (profile.role === "student") {
        window.location.replace("/student/dashboard.html");
      } else {
        await signOut(auth);
        window.location.replace("/login.html");
      }

      return null;
    }

    return {
      user,
      profile
    };

  } catch (error) {
    console.error("[Auth] Access check failed:", error);

    if (auth.currentUser) {
      await signOut(auth).catch(() => {});
    }

    window.location.replace("/login.html");
    return null;
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
    console.error("[Auth] Logout failed:", error);
    throw new Error("ログアウトに失敗しました。");
  }
}

// ========================================
// Firebase ID Token取得
// ========================================

export async function getAccessToken() {
  await authPersistenceReady;

  const user = auth.currentUser;

  if (!user) {
    throw new Error("ログインしてください。");
  }

  return user.getIdToken();
}

// ========================================
// ロール別ホームページ
// ========================================

export function getDashboardUrl(role) {
  const routes = {
    student: "/student/dashboard.html",
    teacher: "/teacher/dashboard.html",
    admin: "/admin/dashboard.html"
  };

  return routes[role] || "/login.html";
}

// ========================================
// ログイン状態の監視
// ========================================

export function observeAuthState(callback) {
  return onAuthStateChanged(auth, callback);
}

// ========================================
// 互換用 Auth オブジェクト
// ========================================

export const Auth = {
  getCurrentUser,
  getProfile,
  getAuthenticatedProfile,
  requireRole,
  logout,
  getAccessToken,
  getDashboardUrl,
  observeAuthState
};

export default Auth;
