
import {
  auth,
  db,
  authPersistenceReady
} from "./firebase.js";

import {
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

import {
  getSessionId,
  apiFetch,
  startSessionHeartbeat,
  stopSessionHeartbeat,
  setSessionId
} from "./common.js";

/* ========================================
   認証状態
======================================== */

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

/* ========================================
   プロフィール取得
======================================== */

export async function getProfile(uid) {
  if (!uid) {
    throw new Error("ユーザーIDが指定されていません。");
  }

  const snapshot = await getDoc(
    doc(db, "users", uid)
  );

  if (!snapshot.exists()) {
    throw new Error("利用者情報が登録されていません。");
  }

  return {
    uid,
    ...snapshot.data()
  };
}

/* ========================================
   利用状態確認
======================================== */

function isActiveProfile(profile) {
  if (!profile || profile.active === false) {
    return false;
  }

  const status = String(profile.status || "active").toLowerCase();

  return ![
    "inactive",
    "disabled",
    "suspended",
    "deleted"
  ].includes(status);
}

/* ========================================
   認証済みプロフィール
======================================== */

export async function getAuthenticatedProfile() {
  await authPersistenceReady;

  const user = await getCurrentUser();

  if (!user) {
    return null;
  }

  const profile = await getProfile(user.uid);

  if (!isActiveProfile(profile)) {
    throw new Error("このアカウントは利用できません。");
  }

  return {
    user,
    profile
  };
}

/* ========================================
   端末セッション確認
======================================== */

export async function verifyDeviceSession() {
  if (!auth.currentUser) {
    throw new Error("ログインしてください。");
  }

  const sessionId = getSessionId();

  if (!sessionId) {
    throw new Error("端末セッションが登録されていません。");
  }

  const result = await apiFetch("/api/sessions/heartbeat", {
    method: "POST",
    body: JSON.stringify({ sessionId })
  });

  if (!result.success) {
    throw new Error("端末セッションを確認できません。");
  }

  startSessionHeartbeat();

  return true;
}

/* ========================================
   ロール別アクセス制御
======================================== */

export async function requireRole(expectedRole) {
  try {
    await authPersistenceReady;

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
      const destination = getDashboardUrl(profile.role);

      if (destination === "/login.html") {
        await signOut(auth);
      }

      window.location.replace(destination);
      return null;
    }

    await verifyDeviceSession();

    return {
      user,
      profile
    };

  } catch (error) {
    console.error("[Auth] Access check failed:", error);

    stopSessionHeartbeat();
    setSessionId("");

    if (auth.currentUser) {
      await signOut(auth).catch(() => {});
    }

    window.location.replace("/login.html?reason=session");
    return null;
  }
}

/* ========================================
   ログアウト
======================================== */

export async function logout() {
  try {
    const sessionId = getSessionId();

    if (auth.currentUser && sessionId) {
      await apiFetch("/api/sessions/logout", {
        method: "POST",
        body: JSON.stringify({ sessionId })
      }).catch(() => {});
    }

    stopSessionHeartbeat();
    setSessionId("");

    await signOut(auth);

    window.location.replace("/login.html");

  } catch (error) {
    console.error("[Auth] Logout failed:", error);
    throw new Error("ログアウトに失敗しました。");
  }
}

/* ========================================
   Firebase ID Token
======================================== */

export async function getAccessToken() {
  await authPersistenceReady;

  const user = auth.currentUser;

  if (!user) {
    throw new Error("ログインしてください。");
  }

  return user.getIdToken();
}

/* ========================================
   ホームURL
======================================== */

export function getDashboardUrl(role) {
  const routes = {
    student: "/student/dashboard.html",
    teacher: "/teacher/dashboard.html",
    admin: "/admin/dashboard.html"
  };

  return routes[role] || "/login.html";
}

/* ========================================
   認証状態監視
======================================== */

export function observeAuthState(callback) {
  return onAuthStateChanged(auth, callback);
}

/* ========================================
   Auth互換オブジェクト
======================================== */

export const Auth = {
  getCurrentUser,
  getProfile,
  getAuthenticatedProfile,
  verifyDeviceSession,
  requireRole,
  logout,
  getAccessToken,
  getDashboardUrl,
  observeAuthState
};

export default Auth;
