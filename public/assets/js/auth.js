
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
    let unsubscribe = null;

    unsubscribe = onAuthStateChanged(
      auth,
      user => {
        if (unsubscribe) unsubscribe();
        resolve(user);
      },
      error => {
        if (unsubscribe) unsubscribe();
        reject(error);
      }
    );
  });
}

/* ========================================
   利用状態確認
======================================== */

export function isActiveProfile(profile) {
  if (!profile || profile.active === false) {
    return false;
  }

  const status = String(
    profile.status || "active"
  ).toLowerCase();

  return ![
    "inactive",
    "disabled",
    "suspended",
    "deleted"
  ].includes(status);
}

/* ========================================
   プロフィール取得

   Firestoreの直接読み取りが拒否された場合は
   サーバー側のAdmin SDK APIへフォールバックする。
======================================== */

export async function getProfile(uid) {
  if (!uid) {
    throw new Error(
      "ユーザーIDが指定されていません。"
    );
  }

  if (
    auth.currentUser &&
    auth.currentUser.uid !== uid
  ) {
    throw new Error(
      "他のユーザーのプロフィールは取得できません。"
    );
  }

  try {
    const snapshot = await getDoc(
      doc(db, "users", uid)
    );

    if (snapshot.exists()) {
      return {
        uid,
        ...snapshot.data()
      };
    }

  } catch (firestoreError) {
    console.warn(
      "[Auth] Firestoreプロフィール取得に失敗。サーバーAPIを使用します。",
      firestoreError
    );
  }

  if (!auth.currentUser || !getSessionId()) {
    throw new Error(
      "利用者情報を取得できません。再度ログインしてください。"
    );
  }

  const response = await apiFetch(
    "/api/me",
    {
      method: "GET"
    }
  );

  if (
    !response.user ||
    response.user.uid !== uid
  ) {
    throw new Error(
      "サーバーから正しい利用者情報を取得できませんでした。"
    );
  }

  return {
    ...response.user,
    uid
  };
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
    throw new Error(
      "このアカウントは利用できません。"
    );
  }

  if (
    !["admin", "teacher", "student"].includes(
      profile.role
    )
  ) {
    throw new Error(
      "アカウントの権限が正しくありません。"
    );
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
    throw new Error(
      "端末セッションが登録されていません。再度ログインしてください。"
    );
  }

  const result = await apiFetch(
    "/api/sessions/heartbeat",
    {
      method: "POST",
      body: JSON.stringify({
        sessionId
      })
    }
  );

  if (!result.success) {
    throw new Error(
      result.error ||
      "端末セッションを確認できません。"
    );
  }

  startSessionHeartbeat();

  return true;
}

/* ========================================
   メンテナンス判定

   メンテナンス中はログアウトせず、
   専用画面へ移動する。
======================================== */

async function checkMaintenanceAccess(role) {
  const result = await apiFetch(
    "/api/system/access",
    {
      method: "GET"
    }
  );

  if (
    result.role &&
    result.role !== role
  ) {
    throw new Error(
      "サーバーの権限情報と利用者情報が一致しません。"
    );
  }

  if (
    result.maintenance === true &&
    role !== "admin"
  ) {
    window.location.replace(
      "/maintenance.html"
    );

    return false;
  }

  return true;
}

/* ========================================
   ロール別アクセス制御
======================================== */

export async function requireRole(expectedRole) {
  try {
    await authPersistenceReady;

    const result =
      await getAuthenticatedProfile();

    if (!result) {
      stopSessionHeartbeat();

      window.location.replace(
        "/login.html"
      );

      return null;
    }

    const { user, profile } = result;

    const allowedRoles = Array.isArray(expectedRole)
      ? expectedRole
      : [expectedRole];

    if (!allowedRoles.includes(profile.role)) {
      const destination =
        getDashboardUrl(profile.role);

      window.location.replace(destination);

      return null;
    }

    // メンテナンス中もセッション確認は実施する。
    await verifyDeviceSession();

    // サーバー側でメンテナンス状態を確認する。
    const allowed =
      await checkMaintenanceAccess(profile.role);

    if (!allowed) {
      return null;
    }

    return {
      user,
      profile
    };

  } catch (error) {
    console.error(
      "[Auth] Access check failed:",
      error
    );

    // メンテナンス応答ではログアウトしない。
    if (
      error.maintenance === true ||
      error.status === 503
    ) {
      window.location.replace(
        "/maintenance.html"
      );

      return null;
    }

    // 401・403は認証または権限の問題として扱う。
    if (
      error.status === 401 ||
      error.status === 403
    ) {
      stopSessionHeartbeat();
      setSessionId("");

      if (auth.currentUser) {
        await signOut(auth).catch(() => {});
      }

      window.location.replace(
        "/login.html?reason=session"
      );

      return null;
    }

    // 通信障害や一時的なエラーでは、
    // 認証情報を勝手に削除しない。
    const message = encodeURIComponent(
      error.message ||
      "認証情報を確認できませんでした。"
    );

    window.location.replace(
      `/login.html?reason=error&message=${message}`
    );

    return null;
  }
}

/* ========================================
   ログアウト
======================================== */

export async function logout() {
  try {
    const sessionId = getSessionId();

    if (
      auth.currentUser &&
      sessionId
    ) {
      await apiFetch(
        "/api/sessions/logout",
        {
          method: "POST",
          body: JSON.stringify({
            sessionId
          })
        }
      ).catch(error => {
        console.warn(
          "サーバー側セッション終了:",
          error
        );
      });
    }

    stopSessionHeartbeat();
    setSessionId("");

    await signOut(auth);

    window.location.replace(
      "/login.html"
    );

  } catch (error) {
    console.error(
      "[Auth] Logout failed:",
      error
    );

    throw new Error(
      "ログアウトに失敗しました。"
    );
  }
}

/* ========================================
   Firebase ID Token
======================================== */

export async function getAccessToken() {
  await authPersistenceReady;

  const user = auth.currentUser;

  if (!user) {
    throw new Error(
      "ログインしてください。"
    );
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
  return onAuthStateChanged(
    auth,
    callback
  );
}

/* ========================================
   Auth互換オブジェクト
======================================== */

export const Auth = {
  getCurrentUser,
  getProfile,
  isActiveProfile,
  getAuthenticatedProfile,
  verifyDeviceSession,
  requireRole,
  logout,
  getAccessToken,
  getDashboardUrl,
  observeAuthState
};

export default Auth;
