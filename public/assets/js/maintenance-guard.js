import {
  auth,
  db,
  authPersistenceReady
} from "/assets/js/firebase.js";

import {
  onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

const SESSION_KEY = "web-course-plus-device-session";

let started = false;
let checking = false;

function getSessionId() {
  let id = localStorage.getItem(SESSION_KEY);

  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(SESSION_KEY, id);
  }

  return id;
}

async function waitForUser() {
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

async function checkMaintenance(user) {
  if (checking) return;
  checking = true;

  try {
    const profileSnapshot = await getDoc(
      doc(db, "users", user.uid)
    );

    if (!profileSnapshot.exists()) {
      location.replace("/login.html");
      return;
    }

    const profile = profileSnapshot.data();

    if (
      profile.active === false ||
      ["inactive", "disabled", "suspended", "deleted"].includes(
        String(profile.status || "").toLowerCase()
      )
    ) {
      location.replace("/login.html");
      return;
    }

    // 管理者はメンテナンス中でも利用可能
    if (profile.role === "admin") return;

    const response = await fetch("/api/system/status", {
      method: "GET",
      cache: "no-store",
      headers: {
        "Accept": "application/json"
      }
    });

    if (!response.ok) {
      throw new Error("メンテナンス状態を取得できませんでした。");
    }

    const data = await response.json();

    if (data.success !== true) {
      throw new Error("メンテナンス状態を確認できませんでした。");
    }

    if (data.maintenance === true) {
      location.replace("/maintenance.html");
      return;
    }

    // セッションの存在確認と生存確認
    const heartbeat = await fetch("/api/sessions/heartbeat", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${await user.getIdToken()}`,
        "X-Session-Id": getSessionId()
      },
      cache: "no-store"
    });

    if (!heartbeat.ok) {
      location.replace("/login.html");
      return;
    }

  } catch (error) {
    console.error("メンテナンス確認エラー:", error);

    // 状態を確認できない場合は通常画面の利用を止める
    document.body.innerHTML = `
      <main style="
        min-height:100vh;
        display:grid;
        place-items:center;
        padding:24px;
        font-family:system-ui,sans-serif;
        background:#f4f7fb;
        color:#182334;
      ">
        <section style="
          max-width:440px;
          padding:32px;
          background:#fff;
          border:1px solid #dfe6ef;
          border-radius:14px;
          text-align:center;
        ">
          <h1 style="font-size:20px;">システム状態を確認できません</h1>
          <p style="color:#64748b;line-height:1.8;">
            通信状態を確認して、もう一度お試しください。
          </p>
          <button onclick="location.reload()" style="
            padding:11px 20px;
            border:0;
            border-radius:7px;
            background:#2563eb;
            color:#fff;
            cursor:pointer;
          ">再読み込み</button>
        </section>
      </main>
    `;
  } finally {
    checking = false;
  }
}

async function startMaintenanceGuard() {
  if (started) return;
  started = true;

  try {
    const user = await waitForUser();

    if (!user) {
      location.replace("/login.html");
      return;
    }

    await checkMaintenance(user);

  } catch (error) {
    console.error("ログイン状態確認エラー:", error);
    location.replace("/login.html");
  }
}

startMaintenanceGuard();
