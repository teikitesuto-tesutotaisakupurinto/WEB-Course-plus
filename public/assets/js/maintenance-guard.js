import { auth, db, authPersistenceReady } from "/assets/js/firebase.js";

import {
  onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

const SESSION_KEY = "web-course-plus-device-session";

let started = false;

function getSessionId() {
  let id = localStorage.getItem(SESSION_KEY);

  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(SESSION_KEY, id);
  }

  return id;
}

async function getSystemStatus() {
  const response = await fetch("/api/system/status", {
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error("システム状態を確認できません。");
  }

  return response.json();
}

async function sendHeartbeat(user) {
  const response = await fetch("/api/sessions/heartbeat", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${await user.getIdToken()}`,
      "X-Session-Id": getSessionId()
    },
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error("端末セッションを確認できません。");
  }
}

function showError(message) {
  document.body.innerHTML = `
    <main style="
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      padding:24px;
      background:#f4f7fb;
      font-family:Inter,'Noto Sans JP',sans-serif;
    ">
      <section style="
        width:100%;
        max-width:460px;
        padding:32px;
        background:white;
        border:1px solid #dfe6ef;
        border-radius:12px;
        text-align:center;
      ">
        <h1 style="font-size:20px;color:#14263f;">
          ページを確認できません
        </h1>
        <p style="color:#64748b;line-height:1.8;">
          ${message}
        </p>
        <button
          onclick="location.reload()"
          style="
            padding:10px 20px;
            border:0;
            border-radius:6px;
            background:#2563eb;
            color:white;
            cursor:pointer;
          "
        >
          再試行
        </button>
      </section>
    </main>
  `;
}

async function checkUser(user) {
  const snapshot = await getDoc(doc(db, "users", user.uid));

  if (!snapshot.exists()) {
    throw new Error("ユーザー情報が登録されていません。");
  }

  const profile = snapshot.data();

  if (
    profile.active === false ||
    ["inactive", "disabled", "suspended", "deleted"]
      .includes(String(profile.status || "").toLowerCase())
  ) {
    throw new Error("このアカウントは利用停止中です。");
  }

  const path = location.pathname;

  const isStudentPage = path.startsWith("/student/");
  const isTeacherPage = path.startsWith("/teacher/");

  if (isStudentPage && profile.role !== "student") {
    location.replace("/login.html");
    return;
  }

  if (isTeacherPage && profile.role !== "teacher") {
    location.replace("/login.html");
    return;
  }

  if (!["student", "teacher"].includes(profile.role)) {
    location.replace("/login.html");
    return;
  }

  const status = await getSystemStatus();

  if (
    status.maintenance === true ||
    status.maintenanceMode === true
  ) {
    location.replace("/maintenance.html");
    return;
  }

  await sendHeartbeat(user);
}

async function startMaintenanceGuard() {
  if (started) return;
  started = true;

  try {
    await authPersistenceReady;

    onAuthStateChanged(auth, async user => {
      if (!user) {
        location.replace("/login.html");
        return;
      }

      try {
        await checkUser(user);
      } catch (error) {
        console.error("[Maintenance Guard]", error);
        showError(error.message || "認証情報を確認できません。");
      }
    });
  } catch (error) {
    console.error(error);
    showError("認証システムを初期化できませんでした。");
  }
}

startMaintenanceGuard();
