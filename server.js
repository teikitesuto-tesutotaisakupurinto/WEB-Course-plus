"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const admin = require("firebase-admin");
const {
  AccessToken,
  RoomServiceClient
} = require("livekit-server-sdk");

const app = express();
const PORT = process.env.PORT || 10000;
const MAX_SESSIONS = 4;
const SESSION_STALE_MS = 2 * 60 * 1000;
const SECURITY_EVENT_WINDOW_MS = 60 * 1000;
const SECURITY_EVENT_MAX_PER_WINDOW = 12;
const securityEventAttempts = new Map();

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cache-Control", "no-store");
  next();
});

const SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY;
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET;
const LIVEKIT_URL = process.env.LIVEKIT_URL;

if (!SERVICE_ACCOUNT_JSON) {
  console.error("FIREBASE_SERVICE_ACCOUNT_JSON が未設定です。");
  process.exit(1);
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(SERVICE_ACCOUNT_JSON);
  if (serviceAccount.private_key) {
    serviceAccount.private_key =
      serviceAccount.private_key.replace(/\\n/g, "\n");
  }
} catch (error) {
  console.error("FirebaseサービスアカウントJSONが不正です。");
  process.exit(1);
}

if (!serviceAccount.project_id || !serviceAccount.private_key) {
  console.error("Firebaseサービスアカウント情報が不足しています。");
  process.exit(1);
}

if (!LIVEKIT_API_KEY || !LIVEKIT_API_SECRET || !LIVEKIT_URL) {
  console.error("LiveKit環境変数が不足しています。");
  process.exit(1);
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: serviceAccount.project_id
  });
}

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;
const livekitHost = LIVEKIT_URL.replace(/^wss:/, "https:")
  .replace(/^ws:/, "http:");
const roomService = new RoomServiceClient(
  livekitHost,
  LIVEKIT_API_KEY,
  LIVEKIT_API_SECRET
);

function sendError(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

function bearer(req) {
  const value = req.headers.authorization || "";
  return value.startsWith("Bearer ") ? value.slice(7).trim() : null;
}

function activeProfile(profile) {
  if (!profile || profile.active === false) return false;
  return !["inactive", "disabled", "suspended", "deleted"]
    .includes(String(profile.status || "").toLowerCase());
}

function validRole(role) {
  return ["admin", "teacher", "student"].includes(role);
}

function sessionCollection(uid) {
  return db.collection("users").doc(uid).collection("sessions");
}

function sessionIdFrom(req) {
  return String(
    req.headers["x-session-id"] ||
    req.body?.sessionId ||
    ""
  ).trim();
}

function validSessionId(value) {
  return /^[A-Za-z0-9_-]{16,100}$/.test(value);
}

async function authenticate(req, res, next) {
  try {
    const token = bearer(req);
    if (!token) return sendError(res, 401, "ログインが必要です。");

    const decoded = await admin.auth().verifyIdToken(token);
    const snapshot = await db.collection("users").doc(decoded.uid).get();

    if (!snapshot.exists) {
      return sendError(res, 403, "ユーザー情報が登録されていません。");
    }

    const profile = snapshot.data();

    if (!activeProfile(profile)) {
      return sendError(res, 403, "このアカウントは利用停止中です。");
    }

    if (!validRole(profile.role)) {
      return sendError(res, 403, "ユーザー権限が正しくありません。");
    }

    req.user = {
      uid: decoded.uid,
      email: decoded.email || profile.email || null,
      profile
    };

    next();
  } catch (error) {
    console.error("認証エラー:", error.message);
    return sendError(res, 401, "認証に失敗しました。再度ログインしてください。");
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.profile?.role !== "admin") {
    return sendError(res, 403, "管理者権限が必要です。");
  }
  next();
}

/*
 * Firebase認証のみ必要な処理。
 * セッション登録・ログアウトでは既存セッションを要求しない。
 */
async function requireSession(req, res, next) {
  try {
    const sid = sessionIdFrom(req);
    if (!validSessionId(sid)) {
      return sendError(res, 401, "端末セッションIDが不正です。");
    }

    const ref = sessionCollection(req.user.uid).doc(sid);
    const snap = await ref.get();

    if (!snap.exists) {
      return sendError(res, 401, "端末セッションが登録されていません。");
    }

    const data = snap.data();
    const lastSeen = data.lastSeenAt?.toDate
      ? data.lastSeenAt.toDate().getTime()
      : 0;

    if (
      data.active !== true ||
      data.revoked === true ||
      Date.now() - lastSeen > SESSION_STALE_MS
    ) {
      return sendError(res, 401, "端末セッションが無効です。");
    }

    req.sessionId = sid;
    req.sessionRef = ref;
    next();
  } catch (error) {
    console.error("セッション確認エラー:", error);
    return sendError(res, 500, "端末セッションを確認できませんでした。");
  }
}

function requireAdminSession(req, res, next) {
  if (req.user.profile.role !== "admin") {
    return sendError(res, 403, "管理者権限が必要です。");
  }
  next();
}

async function writeLog(uid, email, action, target = "", details = "") {
  await db.collection("adminLogs").add({
    adminUid: uid,
    adminEmail: email || "",
    action,
    target,
    details,
    createdAt: FieldValue.serverTimestamp()
  });
}

async function writeSecurityEvent(type, label, uid = "", email = "", details = "") {
  await db.collection("securityEvents").add({
    type,
    label,
    uid,
    email,
    details: String(details || "").slice(0, 1000),
    createdAt: FieldValue.serverTimestamp()
  });
}

function getRequestAddress(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")
    .split(",")[0].trim().slice(0, 100);
}

async function getSystemSettings() {
  const ref = db.collection("settings").doc("system");
  const snap = await ref.get();

  if (!snap.exists) {
    const initial = {
      maintenance: false,
      maintenanceMessage: "",
      maxSessionsPerUser: MAX_SESSIONS,
      maintenanceSchedule: { enabled: false },
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    };
    await ref.set(initial);
    return {
      maintenance: false,
      maintenanceMessage: "",
      maxSessionsPerUser: MAX_SESSIONS,
      maintenanceSchedule: { enabled: false }
    };
  }

  return snap.data();
}

async function cleanStaleSessions(uid) {
  const ref = sessionCollection(uid);
  const snapshot = await ref.where("active", "==", true).get();
  const cutoff = Date.now() - SESSION_STALE_MS;
  const batch = db.batch();

  for (const docSnap of snapshot.docs) {
    const data = docSnap.data();
    const lastSeen = data.lastSeenAt?.toDate
      ? data.lastSeenAt.toDate().getTime()
      : 0;

    if (lastSeen < cutoff) {
      batch.update(docSnap.ref, {
        active: false,
        inactiveReason: "stale",
        updatedAt: FieldValue.serverTimestamp()
      });
    }
  }

  if (!snapshot.empty) await batch.commit();
}

async function initializeFirestore() {
  await getSystemSettings();
  console.log("Firestore settings/system initialized");
}
/* ヘルスチェック */

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "WEB Course-plus",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.json({ success: true, status: "ok" });
});

/* ログイン前のメンテナンス状態確認 */

app.get("/api/system/status", async (req, res) => {
  try {
    const settings = await getSystemSettings();

    res.json({
      success: true,
      maintenance: settings.maintenance === true,
      maintenanceMessage: settings.maintenanceMessage || ""
    });
  } catch (error) {
    console.error(error);
    sendError(res, 500, "システム状態を取得できませんでした。");
  }
});

/*
 * セッション登録
 * メンテナンス中でもログイン・セッション登録を許可する。
 * メンテナンス画面への切り替えはログイン後の画面側で行う。
 */

app.post("/api/sessions/register", authenticate, async (req, res) => {
  try {
    const sid = sessionIdFrom(req);

    if (!validSessionId(sid)) {
      return sendError(res, 400, "端末セッションIDが不正です。");
    }

    const uid = req.user.uid;
    const ref = sessionCollection(uid);
    const ownRef = ref.doc(sid);

    await cleanStaleSessions(uid);

    const result = await db.runTransaction(async transaction => {
      const ownSnap = await transaction.get(ownRef);
      const allSnap = await transaction.get(
        ref.where("active", "==", true)
      );

      const activeOthers = allSnap.docs.filter(docSnap => {
        if (docSnap.id === sid) return false;
        return docSnap.data().revoked !== true;
      });

      if (!ownSnap.exists && activeOthers.length >= MAX_SESSIONS) {
        return { allowed: false, count: activeOthers.length };
      }

      transaction.set(ownRef, {
        uid,
        sessionId: sid,
        email: req.user.email || "",
        displayName: req.user.profile.displayName || "",
        role: req.user.profile.role,
        active: true,
        revoked: false,
        userAgent: String(req.headers["user-agent"] || "").slice(0, 300),
        lastSeenAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
        createdAt: ownSnap.exists
          ? ownSnap.data().createdAt || FieldValue.serverTimestamp()
          : FieldValue.serverTimestamp()
      }, { merge: true });

      return { allowed: true, count: activeOthers.length + 1 };
    });

    if (!result.allowed) {
      await writeSecurityEvent(
        "session_limit",
        "同時ログイン端末数の上限超過",
        req.user.uid,
        req.user.email,
        `有効端末数=${result.count} / 上限=${MAX_SESSIONS}`
      );

      return res.status(409).json({
        success: false,
        error: `同時ログインできる端末は${MAX_SESSIONS}台までです。`,
        activeSessions: result.count,
        maxSessionsPerUser: MAX_SESSIONS
      });
    }

    res.json({
      success: true,
      sessionId: sid,
      activeSessions: result.count,
      maxSessionsPerUser: MAX_SESSIONS
    });
  } catch (error) {
    console.error("セッション登録エラー:", error);
    sendError(res, 500, "端末セッションを登録できませんでした。");
  }
});

/* セッション生存確認 */

app.post(
  "/api/sessions/heartbeat",
  authenticate,
  requireSession,
  async (req, res) => {
    try {
      await req.sessionRef.update({
        lastSeenAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      });

      res.json({ success: true });
    } catch (error) {
      console.error(error);
      sendError(res, 500, "セッション確認に失敗しました。");
    }
  }
);

/* ログアウト */

app.post("/api/sessions/logout", authenticate, async (req, res) => {
  try {
    const sid = sessionIdFrom(req);

    if (!validSessionId(sid)) {
      return sendError(res, 400, "端末セッションIDが不正です。");
    }

    await sessionCollection(req.user.uid).doc(sid).set({
      active: false,
      revoked: false,
      inactiveReason: "logout",
      updatedAt: FieldValue.serverTimestamp()
    }, { merge: true });

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    sendError(res, 500, "ログアウト処理に失敗しました。");
  }
});

/* 以下、ログイン済みかつ有効な端末だけが利用可能 */

app.get("/api/me", authenticate, requireSession, (req, res) => {
  res.json({
    success: true,
    user: {
      uid: req.user.uid,
      email: req.user.email,
      role: req.user.profile.role,
      displayName: req.user.profile.displayName || "",
      status: req.user.profile.status || "active"
    }
  });
});

/* 管理者：概要 */

app.get(
  "/api/admin/overview",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      const users = await db.collection("users").get();
      let activeSessions = 0;

      for (const userDoc of users.docs) {
        const sessions = await sessionCollection(userDoc.id)
          .where("active", "==", true).get();

        activeSessions += sessions.docs.filter(d => {
          const s = d.data();
          const last = s.lastSeenAt?.toDate
            ? s.lastSeenAt.toDate().getTime() : 0;

          return s.revoked !== true &&
            Date.now() - last <= SESSION_STALE_MS;
        }).length;
      }

      const settings = await getSystemSettings();

      const [studentSnap, teacherSnap, lessonSnap] = await Promise.all([
        db.collection("users").where("role", "==", "student").get(),
        db.collection("users").where("role", "==", "teacher").get(),
        db.collection("lessons").get()
      ]);

      const students = studentSnap.docs.filter(d => activeProfile(d.data())).length;
      const teachers = teacherSnap.docs.filter(d => activeProfile(d.data())).length;

      res.json({
        success: true,
        statistics: {
          students,
          teachers,
          lessons: lessonSnap.size
        },
        overview: {
          activeSessions,
          maxSessionsPerUser: MAX_SESSIONS,
          serverStatus: "ok",
          maintenance: settings.maintenance === true
        }
      });
    } catch (error) {
      console.error(error);
      sendError(res, 500, "概要情報を取得できませんでした。");
    }
  }
);

/* 管理者：セッション一覧 */

app.get(
  "/api/admin/sessions",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      const users = await db.collection("users").get();
      const sessions = [];

      for (const userDoc of users.docs) {
        const profile = userDoc.data();
        const snap = await sessionCollection(userDoc.id).get();

        for (const sessionDoc of snap.docs) {
          const s = sessionDoc.data();

          sessions.push({
            uid: userDoc.id,
            userId: userDoc.id,
            email: s.email || profile.email || "",
            displayName: s.displayName || profile.displayName || "",
            role: s.role || profile.role || "",
            sessionId: sessionDoc.id,
            active: s.active === true,
            revoked: s.revoked === true,
            lastSeen: s.lastSeenAt?.toDate
              ? s.lastSeenAt.toDate().toISOString() : null,
            createdAt: s.createdAt?.toDate
              ? s.createdAt.toDate().toISOString() : null
          });
        }
      }

      sessions.sort((a, b) =>
        String(b.lastSeen || "").localeCompare(String(a.lastSeen || ""))
      );

      res.json({ success: true, sessions });
    } catch (error) {
      console.error(error);
      sendError(res, 500, "セッション一覧を取得できませんでした。");
    }
  }
);

/* 管理者：特定端末の強制解除 */

app.delete(
  "/api/admin/sessions/:uid/:sessionId",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      const { uid, sessionId } = req.params;

      if (!uid || !validSessionId(sessionId)) {
        return sendError(res, 400, "指定内容が不正です。");
      }

      const ref = sessionCollection(uid).doc(sessionId);
      const snap = await ref.get();

      if (!snap.exists) {
        return sendError(res, 404, "セッションが見つかりません。");
      }

      await ref.set({
        active: false,
        revoked: true,
        inactiveReason: "admin_revoked",
        revokedBy: req.user.uid,
        revokedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      }, { merge: true });

      await writeLog(
        req.user.uid,
        req.user.email,
        "session_revoked",
        uid,
        `sessionId=${sessionId}`
      );

      await writeSecurityEvent(
        "session_revoked",
        "管理者による端末の強制ログアウト",
        uid,
        snap.data().email || "",
        `解除実行者=${req.user.email || req.user.uid}`
      );

      try {
        const session = snap.data();

        if (session.role !== "admin") {
          const rooms = await roomService.listRooms();

          for (const room of rooms) {
            const participants = await roomService.listParticipants(room.name);

            if (participants.some(p => p.identity === uid)) {
              await roomService.removeParticipant(room.name, uid);
            }
          }
        }
      } catch (livekitError) {
        console.warn("LiveKit切断処理:", livekitError.message);
      }

      res.json({ success: true });
    } catch (error) {
      console.error(error);
      sendError(res, 500, "セッションを解除できませんでした。");
    }
  }
);

/* 管理者：設定取得 */

app.get(
  "/api/admin/settings",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      const settings = await getSystemSettings();

      res.json({
        success: true,
        settings: {
          maintenance: settings.maintenance === true,
          maintenanceMessage: settings.maintenanceMessage || "",
          maintenanceSchedule: settings.maintenanceSchedule || { enabled: false },
          maxSessionsPerUser: MAX_SESSIONS
        }
      });
    } catch (error) {
      console.error(error);
      sendError(res, 500, "設定を取得できませんでした。");
    }
  }
);

/* 管理者：設定更新 */

app.patch(
  "/api/admin/settings",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      const updates = {};

      if (typeof req.body.maintenance === "boolean") {
        updates.maintenance = req.body.maintenance;
      }

      if (typeof req.body.maintenanceMessage === "string") {
        updates.maintenanceMessage =
          req.body.maintenanceMessage.slice(0, 1000);
      }

      if (!Object.keys(updates).length) {
        return sendError(res, 400, "変更する設定がありません。");
      }

      updates.updatedAt = FieldValue.serverTimestamp();

      await db.collection("settings").doc("system")
        .set(updates, { merge: true });

      await writeLog(
        req.user.uid,
        req.user.email,
        typeof updates.maintenance === "boolean"
          ? (updates.maintenance ? "maintenance_started" : "maintenance_ended")
          : "settings_updated",
        "settings/system",
        JSON.stringify(updates)
      );

      res.json({ success: true });
    } catch (error) {
      console.error(error);
      sendError(res, 500, "設定を更新できませんでした。");
    }
  }
);
/* 管理者：操作履歴 */

app.get(
  "/api/admin/logs",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
      const snap = await db.collection("adminLogs")
        .orderBy("createdAt", "desc")
        .limit(limit)
        .get();

      const logs = snap.docs.map(d => {
        const x = d.data();
        return {
          id: d.id,
          adminUid: x.adminUid || "",
          adminEmail: x.adminEmail || "",
          action: x.action || "",
          target: x.target || "",
          details: x.details || "",
          createdAt: x.createdAt?.toDate
            ? x.createdAt.toDate().toISOString()
            : null
        };
      });

      res.json({ success: true, logs });
    } catch (error) {
      console.error("操作履歴取得エラー:", error);
      sendError(res, 500, "操作履歴を取得できませんでした。");
    }
  }
);

/* 管理者：メンテナンス予約 */

app.put(
  "/api/admin/maintenance/schedule",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      const startAt = new Date(req.body.startAt);
      const endAt = new Date(req.body.endAt);
      const message = String(req.body.message || "").trim().slice(0, 1000);

      if (
        !Number.isFinite(startAt.getTime()) ||
        !Number.isFinite(endAt.getTime()) ||
        endAt <= startAt
      ) {
        return sendError(res, 400, "日時の指定が正しくありません。");
      }

      if (startAt.getTime() <= Date.now()) {
        return sendError(res, 400, "開始日時は現在より後にしてください。");
      }

      const schedule = {
        enabled: true,
        startAt: startAt.toISOString(),
        endAt: endAt.toISOString(),
        message,
        createdBy: req.user.uid,
        updatedAt: FieldValue.serverTimestamp()
      };

      await db.collection("settings").doc("system")
        .set({ maintenanceSchedule: schedule }, { merge: true });

      await writeLog(
        req.user.uid,
        req.user.email,
        "maintenance_schedule_created",
        "settings/system",
        `${schedule.startAt} ～ ${schedule.endAt}`
      );

      res.json({ success: true, schedule });
    } catch (error) {
      console.error("メンテナンス予約登録エラー:", error);
      sendError(res, 500, "メンテナンス予約を登録できませんでした。");
    }
  }
);

app.delete(
  "/api/admin/maintenance/schedule",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      await db.collection("settings").doc("system").set({
        maintenanceSchedule: {
          enabled: false,
          cancelledBy: req.user.uid,
          cancelledAt: new Date().toISOString()
        },
        updatedAt: FieldValue.serverTimestamp()
      }, { merge: true });

      await writeLog(
        req.user.uid,
        req.user.email,
        "maintenance_schedule_cancelled",
        "settings/system",
        "予約メンテナンスを解除"
      );

      res.json({ success: true });
    } catch (error) {
      console.error("メンテナンス予約解除エラー:", error);
      sendError(res, 500, "予約を解除できませんでした。");
    }
  }
);

/* 管理者：セキュリティイベント */

app.get(
  "/api/admin/security",
  authenticate,
  requireSession,
  requireAdminSession,
  async (req, res) => {
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 30, 1), 200);
      const snap = await db.collection("securityEvents")
        .orderBy("createdAt", "desc")
        .limit(limit)
        .get();

      const events = snap.docs.map(d => {
        const x = d.data();
        return {
          id: d.id,
          type: x.type || "unknown",
          label: x.label || "",
          uid: x.uid || "",
          email: x.email || "",
          details: x.details || "",
          createdAt: x.createdAt?.toDate
            ? x.createdAt.toDate().toISOString()
            : null
        };
      });

      res.json({ success: true, events });
    } catch (error) {
      console.error("セキュリティ履歴取得エラー:", error);
      sendError(res, 500, "セキュリティ履歴を取得できませんでした。");
    }
  }
);

/* 未ログイン状態のログイン失敗記録。送信頻度を制限する。 */

app.post("/api/security/event", async (req, res) => {
  try {
    const now = Date.now();
    const address = getRequestAddress(req);
    const previous = securityEventAttempts.get(address) || [];
    const recent = previous.filter(time => now - time < SECURITY_EVENT_WINDOW_MS);

    if (recent.length >= SECURITY_EVENT_MAX_PER_WINDOW) {
      return sendError(res, 429, "イベント送信回数が上限に達しました。");
    }

    recent.push(now);
    securityEventAttempts.set(address, recent);

    if (String(req.body.type || "") !== "login_failed") {
      return sendError(res, 400, "イベント種別が正しくありません。");
    }

    const email = String(req.body.email || "").trim().slice(0, 254);
    const errorCode = String(req.body.errorCode || "").slice(0, 100);

    await writeSecurityEvent(
      "login_failed",
      "ログイン失敗",
      "",
      email,
      `認証エラーコード=${errorCode}; address=${address}`
    );

    res.json({ success: true });
  } catch (error) {
    console.error("ログイン失敗記録エラー:", error);
    sendError(res, 500, "イベントを記録できませんでした。");
  }
});

/* 予約メンテナンスの自動開始・終了 */

async function processMaintenanceSchedule() {
  const ref = db.collection("settings").doc("system");
  const snap = await ref.get();

  if (!snap.exists) return;

  const settings = snap.data();
  const schedule = settings.maintenanceSchedule;

  if (!schedule || schedule.enabled !== true) return;

  const start = new Date(schedule.startAt);
  const end = new Date(schedule.endAt);

  if (
    !Number.isFinite(start.getTime()) ||
    !Number.isFinite(end.getTime()) ||
    end <= start
  ) {
    return;
  }

  const now = Date.now();
  const shouldBeActive = now >= start.getTime() && now < end.getTime();
  const current = settings.maintenance === true;

  if (shouldBeActive !== current) {
    await ref.set({
      maintenance: shouldBeActive,
      maintenanceMessage: schedule.message || "",
      updatedAt: FieldValue.serverTimestamp()
    }, { merge: true });

    await db.collection("adminLogs").add({
      adminUid: "system",
      adminEmail: "system",
      action: shouldBeActive
        ? "maintenance_schedule_started"
        : "maintenance_schedule_ended",
      target: "settings/system",
      details: shouldBeActive
        ? "予約時刻によりメンテナンスを自動開始"
        : "予約終了時刻によりメンテナンスを自動解除",
      createdAt: FieldValue.serverTimestamp()
    });
  }
}

/* 日時変換 */

function toDate(value) {
  if (!value) return null;
  if (value instanceof Date) return value;
  if (typeof value.toDate === "function") return value.toDate();
  if (typeof value === "number") return new Date(value);

  if (typeof value === "string") {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  return null;
}

function lessonStart(lesson) {
  const direct =
    toDate(lesson.startAt) ||
    toDate(lesson.startsAt) ||
    toDate(lesson.scheduledAt) ||
    toDate(lesson.startDateTime);

  if (direct) return direct;

  if (lesson.date && lesson.startTime) {
    const d = new Date(
      `${String(lesson.date).slice(0, 10)}T${String(lesson.startTime).slice(0, 5)}:00+09:00`
    );

    if (!Number.isNaN(d.getTime())) return d;
  }

  return null;
}

function lessonEnd(lesson, start) {
  const direct =
    toDate(lesson.endAt) ||
    toDate(lesson.endsAt) ||
    toDate(lesson.endDateTime);

  if (direct) return direct;

  if (lesson.date && lesson.endTime) {
    const d = new Date(
      `${String(lesson.date).slice(0, 10)}T${String(lesson.endTime).slice(0, 5)}:00+09:00`
    );

    if (!Number.isNaN(d.getTime())) return d;
  }

  if (start && Number(lesson.durationMinutes) > 0) {
    return new Date(
      start.getTime() + Number(lesson.durationMinutes) * 60000
    );
  }

  return null;
}

/* LiveKitトークン発行：有効セッション必須 */

app.post(
  "/api/livekit/token",
  authenticate,
  requireSession,
  async (req, res) => {
    try {
      const lessonId = String(req.body.lessonId || "").trim();

      if (!lessonId || lessonId.length > 150) {
        return sendError(res, 400, "授業IDが正しくありません。");
      }

      const profile = req.user.profile;
      const uid = req.user.uid;

      if (profile.role === "admin") {
        return sendError(res, 403, "管理者アカウントは授業に参加できません。");
      }

      const lessonSnap = await db.collection("lessons")
        .doc(lessonId)
        .get();

      if (!lessonSnap.exists) {
        return sendError(res, 404, "授業が見つかりません。");
      }

      const lesson = lessonSnap.data();

      const allowed =
        (profile.role === "teacher" && lesson.teacherId === uid) ||
        (profile.role === "student" && lesson.studentId === uid);

      if (!allowed) {
        return sendError(res, 403, "この授業に参加する権限がありません。");
      }

      if (!["scheduled", "in_progress"].includes(lesson.status)) {
        return sendError(res, 403, "現在この授業には入室できません。");
      }

      const start = lessonStart(lesson);
      const end = lessonEnd(lesson, start);
      const now = Date.now();

      if (start && now < start.getTime() - 5 * 60 * 1000) {
        return sendError(res, 403, "授業開始5分前から入室できます。");
      }

      if (end && now > end.getTime() + 30 * 60 * 1000) {
        return sendError(res, 403, "この授業の入室可能時間は終了しました。");
      }

      const settings = await getSystemSettings();

      if (settings.maintenance === true) {
        return sendError(res, 503, "現在メンテナンス中です。");
      }

      const roomName = `lesson-${lessonId}`;
      const displayName =
        profile.displayName ||
        req.user.email ||
        (profile.role === "teacher" ? "先生" : "生徒");

      const token = new AccessToken(
        LIVEKIT_API_KEY,
        LIVEKIT_API_SECRET,
        {
          identity: uid,
          name: displayName,
          metadata: JSON.stringify({
            uid,
            role: profile.role,
            lessonId
          }),
          ttl: "15m"
        }
      );

      token.addGrant({
        roomJoin: true,
        room: roomName,
        canPublish: true,
        canSubscribe: true,
        canPublishData: true
      });

      res.json({
        success: true,
        url: LIVEKIT_URL,
        token: await token.toJwt(),
        roomName,
        identity: uid,
        name: displayName
      });
    } catch (error) {
      console.error("LiveKitトークン発行エラー:", error);
      sendError(res, 500, "授業室への接続準備に失敗しました。");
    }
  }
);

/* 静的ファイル */

const publicDirectory = path.join(__dirname, "public");

if (fs.existsSync(publicDirectory)) {
  app.use(express.static(publicDirectory, {
    index: false,
    extensions: ["html"],
    maxAge: "1h"
  }));

  app.get("/", (req, res) => {
    const login = path.join(publicDirectory, "login.html");

    if (fs.existsSync(login)) return res.sendFile(login);

    res.status(404).send("login.html がありません。");
  });
}

app.use("/api", (req, res) =>
  sendError(res, 404, "指定されたAPIは存在しません。")
);

app.use((req, res) => {
  res.status(404).send("ページが見つかりません。");
});

app.use((error, req, res, next) => {
  console.error("サーバーエラー:", error);

  if (res.headersSent) return next(error);

  sendError(res, 500, "サーバー内部でエラーが発生しました。");
});

async function startServer() {
  try {
    await initializeFirestore();
    await processMaintenanceSchedule();

    setInterval(() => {
      processMaintenanceSchedule().catch(error =>
        console.error("予約メンテナンス処理エラー:", error)
      );
    }, 15000);

    app.listen(PORT, "0.0.0.0", () => {
      console.log("WEB Course-plus server started");
      console.log(`Port: ${PORT}`);
      console.log("Firebase: initialized");
      console.log("Firestore: initialized");
      console.log("LiveKit: configured");
    });
  } catch (error) {
    console.error("サーバー起動失敗:", error);
    process.exit(1);
  }
}

startServer();
