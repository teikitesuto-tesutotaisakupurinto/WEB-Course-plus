
"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const admin = require("firebase-admin");
const { AccessToken } = require("livekit-server-sdk");

const app = express();
const PORT = process.env.PORT || 10000;

const MAX_SESSIONS = 4;
const SESSION_DAYS = 30;
const HEARTBEAT_INTERVAL_MS = 60 * 1000;
const STARTED_AT = Date.now();

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// ==========================================
// 1. 基本セキュリティ・リクエスト計測
// ==========================================

const metrics = {
  requests: 0,
  errors: 0,
  apiRequests: 0,
  apiErrors: 0,
  startedAt: new Date().toISOString(),
  recentErrors: []
};

app.use((req, res, next) => {
  const started = Date.now();

  metrics.requests++;
  if (req.path.startsWith("/api/")) metrics.apiRequests++;

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cache-Control", "no-store");

  res.on("finish", () => {
    if (res.statusCode >= 400) {
      metrics.errors++;
      if (req.path.startsWith("/api/")) metrics.apiErrors++;

      metrics.recentErrors.unshift({
        time: new Date().toISOString(),
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: Date.now() - started
      });

      metrics.recentErrors = metrics.recentErrors.slice(0, 100);
    }
  });

  next();
});

// ==========================================
// 2. 環境変数
// ==========================================

const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY;
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET;
const LIVEKIT_URL = process.env.LIVEKIT_URL;
const FIREBASE_SERVICE_ACCOUNT_JSON =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.error("FIREBASE_SERVICE_ACCOUNT_JSON が未設定です。");
  process.exit(1);
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
  if (serviceAccount.private_key) {
    serviceAccount.private_key =
      serviceAccount.private_key.replace(/\\n/g, "\n");
  }
} catch (error) {
  console.error("Firebase JSONの解析に失敗しました。");
  process.exit(1);
}

if (!serviceAccount.project_id || !serviceAccount.private_key) {
  console.error("Firebaseサービスアカウント情報が不足しています。");
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
const Timestamp = admin.firestore.Timestamp;

if (!LIVEKIT_API_KEY || !LIVEKIT_API_SECRET || !LIVEKIT_URL) {
  console.error("LiveKit環境変数が不足しています。");
  process.exit(1);
}

// ==========================================
// 3. 共通関数
// ==========================================

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message
  });
}

function bearerToken(req) {
  const value = req.headers.authorization || "";
  return value.startsWith("Bearer ") ? value.slice(7).trim() : null;
}

function sessionIdFromRequest(req) {
  return String(req.headers["x-session-id"] || "").trim();
}

function isActiveProfile(profile) {
  if (!profile || profile.active === false) return false;

  const status = String(profile.status || "").toLowerCase();
  return !["inactive", "disabled", "suspended", "deleted"].includes(status);
}

function validRole(role) {
  return ["admin", "teacher", "student"].includes(role);
}

function sessionExpiry() {
  return Timestamp.fromDate(
    new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000)
  );
}

function cleanText(value, max = 120) {
  return String(value || "").trim().replace(/[<>]/g, "").slice(0, max);
}

function serializeSession(doc) {
  const data = doc.data();

  return {
    id: doc.id,
    uid: data.uid || "",
    email: data.email || "",
    deviceName: data.deviceName || "不明な端末",
    browser: data.browser || "",
    platform: data.platform || "",
    createdAt: data.createdAt?.toDate?.()?.toISOString() || null,
    lastSeenAt: data.lastSeenAt?.toDate?.()?.toISOString() || null,
    expiresAt: data.expiresAt?.toDate?.()?.toISOString() || null
  };
}

async function writeSystemLog(type, message, details = {}) {
  try {
    await db.collection("systemLogs").add({
      type,
      message: cleanText(message, 500),
      details,
      createdAt: FieldValue.serverTimestamp()
    });
  } catch (error) {
    console.error("システムログ保存失敗:", error.message);
  }
}

async function writeAdminLog(req, action, details = {}) {
  await db.collection("adminLogs").add({
    adminUid: req.user.uid,
    adminEmail: req.user.email || "",
    action,
    details,
    createdAt: FieldValue.serverTimestamp()
  });
}

async function getSystemSettings() {
  const snapshot = await db.collection("settings").doc("system").get();
  return snapshot.exists ? snapshot.data() : {};
}

// ==========================================
// 4. Firestore初期化
// ==========================================

async function initializeFirestore() {
  const ref = db.collection("settings").doc("system");
  const snapshot = await ref.get();

  if (!snapshot.exists) {
    await ref.set({
      maintenance: false,
      maintenanceMessage: "",
      maxSessions: MAX_SESSIONS,
      sessionDays: SESSION_DAYS,
      updatedAt: FieldValue.serverTimestamp(),
      createdAt: FieldValue.serverTimestamp()
    });
  }

  console.log("Firestore system settings initialized.");
}

// ==========================================
// 5. Firebase IDトークン検証
// ==========================================

async function verifyFirebaseToken(req) {
  const token = bearerToken(req);
  if (!token) throw new Error("NO_TOKEN");

  return admin.auth().verifyIdToken(token);
}

// ==========================================
// 6. ログインセッション登録
// Firebaseログイン成功後に呼び出す
// ==========================================

app.post("/api/sessions/register", async (req, res) => {
  try {
    const decoded = await verifyFirebaseToken(req);
    const uid = decoded.uid;

    const userRef = db.collection("users").doc(uid);
    const userSnapshot = await userRef.get();

    if (!userSnapshot.exists) {
      return sendError(res, 403, "ユーザー情報がありません。");
    }

    const profile = userSnapshot.data();

    if (!isActiveProfile(profile) || !validRole(profile.role)) {
      return sendError(res, 403, "このアカウントは利用できません。");
    }

    const deviceName = cleanText(req.body.deviceName, 100) || "不明な端末";
    const browser = cleanText(req.body.browser, 100);
    const platform = cleanText(req.body.platform, 100);

    const sessionRef = db.collection("sessions").doc(crypto.randomUUID());
    const sessionsRef = db.collection("sessions");

    const result = await db.runTransaction(async (transaction) => {
      const query = sessionsRef.where("uid", "==", uid);
      const snapshot = await transaction.get(query);

      const now = Date.now();
      const validSessions = [];

      snapshot.docs.forEach((doc) => {
        const data = doc.data();
        const expiresAt = data.expiresAt?.toDate?.()?.getTime() || 0;

        if (expiresAt > now && data.revoked !== true) {
          validSessions.push(doc);
        } else {
          transaction.delete(doc.ref);
        }
      });

      if (validSessions.length >= MAX_SESSIONS) {
        return { full: true, count: validSessions.length };
      }

      transaction.set(sessionRef, {
        uid,
        email: decoded.email || profile.email || "",
        deviceName,
        browser,
        platform,
        role: profile.role,
        revoked: false,
        createdAt: FieldValue.serverTimestamp(),
        lastSeenAt: FieldValue.serverTimestamp(),
        expiresAt: sessionExpiry()
      });

      return { full: false, count: validSessions.length + 1 };
    });

    if (result.full) {
      await writeSystemLog("session_limit", "同時ログイン上限に到達しました。", {
        uid,
        count: result.count
      });

      return res.status(429).json({
        success: false,
        error: "同時ログインは最大4台までです。",
        sessionLimit: MAX_SESSIONS,
        currentSessions: result.count
      });
    }

    await writeSystemLog("session_created", "ログインセッションを作成しました。", {
      uid,
      sessionId: sessionRef.id
    });

    return res.json({
      success: true,
      sessionId: sessionRef.id,
      sessionLimit: MAX_SESSIONS,
      currentSessions: result.count
    });
  } catch (error) {
    console.error("セッション登録エラー:", error.message);
    return sendError(res, 401, "ログインセッションを作成できませんでした。");
  }
});

// ==========================================
// 7. 認証・セッション確認ミドルウェア
// ==========================================

async function authenticate(req, res, next) {
  try {
    const decoded = await verifyFirebaseToken(req);
    const uid = decoded.uid;

    const userSnapshot = await db.collection("users").doc(uid).get();

    if (!userSnapshot.exists) {
      return sendError(res, 403, "ユーザー情報がありません。");
    }

    const profile = userSnapshot.data();

    if (!isActiveProfile(profile) || !validRole(profile.role)) {
      return sendError(res, 403, "このアカウントは利用できません。");
    }

    const sessionId = sessionIdFromRequest(req);

    if (!sessionId) {
      return sendError(res, 401, "セッション情報がありません。再ログインしてください。");
    }

    const sessionRef = db.collection("sessions").doc(sessionId);
    const sessionSnapshot = await sessionRef.get();

    if (!sessionSnapshot.exists) {
      return sendError(res, 401, "セッションが無効です。再ログインしてください。");
    }

    const session = sessionSnapshot.data();
    const expiresAt = session.expiresAt?.toDate?.()?.getTime() || 0;

    if (
      session.uid !== uid ||
      session.revoked === true ||
      expiresAt <= Date.now()
    ) {
      return sendError(res, 401, "セッションが無効または期限切れです。");
    }

    // 最終アクセス時刻を更新
    const lastSeen = session.lastSeenAt?.toDate?.()?.getTime() || 0;

    if (Date.now() - lastSeen >= HEARTBEAT_INTERVAL_MS) {
      await sessionRef.update({
        lastSeenAt: FieldValue.serverTimestamp(),
        expiresAt: sessionExpiry()
      });
    }

    req.user = {
      uid,
      email: decoded.email || profile.email || "",
      profile,
      sessionId
    };

    return next();
  } catch (error) {
    console.error("認証エラー:", error.message);
    return sendError(res, 401, "認証に失敗しました。再ログインしてください。");
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.profile?.role !== "admin") {
    return sendError(res, 403, "管理者権限が必要です。");
  }
  return next();
}

// ==========================================
// 8. ログアウト
// ==========================================

app.post("/api/sessions/logout", authenticate, async (req, res) => {
  try {
    await db.collection("sessions").doc(req.user.sessionId).delete();

    await writeSystemLog("session_logout", "セッションを終了しました。", {
      uid: req.user.uid,
      sessionId: req.user.sessionId
    });

    return res.json({ success: true, message: "ログアウトしました。" });
  } catch (error) {
    console.error("ログアウトエラー:", error);
    return sendError(res, 500, "ログアウト処理に失敗しました。");
  }
});

// ==========================================
// 9. セッション確認API
// ==========================================

app.get("/api/sessions/current", authenticate, (req, res) => {
  res.json({
    success: true,
    sessionId: req.user.sessionId,
    sessionLimit: MAX_SESSIONS
  });
});

// ==========================================
// 10. ヘルスチェック
// ==========================================

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "WEB Course-plus",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
    timestamp: new Date().toISOString()
  });
});

// ==========================================
// 11. メンテナンス状態
// ==========================================

app.get("/api/system/status", async (req, res) => {
  try {
    const settings = await getSystemSettings();

    res.json({
      success: true,
      maintenance: settings.maintenance === true,
      maintenanceMessage: settings.maintenanceMessage || ""
    });
  } catch (error) {
    return sendError(res, 500, "システム状態を取得できませんでした。");
  }
});

// ==========================================
// 12. ログインユーザー情報
// ==========================================

app.get("/api/me", authenticate, (req, res) => {
  res.json({
    success: true,
    user: {
      uid: req.user.uid,
      email: req.user.email,
      role: req.user.profile.role,
      displayName: req.user.profile.displayName || ""
    }
  });
});

// ==========================================
// 13. 管理者ダッシュボード概要
// ==========================================

app.get("/api/admin/overview", authenticate, requireAdmin, async (req, res) => {
  try {
    const sessionsSnapshot = await db.collection("sessions").get();
    const now = Date.now();

    let activeSessions = 0;

    sessionsSnapshot.forEach((doc) => {
      const data = doc.data();
      const expiry = data.expiresAt?.toDate?.()?.getTime() || 0;
      if (data.revoked !== true && expiry > now) activeSessions++;
    });

    const settings = await getSystemSettings();

    res.json({
      success: true,
      system: {
        uptimeSeconds: Math.floor((Date.now() - STARTED_AT) / 1000),
        nodeVersion: process.version,
        platform: process.platform,
        memory: process.memoryUsage(),
        totalMemory: os.totalmem(),
        freeMemory: os.freemem(),
        cpuCount: os.cpus().length,
        serverTime: new Date().toISOString()
      },
      metrics: {
        ...metrics,
        activeSessions
      },
      settings: {
        maintenance: settings.maintenance === true
      }
    });
  } catch (error) {
    console.error("概要取得エラー:", error);
    return sendError(res, 500, "概要を取得できませんでした。");
  }
});

// ==========================================
// 14. 管理者：セッション一覧
// ==========================================

app.get("/api/admin/sessions", authenticate, requireAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection("sessions").get();
    const now = Date.now();

    const sessions = snapshot.docs
      .map(serializeSession)
      .filter((session) => !session.expiresAt || new Date(session.expiresAt).getTime() > now);

    res.json({
      success: true,
      sessions,
      count: sessions.length,
      limitPerAccount: MAX_SESSIONS
    });
  } catch (error) {
    console.error("セッション一覧エラー:", error);
    return sendError(res, 500, "セッション一覧を取得できませんでした。");
  }
});

// ==========================================
// 15. 管理者：個別セッション削除
// ==========================================

app.delete("/api/admin/sessions/:sessionId", authenticate, requireAdmin, async (req, res) => {
  try {
    const id = cleanText(req.params.sessionId, 150);
    if (!id) return sendError(res, 400, "セッションIDが不正です。");

    const ref = db.collection("sessions").doc(id);
    const snapshot = await ref.get();

    if (!snapshot.exists) {
      return sendError(res, 404, "セッションが見つかりません。");
    }

    const data = snapshot.data();
    await ref.delete();

    await writeAdminLog(req, "session_deleted", {
      sessionId: id,
      targetUid: data.uid || ""
    });

    await writeSystemLog("session_revoked", "管理者がセッションを削除しました。", {
      sessionId: id,
      targetUid: data.uid || ""
    });

    res.json({ success: true, message: "セッションを削除しました。" });
  } catch (error) {
    console.error("セッション削除エラー:", error);
    return sendError(res, 500, "セッションを削除できませんでした。");
  }
});

// ==========================================
// 16. 管理者：アカウント単位の全セッション削除
// ==========================================

app.delete("/api/admin/sessions/user/:uid", authenticate, requireAdmin, async (req, res) => {
  try {
    const uid = cleanText(req.params.uid, 128);
    if (!uid) return sendError(res, 400, "アカウントIDが不正です。");

    const snapshot = await db.collection("sessions")
      .where("uid", "==", uid)
      .get();

    const batch = db.batch();
    snapshot.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    await writeAdminLog(req, "all_user_sessions_deleted", {
      targetUid: uid,
      deletedCount: snapshot.size
    });

    res.json({
      success: true,
      deletedCount: snapshot.size
    });
  } catch (error) {
    console.error("全セッション削除エラー:", error);
    return sendError(res, 500, "セッションを削除できませんでした。");
  }
});

// ==========================================
// 17. 管理者：メンテナンス設定取得
// ==========================================

app.get("/api/admin/settings", authenticate, requireAdmin, async (req, res) => {
  try {
    const settings = await getSystemSettings();

    res.json({
      success: true,
      settings: {
        maintenance: settings.maintenance === true,
        maintenanceMessage: settings.maintenanceMessage || "",
        maxSessions: MAX_SESSIONS,
        sessionDays: SESSION_DAYS
      }
    });
  } catch (error) {
    return sendError(res, 500, "設定を取得できませんでした。");
  }
});

// ==========================================
// 18. 管理者：メンテナンス設定変更
// ==========================================

app.patch("/api/admin/settings", authenticate, requireAdmin, async (req, res) => {
  try {
    const updates = {};

    if (typeof req.body.maintenance === "boolean") {
      updates.maintenance = req.body.maintenance;
    }

    if (typeof req.body.maintenanceMessage === "string") {
      updates.maintenanceMessage = req.body.maintenanceMessage.slice(0, 1000);
    }

    if (!Object.keys(updates).length) {
      return sendError(res, 400, "変更する設定がありません。");
    }

    updates.updatedAt = FieldValue.serverTimestamp();

    await db.collection("settings").doc("system").set(updates, { merge: true });

    await writeAdminLog(req, "system_settings_updated", {
      maintenance: updates.maintenance,
      maintenanceMessageChanged: updates.maintenanceMessage !== undefined
    });

    res.json({ success: true });
  } catch (error) {
    console.error("設定更新エラー:", error);
    return sendError(res, 500, "設定を更新できませんでした。");
  }
});

// ==========================================
// 19. 管理者：サーバー情報
// ==========================================

app.get("/api/admin/server", authenticate, requireAdmin, (req, res) => {
  res.json({
    success: true,
    server: {
      uptimeSeconds: Math.floor((Date.now() - STARTED_AT) / 1000),
      nodeVersion: process.version,
      platform: process.platform,
      architecture: process.arch,
      hostname: os.hostname(),
      cpuCount: os.cpus().length,
      loadAverage: os.loadavg(),
      totalMemory: os.totalmem(),
      freeMemory: os.freemem(),
      processMemory: process.memoryUsage(),
      pid: process.pid,
      port: PORT
    }
  });
});

// ==========================================
// 20. 管理者：Firebase接続確認
// ==========================================

app.get("/api/admin/firebase", authenticate, requireAdmin, async (req, res) => {
  const started = Date.now();

  try {
    await db.collection("settings").doc("system").get();

    res.json({
      success: true,
      firebase: {
        status: "connected",
        projectId: serviceAccount.project_id,
        firestore: "connected",
        authentication: "admin-sdk-initialized",
        responseTimeMs: Date.now() - started
      }
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      firebase: {
        status: "error",
        message: "Firebaseへの接続に失敗しました。",
        responseTimeMs: Date.now() - started
      }
    });
  }
});

// ==========================================
// 21. 管理者：LiveKit設定確認
// ==========================================

app.get("/api/admin/livekit", authenticate, requireAdmin, async (req, res) => {
  res.json({
    success: true,
    livekit: {
      configured: Boolean(LIVEKIT_API_KEY && LIVEKIT_API_SECRET && LIVEKIT_URL),
      serverUrl: LIVEKIT_URL,
      apiKeyConfigured: Boolean(LIVEKIT_API_KEY),
      apiSecretConfigured: Boolean(LIVEKIT_API_SECRET)
    }
  });
});

// ==========================================
// 22. 管理者：システムログ
// ==========================================

app.get("/api/admin/logs", authenticate, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 300);
    const snapshot = await db.collection("systemLogs")
      .orderBy("createdAt", "desc")
      .limit(limit)
      .get();

    const logs = snapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        id: doc.id,
        type: data.type || "",
        message: data.message || "",
        details: data.details || {},
        createdAt: data.createdAt?.toDate?.()?.toISOString() || null
      };
    });

    res.json({ success: true, logs });
  } catch (error) {
    console.error("システムログ取得エラー:", error);
    return sendError(res, 500, "システムログを取得できませんでした。");
  }
});

// ==========================================
// 23. 管理者：管理操作ログ
// ==========================================

app.get("/api/admin/audit-logs", authenticate, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 300);
    const snapshot = await db.collection("adminLogs")
      .orderBy("createdAt", "desc")
      .limit(limit)
      .get();

    const logs = snapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        id: doc.id,
        adminEmail: data.adminEmail || "",
        action: data.action || "",
        details: data.details || {},
        createdAt: data.createdAt?.toDate?.()?.toISOString() || null
      };
    });

    res.json({ success: true, logs });
  } catch (error) {
    return sendError(res, 500, "管理操作ログを取得できませんでした。");
  }
});

// ==========================================
// 24. 管理者：セキュリティ状況
// ==========================================

app.get("/api/admin/security", authenticate, requireAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection("systemLogs")
      .where("type", "in", ["session_limit", "session_revoked", "auth_failure"])
      .limit(200)
      .get();

    const events = snapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        id: doc.id,
        type: data.type,
        message: data.message,
        details: data.details || {},
        createdAt: data.createdAt?.toDate?.()?.toISOString() || null
      };
    });

    res.json({
      success: true,
      sessionLimit: MAX_SESSIONS,
      events
    });
  } catch (error) {
    return sendError(res, 500, "セキュリティ情報を取得できませんでした。");
  }
});

// ==========================================
// 25. 管理者：通知一覧
// ==========================================

app.get("/api/admin/notifications", authenticate, requireAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection("systemLogs")
      .where("type", "in", ["error", "service_warning", "service_recovered"])
      .limit(100)
      .get();

    const notifications = snapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        id: doc.id,
        type: data.type,
        message: data.message,
        createdAt: data.createdAt?.toDate?.()?.toISOString() || null
      };
    });

    res.json({ success: true, notifications });
  } catch (error) {
    return sendError(res, 500, "通知を取得できませんでした。");
  }
});

// ==========================================
// 26. 管理者：APIメトリクス
// ==========================================

app.get("/api/admin/metrics", authenticate, requireAdmin, (req, res) => {
  res.json({
    success: true,
    metrics: {
      ...metrics,
      uptimeSeconds: Math.floor((Date.now() - STARTED_AT) / 1000),
      memory: process.memoryUsage()
    }
  });
});

// ==========================================
// 27. 日時変換・授業時間判定
// ==========================================

function toDate(value) {
  if (!value) return null;
  if (value instanceof Date) return value;
  if (typeof value.toDate === "function") return value.toDate();
  if (typeof value === "number") return new Date(value);
  if (typeof value === "string") {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  return null;
}

function getLessonStart(lesson) {
  const direct =
    toDate(lesson.startAt) ||
    toDate(lesson.startsAt) ||
    toDate(lesson.scheduledAt) ||
    toDate(lesson.startDateTime);

  if (direct) return direct;

  if (lesson.date && lesson.startTime) {
    const date = String(lesson.date).slice(0, 10);
    const time = String(lesson.startTime).slice(0, 5);
    const parsed = new Date(`${date}T${time}:00+09:00`);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }

  return null;
}

function getLessonEnd(lesson, start) {
  const direct =
    toDate(lesson.endAt) ||
    toDate(lesson.endsAt) ||
    toDate(lesson.endDateTime);

  if (direct) return direct;

  if (lesson.date && lesson.endTime) {
    const date = String(lesson.date).slice(0, 10);
    const time = String(lesson.endTime).slice(0, 5);
    const parsed = new Date(`${date}T${time}:00+09:00`);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }

  if (start && Number(lesson.durationMinutes) > 0) {
    return new Date(start.getTime() + Number(lesson.durationMinutes) * 60000);
  }

  return null;
}

// ==========================================
// 28. LiveKit授業参加トークン
// ==========================================

app.post("/api/livekit/token", authenticate, async (req, res) => {
  try {
    const profile = req.user.profile;
    const uid = req.user.uid;

    if (profile.role === "admin") {
      return sendError(res, 403, "システム管理者は授業に参加できません。");
    }

    const lessonId = cleanText(req.body.lessonId, 150);
    if (!lessonId) return sendError(res, 400, "授業IDが必要です。");

    const lessonSnapshot = await db.collection("lessons").doc(lessonId).get();

    if (!lessonSnapshot.exists) {
      return sendError(res, 404, "授業が見つかりません。");
    }

    const lesson = lessonSnapshot.data();

    const isTeacher = profile.role === "teacher";
    const isStudent = profile.role === "student" && lesson.studentId === uid;

    if (!isTeacher && !isStudent) {
      return sendError(res, 403, "この授業に参加する権限がありません。");
    }

    if (!["scheduled", "in_progress"].includes(lesson.status)) {
      return sendError(res, 403, "現在この授業には入室できません。");
    }

    const start = getLessonStart(lesson);
    const end = getLessonEnd(lesson, start);
    const now = Date.now();

    if (start && now < start.getTime() - 5 * 60 * 1000) {
      return sendError(res, 403, "授業開始5分前から入室できます。");
    }

    if (end && now > end.getTime() + 30 * 60 * 1000) {
      return sendError(res, 403, "この授業の入室可能時間は終了しました。");
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
        ttl: "2h"
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
    return sendError(res, 500, "授業室への接続準備に失敗しました。");
  }
});

// ==========================================
// 29. 静的ファイル
// ==========================================

const publicDirectory = path.join(__dirname, "public");

if (fs.existsSync(publicDirectory)) {
  app.use(express.static(publicDirectory, {
    index: false,
    extensions: ["html"],
    maxAge: "1h"
  }));

  app.get("/", (req, res) => {
    const loginPath = path.join(publicDirectory, "login.html");
    const indexPath = path.join(publicDirectory, "index.html");

    if (fs.existsSync(loginPath)) return res.sendFile(loginPath);
    if (fs.existsSync(indexPath)) return res.sendFile(indexPath);

    return res.status(404).send("WEB Course-plus");
  });
}

// ==========================================
// 30. 404・エラー処理
// ==========================================

app.use("/api", (req, res) => {
  sendError(res, 404, "指定されたAPIは存在しません。");
});

app.use((req, res) => {
  res.status(404).send("ページが見つかりません。");
});

app.use((error, req, res, next) => {
  console.error("サーバーエラー:", error);

  if (res.headersSent) return next(error);

  return sendError(res, 500, "サーバー内部でエラーが発生しました。");
});

// ==========================================
// 31. 起動
// ==========================================

async function startServer() {
  try {
    await initializeFirestore();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("WEB Course-plus server started.");
      console.log(`Port: ${PORT}`);
      console.log("Session limit: 4");
      console.log("Admin system: enabled");
      console.log("User management API: removed");
      console.log("Health endpoint: /health");
    });
  } catch (error) {
    console.error("サーバー起動失敗:", error);
    process.exit(1);
  }
}

startServer();
