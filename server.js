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
const SESSION_TIMEOUT_MS = 2 * 60 * 1000;
const SESSION_COLLECTION = "userSessions";

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cache-Control", "no-store");
  next();
});

// ==========================================
// 1. 環境変数
// ==========================================

const FIREBASE_SERVICE_ACCOUNT_JSON =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY;
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET;
const LIVEKIT_URL = process.env.LIVEKIT_URL;

if (!FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.error("FIREBASE_SERVICE_ACCOUNT_JSON が未設定です。");
  process.exit(1);
}

if (!LIVEKIT_API_KEY || !LIVEKIT_API_SECRET || !LIVEKIT_URL) {
  console.error("LiveKitの環境変数が不足しています。");
  process.exit(1);
}

// ==========================================
// 2. Firebase Admin
// ==========================================

let serviceAccount;

try {
  serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);

  if (serviceAccount.private_key) {
    serviceAccount.private_key =
      serviceAccount.private_key.replace(/\\n/g, "\n");
  }
} catch (error) {
  console.error("Firebase JSON解析エラー:", error.message);
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

// ==========================================
// 3. LiveKit Room Service
// ==========================================

const livekitHost = LIVEKIT_URL
  .replace(/^wss:/, "https:")
  .replace(/^ws:/, "http:");

const roomService = new RoomServiceClient(
  livekitHost,
  LIVEKIT_API_KEY,
  LIVEKIT_API_SECRET
);

// ==========================================
// 4. 共通関数
// ==========================================

function sendError(res, status, message, code) {
  return res.status(status).json({
    success: false,
    error: message,
    ...(code ? { code } : {})
  });
}

function getBearerToken(req) {
  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return null;
  }

  return authorization.slice(7).trim();
}

function isValidRole(role) {
  return ["admin", "teacher", "student"].includes(role);
}

function isActiveProfile(profile) {
  if (!profile || profile.active === false) {
    return false;
  }

  return ![
    "inactive",
    "disabled",
    "suspended",
    "deleted"
  ].includes(String(profile.status || "").toLowerCase());
}

function isValidSessionId(id) {
  return typeof id === "string" &&
    /^[a-f0-9-]{30,80}$/i.test(id);
}

function sessionCollection(uid) {
  return db.collection(SESSION_COLLECTION)
    .doc(uid)
    .collection("sessions");
}

function sessionRef(uid, sessionId) {
  return sessionCollection(uid).doc(sessionId);
}

function timestampToDate(value) {
  if (!value) return null;

  if (value instanceof Date) return value;

  if (typeof value.toDate === "function") {
    return value.toDate();
  }

  return null;
}

async function writeAdminLog(req, action, targetUid, details = {}) {
  await db.collection("adminLogs").add({
    adminUid: req.user.uid,
    adminEmail: req.user.email || "",
    action,
    targetUid: targetUid || null,
    details,
    createdAt: FieldValue.serverTimestamp()
  });
}

// ==========================================
// 5. Firestore初期化
// ==========================================

async function initializeFirestore() {
  const ref = db.collection("settings").doc("system");
  const snapshot = await ref.get();

  if (!snapshot.exists) {
    await ref.set({
      maintenance: false,
      maintenanceMessage: "",
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });
  }
}

// ==========================================
// 6. Firebase認証
// ==========================================

async function authenticateFirebase(req, res, next) {
  try {
    const idToken = getBearerToken(req);

    if (!idToken) {
      return sendError(res, 401, "ログインしてください。");
    }

    const decoded = await admin.auth().verifyIdToken(idToken);

    const userSnapshot = await db.collection("users")
      .doc(decoded.uid)
      .get();

    if (!userSnapshot.exists) {
      return sendError(res, 403, "ユーザー情報が登録されていません。");
    }

    const profile = userSnapshot.data();

    if (!isActiveProfile(profile)) {
      return sendError(res, 403, "このアカウントは利用停止中です。");
    }

    if (!isValidRole(profile.role)) {
      return sendError(res, 403, "ユーザー権限が正しくありません。");
    }

    req.user = {
      uid: decoded.uid,
      email: decoded.email || profile.email || "",
      profile
    };

    next();
  } catch (error) {
    console.error("Firebase認証エラー:", error);
    return sendError(res, 401, "認証に失敗しました。");
  }
}

// ==========================================
// 7. セッション認証
// ==========================================

async function authenticate(req, res, next) {
  authenticateFirebase(req, res, async () => {
    try {
      const sessionId = String(
        req.headers["x-session-id"] || ""
      );

      if (!isValidSessionId(sessionId)) {
        return sendError(
          res,
          401,
          "端末セッションが確認できません。",
          "SESSION_INVALID"
        );
      }

      const ref = sessionRef(req.user.uid, sessionId);
      const snapshot = await ref.get();

      if (!snapshot.exists || snapshot.data().active !== true) {
        return sendError(
          res,
          401,
          "この端末のセッションは解除されています。",
          "SESSION_REVOKED"
        );
      }

      const data = snapshot.data();
      const lastSeen = timestampToDate(data.lastSeenAt);

      if (
        !lastSeen ||
        Date.now() - lastSeen.getTime() > SESSION_TIMEOUT_MS
      ) {
        await ref.set({
          active: false,
          expiredAt: FieldValue.serverTimestamp()
        }, { merge: true });

        return sendError(
          res,
          401,
          "セッションの有効期限が切れました。",
          "SESSION_EXPIRED"
        );
      }

      await ref.set({
        lastSeenAt: FieldValue.serverTimestamp()
      }, { merge: true });

      req.sessionId = sessionId;
      next();

    } catch (error) {
      console.error("セッション認証エラー:", error);
      return sendError(res, 500, "セッション確認に失敗しました。");
    }
  });
}

function requireAdmin(req, res, next) {
  if (req.user.profile.role !== "admin") {
    return sendError(res, 403, "管理者権限が必要です。");
  }

  next();
}

// ==========================================
// 8. ヘルスチェック
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
// 9. システム状態
// ==========================================

app.get("/api/system/status", async (req, res) => {
  try {
    const snapshot = await db.collection("settings")
      .doc("system")
      .get();

    const settings = snapshot.exists ? snapshot.data() : {};

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

// ==========================================
// 10. 端末セッション登録
// ==========================================

app.post("/api/sessions/register", authenticateFirebase, async (req, res) => {
  try {
    const sessionId = String(req.body.sessionId || "");

    if (!isValidSessionId(sessionId)) {
      return sendError(res, 400, "セッションIDが正しくありません。");
    }

    const uid = req.user.uid;
    const collection = sessionCollection(uid);
    const currentRef = collection.doc(sessionId);

    const result = await db.runTransaction(async (tx) => {
      const snapshot = await tx.get(collection);
      const now = Date.now();

      const activeSessions = snapshot.docs.filter((doc) => {
        const data = doc.data();

        if (data.active !== true) return false;

        const lastSeen = timestampToDate(data.lastSeenAt);

        if (
          !lastSeen ||
          now - lastSeen.getTime() > SESSION_TIMEOUT_MS
        ) {
          tx.set(doc.ref, {
            active: false,
            expiredAt: FieldValue.serverTimestamp()
          }, { merge: true });

          return false;
        }

        return true;
      });

      const existing = activeSessions.find(
        (doc) => doc.id === sessionId
      );

      if (existing) {
        tx.set(currentRef, {
          lastSeenAt: FieldValue.serverTimestamp(),
          userAgent: String(req.headers["user-agent"] || "").slice(0, 300)
        }, { merge: true });

        return {
          success: true,
          count: activeSessions.length
        };
      }

      if (activeSessions.length >= MAX_SESSIONS) {
        return {
          success: false,
          count: activeSessions.length
        };
      }

      tx.set(currentRef, {
        uid,
        sessionId,
        active: true,
        userAgent: String(req.headers["user-agent"] || "").slice(0, 300),
        createdAt: FieldValue.serverTimestamp(),
        lastSeenAt: FieldValue.serverTimestamp()
      });

      return {
        success: true,
        count: activeSessions.length + 1
      };
    });

    if (!result.success) {
      return res.status(409).json({
        success: false,
        code: "SESSION_LIMIT",
        error: "同時ログイン上限の4端末に達しています。",
        activeCount: result.count,
        maxSessions: MAX_SESSIONS
      });
    }

    res.json({
      success: true,
      activeCount: result.count,
      maxSessions: MAX_SESSIONS
    });

  } catch (error) {
    console.error(error);
    sendError(res, 500, "端末セッションを登録できませんでした。");
  }
});

// ==========================================
// 11. セッションのハートビート
// ==========================================

app.post("/api/sessions/heartbeat", authenticateFirebase, async (req, res) => {
  try {
    const sessionId = String(req.body.sessionId || "");

    if (!isValidSessionId(sessionId)) {
      return sendError(res, 400, "セッションIDが正しくありません。");
    }

    const ref = sessionRef(req.user.uid, sessionId);
    const snapshot = await ref.get();

    if (!snapshot.exists || snapshot.data().active !== true) {
      return sendError(
        res,
        401,
        "セッションが解除されています。",
        "SESSION_REVOKED"
      );
    }

    await ref.update({
      lastSeenAt: FieldValue.serverTimestamp()
    });

    res.json({ success: true });

  } catch (error) {
    console.error(error);
    sendError(res, 500, "セッション確認に失敗しました。");
  }
});

// ==========================================
// 12. ログアウト
// ==========================================

app.post("/api/sessions/logout", authenticateFirebase, async (req, res) => {
  try {
    const sessionId = String(req.body.sessionId || "");

    if (!isValidSessionId(sessionId)) {
      return sendError(res, 400, "セッションIDが正しくありません。");
    }

    const ref = sessionRef(req.user.uid, sessionId);
    const snapshot = await ref.get();

    if (snapshot.exists) {
      await ref.set({
        active: false,
        loggedOutAt: FieldValue.serverTimestamp()
      }, { merge: true });
    }

    res.json({ success: true });

  } catch (error) {
    console.error(error);
    sendError(res, 500, "ログアウト処理に失敗しました。");
  }
});

// ==========================================
// 13. 現在のセッション
// ==========================================

app.get("/api/sessions/current", authenticate, (req, res) => {
  res.json({
    success: true,
    valid: true,
    sessionId: req.sessionId
  });
});

// ==========================================
// 14. ログインユーザー情報
// ==========================================

app.get("/api/me", authenticate, (req, res) => {
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

// ==========================================
// 15. 管理者：システム概要
// ==========================================

app.get(
  "/api/admin/overview",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const sessions = await db.collectionGroup("sessions")
        .where("active", "==", true)
        .get();

      const settings = await db.collection("settings")
        .doc("system")
        .get();

      res.json({
        success: true,
        overview: {
          activeSessions: sessions.size,
          maxSessionsPerUser: MAX_SESSIONS,
          maintenance: settings.exists &&
            settings.data().maintenance === true,
          serverStatus: "ok",
          serverTime: new Date().toISOString()
        }
      });

    } catch (error) {
      console.error(error);
      sendError(res, 500, "システム概要を取得できませんでした。");
    }
  }
);

// ==========================================
// 16. 管理者：端末一覧
// ==========================================

app.get(
  "/api/admin/sessions",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const users = await db.collection("users").get();
      const sessions = [];

      for (const userDoc of users.docs) {
        const profile = userDoc.data();

        const snapshot = await sessionCollection(userDoc.id)
          .where("active", "==", true)
          .get();

        for (const sessionDoc of snapshot.docs) {
          const data = sessionDoc.data();

          sessions.push({
            uid: userDoc.id,
            email: profile.email || "",
            displayName: profile.displayName || "",
            role: profile.role || "",
            sessionId: sessionDoc.id,
            createdAt: timestampToDate(data.createdAt)?.toISOString() || null,
            lastSeenAt: timestampToDate(data.lastSeenAt)?.toISOString() || null,
            userAgent: data.userAgent || ""
          });
        }
      }

      res.json({
        success: true,
        count: sessions.length,
        sessions
      });

    } catch (error) {
      console.error(error);
      sendError(res, 500, "端末一覧を取得できませんでした。");
    }
  }
);

// ==========================================
// 17. 管理者：端末強制解除
// ==========================================

app.delete(
  "/api/admin/sessions/:uid/:sessionId",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const uid = String(req.params.uid || "");
      const sessionId = String(req.params.sessionId || "");

      if (!uid || !isValidSessionId(sessionId)) {
        return sendError(res, 400, "指定情報が正しくありません。");
      }

      const ref = sessionRef(uid, sessionId);
      const snapshot = await ref.get();

      if (!snapshot.exists || snapshot.data().active !== true) {
        return sendError(res, 404, "有効なセッションがありません。");
      }

      await ref.set({
        active: false,
        revokedAt: FieldValue.serverTimestamp(),
        revokedBy: req.user.uid
      }, { merge: true });

      // 同じユーザーのLiveKit参加者を切断
      try {
        const participants = await roomService.listRooms();

        for (const room of participants) {
          const roomParticipants = await roomService.listParticipants(
            room.name
          );

          for (const participant of roomParticipants) {
            if (participant.identity === uid) {
              await roomService.removeParticipant(
                room.name,
                uid
              );
            }
          }
        }
      } catch (livekitError) {
        console.error("LiveKit切断処理:", livekitError);
      }

      await writeAdminLog(
        req,
        "session_revoked",
        uid,
        { sessionId }
      );

      res.json({
        success: true,
        message: "端末セッションを解除しました。"
      });

    } catch (error) {
      console.error(error);
      sendError(res, 500, "端末セッションを解除できませんでした。");
    }
  }
);

// ==========================================
// 18. 管理者：システム設定取得
// ==========================================

app.get(
  "/api/admin/settings",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const snapshot = await db.collection("settings")
        .doc("system")
        .get();

      const data = snapshot.exists ? snapshot.data() : {};

      res.json({
        success: true,
        settings: {
          maintenance: data.maintenance === true,
          maintenanceMessage: data.maintenanceMessage || "",
          maxSessionsPerUser: MAX_SESSIONS
        }
      });

    } catch (error) {
      console.error(error);
      sendError(res, 500, "設定を取得できませんでした。");
    }
  }
);

// ==========================================
// 19. 管理者：システム設定変更
// ==========================================

app.patch(
  "/api/admin/settings",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const updates = {};
      const details = {};

      if (typeof req.body.maintenance === "boolean") {
        updates.maintenance = req.body.maintenance;
        details.maintenance = req.body.maintenance;
      }

      if (typeof req.body.maintenanceMessage === "string") {
        updates.maintenanceMessage =
          req.body.maintenanceMessage.trim().slice(0, 1000);

        details.maintenanceMessage = updates.maintenanceMessage;
      }

      if (!Object.keys(updates).length) {
        return sendError(res, 400, "変更する設定がありません。");
      }

      updates.updatedAt = FieldValue.serverTimestamp();

      await db.collection("settings")
        .doc("system")
        .set(updates, { merge: true });

      await writeAdminLog(
        req,
        "system_settings_updated",
        null,
        details
      );

      res.json({
        success: true,
        message: "システム設定を更新しました。"
      });

    } catch (error) {
      console.error(error);
      sendError(res, 500, "設定を更新できませんでした。");
    }
  }
);

// ==========================================
// 20. 管理者：操作ログ
// ==========================================

app.get(
  "/api/admin/logs",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const limit = Math.min(
        Math.max(Number(req.query.limit) || 50, 1),
        100
      );

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
          targetUid: data.targetUid || null,
          details: data.details || {},
          createdAt: timestampToDate(data.createdAt)?.toISOString() || null
        };
      });

      res.json({
        success: true,
        logs
      });

    } catch (error) {
      console.error(error);
      sendError(res, 500, "操作ログを取得できませんでした。");
    }
  }
);

// ==========================================
// 21. 授業日時変換
// ==========================================

function toDate(value) {
  if (!value) return null;

  if (value instanceof Date) return value;

  if (typeof value.toDate === "function") {
    return value.toDate();
  }

  if (typeof value === "number") {
    return new Date(value);
  }

  if (typeof value === "string") {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
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
    return new Date(
      start.getTime() + Number(lesson.durationMinutes) * 60000
    );
  }

  return null;
}

// ==========================================
// 22. LiveKit授業参加トークン
// ==========================================

app.post(
  "/api/livekit/token",
  authenticate,
  async (req, res) => {
    try {
      const lessonId = String(req.body.lessonId || "").trim();

      if (!lessonId || lessonId.length > 150) {
        return sendError(res, 400, "授業IDが正しくありません。");
      }

      const profile = req.user.profile;
      const uid = req.user.uid;

      // 管理者は授業に参加しない
      if (profile.role === "admin") {
        return sendError(res, 403, "管理者は授業に参加できません。");
      }

      const lessonSnapshot = await db.collection("lessons")
        .doc(lessonId)
        .get();

      if (!lessonSnapshot.exists) {
        return sendError(res, 404, "授業が見つかりません。");
      }

      const lesson = lessonSnapshot.data();

      const isTeacher =
        profile.role === "teacher" &&
        lesson.teacherId === uid;

      const isStudent =
        profile.role === "student" &&
        lesson.studentId === uid;

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
        (isTeacher ? "先生" : "生徒");

      const accessToken = new AccessToken(
        LIVEKIT_API_KEY,
        LIVEKIT_API_SECRET,
        {
          identity: `${uid}-${req.sessionId}`,
          name: displayName,
          metadata: JSON.stringify({
            uid,
            sessionId: req.sessionId,
            role: profile.role,
            lessonId
          }),
          ttl: "5m"
        }
      );

      accessToken.addGrant({
        roomJoin: true,
        room: roomName,
        canPublish: true,
        canSubscribe: true,
        canPublishData: true
      });

      res.json({
        success: true,
        url: LIVEKIT_URL,
        token: await accessToken.toJwt(),
        roomName,
        identity: `${uid}-${req.sessionId}`,
        name: displayName
      });

    } catch (error) {
      console.error("LiveKitトークン発行エラー:", error);
      sendError(res, 500, "授業室への接続準備に失敗しました。");
    }
  }
);

// ==========================================
// 23. 静的ファイル
// ==========================================

const publicDirectory = path.join(__dirname, "public");

if (fs.existsSync(publicDirectory)) {
  app.use(express.static(publicDirectory, {
    index: false,
    extensions: ["html"],
    maxAge: "1h"
  }));

  app.get("/", (req, res) => {
    res.sendFile(path.join(publicDirectory, "login.html"));
  });
}

// ==========================================
// 24. 404・エラー処理
// ==========================================

app.use("/api", (req, res) => {
  sendError(res, 404, "指定されたAPIは存在しません。");
});

app.use((req, res) => {
  res.status(404).send("ページが見つかりません。");
});

app.use((error, req, res, next) => {
  console.error("サーバーエラー:", error);

  if (res.headersSent) {
    return next(error);
  }

  sendError(res, 500, "サーバー内部でエラーが発生しました。");
});

// ==========================================
// 25. 起動
// ==========================================

async function startServer() {
  try {
    await initializeFirestore();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("WEB Course-plus");
      console.log("Server: running");
      console.log(`Port: ${PORT}`);
      console.log("Firebase: initialized");
      console.log("Firestore: initialized");
      console.log("LiveKit: configured");
      console.log(`Maximum sessions: ${MAX_SESSIONS}`);
      console.log("Health: /health");
    });

  } catch (error) {
    console.error("サーバー起動エラー:", error);
    process.exit(1);
  }
}

startServer();
