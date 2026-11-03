"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const admin = require("firebase-admin");
const { AccessToken } = require("livekit-server-sdk");

const app = express();
const PORT = process.env.PORT || 10000;

const MAX_SESSIONS_PER_USER = 4;
const SESSION_IDLE_DAYS = 30;
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
// 環境変数
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
// Firebase Admin
// ==========================================

let serviceAccount;

try {
  serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);

  if (serviceAccount.private_key) {
    serviceAccount.private_key =
      serviceAccount.private_key.replace(/\\n/g, "\n");
  }
} catch (error) {
  console.error("Firebase JSONの解析に失敗:", error.message);
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
// 共通関数
// ==========================================

function errorResponse(res, status, message, code) {
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

  const status = String(profile.status || "").toLowerCase();

  return ![
    "inactive",
    "disabled",
    "suspended",
    "deleted"
  ].includes(status);
}

function isValidSessionId(id) {
  return (
    typeof id === "string" &&
    /^[a-f0-9-]{30,80}$/i.test(id)
  );
}

function getSessionRef(uid, sessionId) {
  return db
    .collection(SESSION_COLLECTION)
    .doc(uid)
    .collection("sessions")
    .doc(sessionId);
}

function getSessionsCollection(uid) {
  return db
    .collection(SESSION_COLLECTION)
    .doc(uid)
    .collection("sessions");
}

async function writeAdminLog(req, action, targetUid = null, details = {}) {
  await db.collection("adminLogs").add({
    adminUid: req.user.uid,
    adminEmail: req.user.email,
    action,
    targetUid,
    details,
    createdAt: FieldValue.serverTimestamp()
  });
}

// ==========================================
// Firebase認証
// ==========================================

// Firebase IDトークンとユーザープロフィールを検証する。
// セッション登録前にも使用する。
async function authenticate(req, res, next) {
  try {
    const idToken = getBearerToken(req);

    if (!idToken) {
      return errorResponse(res, 401, "ログインしてください。");
    }

    const decoded = await admin.auth().verifyIdToken(idToken);

    const userSnap = await db
      .collection("users")
      .doc(decoded.uid)
      .get();

    if (!userSnap.exists) {
      return errorResponse(
        res,
        403,
        "ユーザー情報が登録されていません。"
      );
    }

    const profile = userSnap.data();

    if (!isActiveProfile(profile)) {
      return errorResponse(
        res,
        403,
        "このアカウントは利用停止中です。"
      );
    }

    if (!isValidRole(profile.role)) {
      return errorResponse(
        res,
        403,
        "ユーザー権限が正しくありません。"
      );
    }

    req.user = {
      uid: decoded.uid,
      email: decoded.email || profile.email || "",
      profile
    };

    next();

  } catch (error) {
    console.error("認証エラー:", error);

    return errorResponse(
      res,
      401,
      "認証に失敗しました。再度ログインしてください。"
    );
  }
}

// ==========================================
// セッション認証
// ==========================================

async function requireSession(req, res, next) {
  try {
    const sessionId = String(
      req.headers["x-session-id"] || ""
    );

    if (!isValidSessionId(sessionId)) {
      return errorResponse(
        res,
        401,
        "端末セッションを確認できません。",
        "SESSION_INVALID"
      );
    }

    const ref = getSessionRef(req.user.uid, sessionId);
    const snap = await ref.get();

    if (!snap.exists || snap.data().active !== true) {
      return errorResponse(
        res,
        401,
        "この端末のセッションは無効です。再ログインしてください。",
        "SESSION_REVOKED"
      );
    }

    const data = snap.data();

    const lastSeen = data.lastSeenAt &&
      typeof data.lastSeenAt.toDate === "function"
      ? data.lastSeenAt.toDate()
      : null;

    if (
      lastSeen &&
      Date.now() - lastSeen.getTime() >
        SESSION_IDLE_DAYS * 24 * 60 * 60 * 1000
    ) {
      await ref.set({
        active: false,
        expiredAt: FieldValue.serverTimestamp()
      }, { merge: true });

      return errorResponse(
        res,
        401,
        "セッションの有効期限が切れました。再ログインしてください。",
        "SESSION_EXPIRED"
      );
    }

    // 最終利用時刻は5分ごとに更新
    if (
      !lastSeen ||
      Date.now() - lastSeen.getTime() > 5 * 60 * 1000
    ) {
      await ref.set({
        lastSeenAt: FieldValue.serverTimestamp()
      }, { merge: true });
    }

    req.sessionId = sessionId;

    next();

  } catch (error) {
    console.error("セッション確認エラー:", error);

    return errorResponse(
      res,
      500,
      "セッションを確認できませんでした。"
    );
  }
}

function requireAdmin(req, res, next) {
  if (req.user.profile.role !== "admin") {
    return errorResponse(
      res,
      403,
      "システム管理者権限が必要です。"
    );
  }

  next();
}

// ==========================================
// Firestore初期設定
// ==========================================

async function initializeFirestore() {
  const ref = db.collection("settings").doc("system");
  const snap = await ref.get();

  if (!snap.exists) {
    await ref.set({
      maintenance: false,
      maintenanceMessage: "",
      maxSessionsPerUser: MAX_SESSIONS_PER_USER,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });
  } else if (
    typeof snap.data().maxSessionsPerUser !== "number"
  ) {
    await ref.set({
      maxSessionsPerUser: MAX_SESSIONS_PER_USER,
      updatedAt: FieldValue.serverTimestamp()
    }, { merge: true });
  }
}

// ==========================================
// ヘルスチェック
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
// システム状態
// ==========================================

app.get("/api/system/status", async (req, res) => {
  try {
    const snap = await db
      .collection("settings")
      .doc("system")
      .get();

    const settings = snap.exists ? snap.data() : {};

    res.json({
      success: true,
      maintenance: settings.maintenance === true,
      maintenanceMessage:
        settings.maintenanceMessage || "",
      maxSessionsPerUser: MAX_SESSIONS_PER_USER
    });

  } catch (error) {
    console.error("システム状態取得エラー:", error);

    errorResponse(
      res,
      500,
      "システム状態を取得できませんでした。"
    );
  }
});

// ==========================================
// 端末セッション登録
// ==========================================

app.post(
  "/api/sessions/register",
  authenticate,
  async (req, res) => {
    try {
      const sessionId = String(req.body.sessionId || "");

      if (!isValidSessionId(sessionId)) {
        return errorResponse(
          res,
          400,
          "端末セッションIDが正しくありません。"
        );
      }

      const uid = req.user.uid;
      const collection = getSessionsCollection(uid);
      const currentRef = collection.doc(sessionId);

      const result = await db.runTransaction(async (tx) => {
        const allSessions = await tx.get(collection);

        const activeSessions = allSessions.docs.filter(
          (doc) => doc.data().active === true
        );

        const existing = activeSessions.find(
          (doc) => doc.id === sessionId
        );

        // すでに登録済みなら同じ端末として扱う
        if (existing) {
          tx.set(currentRef, {
            lastSeenAt: FieldValue.serverTimestamp(),
            userAgent: String(
              req.headers["user-agent"] || ""
            ).slice(0, 300)
          }, { merge: true });

          return {
            success: true,
            count: activeSessions.length
          };
        }

        // 4端末を超える場合は拒否
        if (activeSessions.length >= MAX_SESSIONS_PER_USER) {
          return {
            success: false,
            count: activeSessions.length
          };
        }

        tx.set(currentRef, {
          uid,
          sessionId,
          active: true,
          userAgent: String(
            req.headers["user-agent"] || ""
          ).slice(0, 300),
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
          error: "同時ログイン上限の4台に達しています。",
          activeCount: result.count,
          maxSessions: MAX_SESSIONS_PER_USER
        });
      }

      res.json({
        success: true,
        activeCount: result.count,
        maxSessions: MAX_SESSIONS_PER_USER
      });

    } catch (error) {
      console.error("セッション登録エラー:", error);

      errorResponse(
        res,
        500,
        "端末セッションを登録できませんでした。"
      );
    }
  }
);

// ==========================================
// ログアウト
// ==========================================

app.post(
  "/api/sessions/logout",
  authenticate,
  async (req, res) => {
    try {
      const sessionId = String(req.body.sessionId || "");

      if (!isValidSessionId(sessionId)) {
        return errorResponse(
          res,
          400,
          "端末セッションIDが正しくありません。"
        );
      }

      const ref = getSessionRef(
        req.user.uid,
        sessionId
      );

      const snap = await ref.get();

      if (snap.exists && snap.data().active === true) {
        await ref.set({
          active: false,
          loggedOutAt: FieldValue.serverTimestamp()
        }, { merge: true });
      }

      res.json({ success: true });

    } catch (error) {
      console.error("ログアウト処理エラー:", error);

      errorResponse(
        res,
        500,
        "セッションを終了できませんでした。"
      );
    }
  }
);

// ==========================================
// 現在のセッション確認
// ==========================================

app.get(
  "/api/sessions/current",
  authenticate,
  requireSession,
  (req, res) => {
    res.json({
      success: true,
      valid: true,
      sessionId: req.sessionId
    });
  }
);

// ==========================================
// ログインユーザー情報
// ==========================================

app.get(
  "/api/me",
  authenticate,
  requireSession,
  (req, res) => {
    res.json({
      success: true,
      user: {
        uid: req.user.uid,
        email: req.user.email,
        role: req.user.profile.role,
        displayName:
          req.user.profile.displayName || "",
        status:
          req.user.profile.status || "active"
      }
    });
  }
);

// ==========================================
// 管理者：システム概要
// ==========================================

app.get(
  "/api/admin/overview",
  authenticate,
  requireSession,
  requireAdmin,
  async (req, res) => {
    try {
      const [sessions, settings, logs] = await Promise.all([
        db.collectionGroup("sessions")
          .where("active", "==", true)
          .get(),

        db.collection("settings")
          .doc("system")
          .get(),

        db.collection("adminLogs")
          .orderBy("createdAt", "desc")
          .limit(1)
          .get()
      ]);

      const settingData = settings.exists
        ? settings.data()
        : {};

      res.json({
        success: true,
        overview: {
          activeSessions: sessions.size,
          maxSessionsPerUser: MAX_SESSIONS_PER_USER,
          maintenance:
            settingData.maintenance === true,
          latestAdminActionAt: logs.empty
            ? null
            : logs.docs[0].data().createdAt
                ?.toDate?.()
                .toISOString() || null,
          serverStatus: "ok",
          serverTime: new Date().toISOString()
        }
      });

    } catch (error) {
      console.error("管理者概要取得エラー:", error);

      errorResponse(
        res,
        500,
        "システム概要を取得できませんでした。"
      );
    }
  }
);

// ==========================================
// 管理者：全端末セッション一覧
// ==========================================

app.get(
  "/api/admin/sessions",
  authenticate,
  requireSession,
  requireAdmin,
  async (req, res) => {
    try {
      const users = await db.collection("users").get();
      const sessions = [];

      for (const userDoc of users.docs) {
        const sessionSnap = await getSessionsCollection(
          userDoc.id
        )
          .where("active", "==", true)
          .get();

        const profile = userDoc.data();

        for (const sessionDoc of sessionSnap.docs) {
          const data = sessionDoc.data();

          sessions.push({
            uid: userDoc.id,
            email: profile.email || "",
            displayName: profile.displayName || "",
            role: profile.role || "",
            sessionId: sessionDoc.id,
            createdAt:
              data.createdAt?.toDate?.().toISOString() || null,
            lastSeenAt:
              data.lastSeenAt?.toDate?.().toISOString() || null,
            userAgent: data.userAgent || ""
          });
        }
      }

      res.json({
        success: true,
        sessions,
        count: sessions.length
      });

    } catch (error) {
      console.error("セッション一覧取得エラー:", error);

      errorResponse(
        res,
        500,
        "セッション一覧を取得できませんでした。"
      );
    }
  }
);

// ==========================================
// 管理者：端末セッション強制解除
// ==========================================

app.delete(
  "/api/admin/sessions/:uid/:sessionId",
  authenticate,
  requireSession,
  requireAdmin,
  async (req, res) => {
    try {
      const uid = String(req.params.uid || "");
      const sessionId = String(req.params.sessionId || "");

      if (!uid || !isValidSessionId(sessionId)) {
        return errorResponse(
          res,
          400,
          "指定されたセッション情報が正しくありません。"
        );
      }

      const ref = getSessionRef(uid, sessionId);
      const snap = await ref.get();

      if (!snap.exists || snap.data().active !== true) {
        return errorResponse(
          res,
          404,
          "有効なセッションが見つかりません。"
        );
      }

      await ref.set({
        active: false,
        revokedAt: FieldValue.serverTimestamp(),
        revokedBy: req.user.uid
      }, { merge: true });

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
      console.error("セッション解除エラー:", error);

      errorResponse(
        res,
        500,
        "セッションを解除できませんでした。"
      );
    }
  }
);

// ==========================================
// 管理者：システム設定取得
// ==========================================

app.get(
  "/api/admin/settings",
  authenticate,
  requireSession,
  requireAdmin,
  async (req, res) => {
    try {
      const snap = await db
        .collection("settings")
        .doc("system")
        .get();

      const data = snap.exists ? snap.data() : {};

      res.json({
        success: true,
        settings: {
          maintenance: data.maintenance === true,
          maintenanceMessage:
            data.maintenanceMessage || "",
          maxSessionsPerUser: MAX_SESSIONS_PER_USER
        }
      });

    } catch (error) {
      console.error("設定取得エラー:", error);

      errorResponse(
        res,
        500,
        "システム設定を取得できませんでした。"
      );
    }
  }
);

// ==========================================
// 管理者：システム設定変更
// ==========================================

app.patch(
  "/api/admin/settings",
  authenticate,
  requireSession,
  requireAdmin,
  async (req, res) => {
    try {
      const updates = {};
      const details = {};

      if (typeof req.body.maintenance === "boolean") {
        updates.maintenance = req.body.maintenance;
        details.maintenance = req.body.maintenance;
      }

      if (
        typeof req.body.maintenanceMessage === "string"
      ) {
        updates.maintenanceMessage =
          req.body.maintenanceMessage.trim().slice(0, 1000);

        details.maintenanceMessage =
          updates.maintenanceMessage;
      }

      if (Object.keys(updates).length === 0) {
        return errorResponse(
          res,
          400,
          "変更する設定がありません。"
        );
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
      console.error("設定更新エラー:", error);

      errorResponse(
        res,
        500,
        "システム設定を更新できませんでした。"
      );
    }
  }
);

// ==========================================
// 管理者：操作ログ
// ==========================================

app.get(
  "/api/admin/logs",
  authenticate,
  requireSession,
  requireAdmin,
  async (req, res) => {
    try {
      const limit = Math.min(
        Math.max(Number(req.query.limit) || 50, 1),
        100
      );

      const snap = await db.collection("adminLogs")
        .orderBy("createdAt", "desc")
        .limit(limit)
        .get();

      const logs = snap.docs.map((doc) => {
        const data = doc.data();

        return {
          id: doc.id,
          adminEmail: data.adminEmail || "",
          action: data.action || "",
          targetUid: data.targetUid || null,
          details: data.details || {},
          createdAt:
            data.createdAt?.toDate?.().toISOString() || null
        };
      });

      res.json({
        success: true,
        logs
      });

    } catch (error) {
      console.error("ログ取得エラー:", error);

      errorResponse(
        res,
        500,
        "操作ログを取得できませんでした。"
      );
    }
  }
);

// ==========================================
// LiveKit：授業参加トークン
// ==========================================

app.post(
  "/api/livekit/token",
  authenticate,
  requireSession,
  async (req, res) => {
    try {
      const profile = req.user.profile;
      const uid = req.user.uid;

      if (profile.role === "admin") {
        return errorResponse(
          res,
          403,
          "システム管理者は授業に参加できません。"
        );
      }

      const lessonId = String(
        req.body.lessonId || ""
      ).trim();

      if (!lessonId || lessonId.length > 150) {
        return errorResponse(
          res,
          400,
          "授業IDが正しくありません。"
        );
      }

      const lessonSnap = await db
        .collection("lessons")
        .doc(lessonId)
        .get();

      if (!lessonSnap.exists) {
        return errorResponse(
          res,
          404,
          "授業が見つかりません。"
        );
      }

      const lesson = lessonSnap.data();

      const isTeacher = profile.role === "teacher";
      const isStudent =
        profile.role === "student" &&
        lesson.studentId === uid;

      if (!isTeacher && !isStudent) {
        return errorResponse(
          res,
          403,
          "この授業に参加する権限がありません。"
        );
      }

      if (
        !["scheduled", "in_progress"].includes(
          lesson.status
        )
      ) {
        return errorResponse(
          res,
          403,
          "現在この授業には入室できません。"
        );
      }

      const roomName = `lesson-${lessonId}`;

      const displayName =
        profile.displayName ||
        req.user.email ||
        (isTeacher ? "先生" : "生徒");

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

      errorResponse(
        res,
        500,
        "授業室への接続準備に失敗しました。"
      );
    }
  }
);

// ==========================================
// 静的ファイル
// ==========================================

const publicDirectory = path.join(__dirname, "public");

if (fs.existsSync(publicDirectory)) {
  app.use(express.static(publicDirectory, {
    index: false,
    extensions: ["html"],
    maxAge: "1h"
  }));

  app.get("/", (req, res) => {
    const loginPath = path.join(
      publicDirectory,
      "login.html"
    );

    if (fs.existsSync(loginPath)) {
      return res.sendFile(loginPath);
    }

    res.status(404).send("WEB Course-plus");
  });
}

// ==========================================
// 404 / エラー処理
// ==========================================

app.use("/api", (req, res) => {
  errorResponse(
    res,
    404,
    "指定されたAPIは存在しません。"
  );
});

app.use((req, res) => {
  res.status(404).send("ページが見つかりません。");
});

app.use((error, req, res, next) => {
  console.error("サーバーエラー:", error);

  if (res.headersSent) {
    return next(error);
  }

  errorResponse(
    res,
    500,
    "サーバー内部でエラーが発生しました。"
  );
});

// ==========================================
// サーバー起動
// ==========================================

async function startServer() {
  try {
    await initializeFirestore();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("----------------------------------");
      console.log("WEB Course-plus");
      console.log("Server: running");
      console.log(`Port: ${PORT}`);
      console.log("Firebase: initialized");
      console.log("Firestore: initialized");
      console.log("LiveKit: configured");
      console.log(
        `Maximum sessions: ${MAX_SESSIONS_PER_USER}`
      );
      console.log("Health: /health");
      console.log("----------------------------------");
    });

  } catch (error) {
    console.error("サーバー起動エラー:", error);
    process.exit(1);
  }
}

startServer();
