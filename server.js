
"use strict";

require("dotenv").config();

const express = require("express");
const path = require("path");
const admin = require("firebase-admin");
const { AccessToken } = require("livekit-server-sdk");

const app = express();

const PORT = process.env.PORT || 3000;
const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY;
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET;
const LIVEKIT_URL = process.env.LIVEKIT_URL;

const db = initializeFirebase();

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// ========================================
// Firebase Admin SDK
// ========================================

function initializeFirebase() {
  if (admin.apps.length) {
    return admin.firestore();
  }

  // 環境変数にサービスアカウントJSONを設定する方式
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    const serviceAccount = JSON.parse(
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON
    );

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  } else {
    // Google CloudなどのApplication Default Credentials
    admin.initializeApp({
      credential: admin.credential.applicationDefault()
    });
  }

  return admin.firestore();
}

// ========================================
// 共通設定
// ========================================

const SERVER_TIMESTAMP =
  admin.firestore.FieldValue.serverTimestamp();

const DEFAULT_SETTINGS = {
  serviceName: "WEB Course-plus",
  maintenanceMode: false,
  maintenanceMessage: "",
  allowStudentLogin: true,
  allowTeacherLogin: true,
  allowAdminLogin: true,
  createdAt: SERVER_TIMESTAMP,
  updatedAt: SERVER_TIMESTAMP
};

// ========================================
// Firestore初期セットアップ
// ========================================

async function initializeDatabase() {
  const settingsRef = db.collection("settings").doc("system");

  const settingsSnap = await settingsRef.get();

  if (!settingsSnap.exists) {
    await settingsRef.create(DEFAULT_SETTINGS);
    console.log("[Database] settings/system created.");
  } else {
    // 新しい設定項目が追加された場合に不足分を補う
    const current = settingsSnap.data();

    const missing = {};

    for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
      if (!(key in current) && key !== "createdAt") {
        missing[key] = value;
      }
    }

    if (Object.keys(missing).length > 0) {
      missing.updatedAt = SERVER_TIMESTAMP;
      await settingsRef.update(missing);
      console.log("[Database] Missing settings initialized.");
    }
  }

  console.log("[Database] Initialization completed.");
}

// ========================================
// 共通レスポンス
// ========================================

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

// ========================================
// Firebase ID Token 認証
// ========================================

async function authenticate(req, res, next) {
  try {
    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return sendError(res, 401, "認証が必要です。");
    }

    const idToken = authorization.substring(7);

    if (!idToken) {
      return sendError(res, 401, "認証トークンがありません。");
    }

    const decoded = await admin.auth().verifyIdToken(idToken);

    const userRef = db.collection("users").doc(decoded.uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return sendError(res, 403, "利用者情報が登録されていません。");
    }

    const profile = userSnap.data();

    if (profile.status !== "active") {
      return sendError(res, 403, "このアカウントは利用できません。");
    }

    req.user = {
      uid: decoded.uid,
      email: decoded.email || "",
      role: profile.role,
      profile
    };

    next();

  } catch (error) {
    console.error("[Authentication]", error.message);
    return sendError(res, 401, "認証に失敗しました。");
  }
}

// ========================================
// 権限確認
// ========================================

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return sendError(res, 401, "ログインしてください。");
    }

    if (!allowedRoles.includes(req.user.role)) {
      return sendError(res, 403, "この操作を行う権限がありません。");
    }

    next();
  };
}

// ========================================
// システム設定取得
// ========================================

async function getSystemSettings() {
  const snap = await db
    .collection("settings")
    .doc("system")
    .get();

  if (!snap.exists) {
    return DEFAULT_SETTINGS;
  }

  return snap.data();
}

// ========================================
// メンテナンス確認
// ========================================

async function checkMaintenance(req, res, next) {
  try {
    const settings = await getSystemSettings();

    // 管理者はメンテナンス中でも利用可能
    if (
      settings.maintenanceMode === true &&
      req.user.role !== "admin"
    ) {
      return res.status(503).json({
        success: false,
        maintenance: true,
        message:
          settings.maintenanceMessage ||
          "現在メンテナンス中です。しばらくお待ちください。"
      });
    }

    next();

  } catch (error) {
    console.error("[Maintenance]", error);
    return sendError(res, 500, "システム設定を確認できません。");
  }
}

// ========================================
// ヘルスチェック
// ========================================

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "WEB Course-plus",
    status: "running",
    timestamp: new Date().toISOString()
  });
});

// ========================================
// システム状態取得
// ========================================

app.get("/api/system/status", async (req, res) => {
  try {
    const settings = await getSystemSettings();

    res.json({
      success: true,
      serviceName: settings.serviceName,
      maintenanceMode: settings.maintenanceMode === true,
      maintenanceMessage: settings.maintenanceMessage || ""
    });

  } catch (error) {
    console.error("[System Status]", error);
    sendError(res, 500, "システム状態を取得できません。");
  }
});

// ========================================
// ログインユーザー情報
// ========================================

app.get(
  "/api/me",
  authenticate,
  async (req, res) => {
    res.json({
      success: true,
      user: {
        uid: req.user.uid,
        email: req.user.email,
        role: req.user.role,
        displayName:
          req.user.profile.displayName ||
          req.user.profile.name ||
          ""
      }
    });
  }
);

// ========================================
// LiveKit 授業参加トークン発行
// ========================================

app.post(
  "/api/livekit/token",
  authenticate,
  checkMaintenance,
  async (req, res) => {
    try {
      const { lessonId } = req.body;

      if (
        typeof lessonId !== "string" ||
        !lessonId.trim() ||
        lessonId.length > 150
      ) {
        return sendError(res, 400, "授業IDが正しくありません。");
      }

      if (!LIVEKIT_API_KEY || !LIVEKIT_API_SECRET || !LIVEKIT_URL) {
        console.error("[LiveKit] Server credentials are missing.");
        return sendError(
          res,
          503,
          "ビデオ通話サービスが設定されていません。"
        );
      }

      const lessonRef = db.collection("lessons").doc(lessonId);
      const lessonSnap = await lessonRef.get();

      if (!lessonSnap.exists) {
        return sendError(res, 404, "授業が見つかりません。");
      }

      const lesson = lessonSnap.data();

      // 授業参加者の権限確認
      const isStudent =
        req.user.role === "student" &&
        lesson.studentId === req.user.uid;

      const isTeacher =
        req.user.role === "teacher" &&
        lesson.teacherId === req.user.uid;

      const isAdmin = req.user.role === "admin";

      if (!isStudent && !isTeacher && !isAdmin) {
        return sendError(
          res,
          403,
          "この授業に参加する権限がありません。"
        );
      }

      // 授業状態確認
      if (!["scheduled", "in_progress"].includes(lesson.status)) {
        return sendError(
          res,
          403,
          "この授業は現在参加できる状態ではありません。"
        );
      }

      const startAt = lesson.startAt?.toDate
        ? lesson.startAt.toDate()
        : new Date(lesson.startAt);

      const endAt = lesson.endAt?.toDate
        ? lesson.endAt.toDate()
        : new Date(lesson.endAt);

      if (
        !Number.isFinite(startAt.getTime()) ||
        !Number.isFinite(endAt.getTime()) ||
        endAt <= startAt
      ) {
        return sendError(
          res,
          400,
          "授業日時の設定が正しくありません。"
        );
      }

      const now = new Date();

      // 開始5分前から終了30分後まで入室可能
      const allowedStart = new Date(
        startAt.getTime() - 5 * 60 * 1000
      );

      const allowedEnd = new Date(
        endAt.getTime() + 30 * 60 * 1000
      );

      if (now < allowedStart) {
        return sendError(
          res,
          403,
          "授業開始時刻の5分前から参加できます。"
        );
      }

      if (now > allowedEnd) {
        return sendError(
          res,
          403,
          "この授業の参加可能時間は終了しました。"
        );
      }

      // 授業中に変更
      if (lesson.status === "scheduled" && now >= startAt) {
        await lessonRef.update({
          status: "in_progress",
          updatedAt: SERVER_TIMESTAMP
        });
      }

      // LiveKitルーム名
      const roomName = `lesson-${lessonId}`;

      const participantName =
        req.user.profile.displayName ||
        req.user.profile.name ||
        req.user.email ||
        req.user.uid;

      // LiveKitトークン作成
      const token = new AccessToken(
        LIVEKIT_API_KEY,
        LIVEKIT_API_SECRET,
        {
          identity: req.user.uid,
          name: participantName,
          ttl: "2h",
          metadata: JSON.stringify({
            lessonId,
            role: req.user.role
          })
        }
      );

      token.addGrant({
        roomJoin: true,
        room: roomName,
        canPublish: true,
        canSubscribe: true,
        canPublishData: true
      });

      const jwt = await token.toJwt();

      res.json({
        success: true,
        token: jwt,
        serverUrl: LIVEKIT_URL,
        roomName,
        lessonId,
        participantName
      });

    } catch (error) {
      console.error("[LiveKit Token]", error);
      sendError(res, 500, "授業への接続準備に失敗しました。");
    }
  }
);

// ========================================
// 管理者専用：システム設定更新
// ========================================

app.patch(
  "/api/admin/settings",
  authenticate,
  requireRole("admin"),
  async (req, res) => {
    try {
      const allowedFields = [
        "maintenanceMode",
        "maintenanceMessage",
        "allowStudentLogin",
        "allowTeacherLogin",
        "allowAdminLogin"
      ];

      const updates = {};

      for (const field of allowedFields) {
        if (Object.prototype.hasOwnProperty.call(req.body, field)) {
          updates[field] = req.body[field];
        }
      }

      if (Object.keys(updates).length === 0) {
        return sendError(res, 400, "更新項目がありません。");
      }

      if (
        "maintenanceMode" in updates &&
        typeof updates.maintenanceMode !== "boolean"
      ) {
        return sendError(res, 400, "メンテナンス設定が不正です。");
      }

      for (const field of [
        "allowStudentLogin",
        "allowTeacherLogin",
        "allowAdminLogin"
      ]) {
        if (field in updates && typeof updates[field] !== "boolean") {
          return sendError(res, 400, `${field}の値が不正です。`);
        }
      }

      if (
        "maintenanceMessage" in updates &&
        typeof updates.maintenanceMessage !== "string"
      ) {
        return sendError(res, 400, "メッセージの形式が不正です。");
      }

      updates.updatedAt = SERVER_TIMESTAMP;

      await db
        .collection("settings")
        .doc("system")
        .set(updates, { merge: true });

      res.json({
        success: true,
        message: "システム設定を更新しました。"
      });

    } catch (error) {
      console.error("[Admin Settings]", error);
      sendError(res, 500, "設定を更新できませんでした。");
    }
  }
);

// ========================================
// 静的ファイル配信
// ========================================

const publicDirectory = path.join(__dirname, "public");

app.use(express.static(publicDirectory));

// トップページ
app.get("/", (req, res) => {
  res.sendFile(path.join(publicDirectory, "index.html"));
});

// ========================================
// 404
// ========================================

app.use("/api", (req, res) => {
  sendError(res, 404, "APIが見つかりません。");
});

app.use((req, res) => {
  res.status(404).send("ページが見つかりません。");
});

// ========================================
// エラー処理
// ========================================

app.use((error, req, res, next) => {
  console.error("[Server Error]", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    success: false,
    message: "サーバー内部でエラーが発生しました。"
  });
});

// ========================================
// サーバー起動
// ========================================

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("------------------------------------");
      console.log("WEB Course-plus");
      console.log("Server: running");
      console.log(`Port: ${PORT}`);
      console.log("------------------------------------");
    });

  } catch (error) {
    console.error("[Startup Error]", error);
    process.exit(1);
  }
}

startServer();
