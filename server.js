
"use strict";

require("dotenv").config();

const express = require("express");
const path = require("path");
const admin = require("firebase-admin");
const { AccessToken } = require("livekit-server-sdk");

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// ========================================
// Firebase Admin SDK
// ========================================

function initializeFirebase() {
  if (admin.apps.length) {
    return admin.firestore();
  }

  let credential;

  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    let serviceAccount;

    try {
      serviceAccount = JSON.parse(
        process.env.FIREBASE_SERVICE_ACCOUNT_JSON
      );
    } catch (error) {
      throw new Error(
        "FIREBASE_SERVICE_ACCOUNT_JSONをJSONとして読み込めません。"
      );
    }

    if (!serviceAccount.project_id || !serviceAccount.private_key) {
      throw new Error(
        "FirebaseサービスアカウントJSONに必要な項目がありません。"
      );
    }

    credential = admin.credential.cert(serviceAccount);

    admin.initializeApp({
      credential,
      projectId: serviceAccount.project_id
    });
  } else {
    admin.initializeApp({
      credential: admin.credential.applicationDefault(),
      projectId: process.env.GOOGLE_CLOUD_PROJECT || "viewr-3a9f1"
    });
  }

  return admin.firestore();
}

const db = initializeFirebase();
const serverTimestamp = () =>
  admin.firestore.FieldValue.serverTimestamp();

// ========================================
// LiveKit設定
// ========================================

function getLiveKitConfig() {
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  const url = process.env.LIVEKIT_URL;

  if (!apiKey || !apiSecret || !url) {
    throw new Error("LiveKitの環境変数が設定されていません。");
  }

  let parsedUrl;

  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error("LIVEKIT_URLの形式が正しくありません。");
  }

  if (
    parsedUrl.protocol !== "wss:" &&
    parsedUrl.protocol !== "ws:"
  ) {
    throw new Error("LIVEKIT_URLはwss://またはws://で指定してください。");
  }

  return {
    apiKey,
    apiSecret,
    url
  };
}

// ========================================
// デフォルト設定
// ========================================

const DEFAULT_SETTINGS = {
  serviceName: "WEB Course-plus",
  maintenanceMode: false,
  maintenanceMessage: "",
  allowStudentLogin: true,
  allowTeacherLogin: true,
  allowAdminLogin: true
};

// ========================================
// Firestore初期セットアップ
// ========================================

async function initializeDatabase() {
  const settingsRef = db.collection("settings").doc("system");
  const settingsSnap = await settingsRef.get();

  if (!settingsSnap.exists) {
    await settingsRef.create({
      ...DEFAULT_SETTINGS,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    });

    console.log("[Database] settings/system created.");
  } else {
    const current = settingsSnap.data();
    const missing = {};

    for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
      if (!(key in current)) {
        missing[key] = value;
      }
    }

    if (Object.keys(missing).length > 0) {
      missing.updatedAt = serverTimestamp();
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
// Firebase ID Token認証
// ========================================

async function authenticate(req, res, next) {
  try {
    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return sendError(res, 401, "ログイン認証が必要です。");
    }

    const idToken = authorization.slice(7).trim();

    if (!idToken) {
      return sendError(res, 401, "認証トークンがありません。");
    }

    const decoded = await admin.auth().verifyIdToken(idToken);
    const userSnap = await db.collection("users").doc(decoded.uid).get();

    if (!userSnap.exists) {
      return sendError(res, 403, "利用者情報が登録されていません。");
    }

    const profile = userSnap.data();

    if (profile.status !== "active") {
      return sendError(res, 403, "このアカウントは利用できません。");
    }

    if (!["student", "teacher", "admin"].includes(profile.role)) {
      return sendError(res, 403, "アカウントの権限設定が正しくありません。");
    }

    req.user = {
      uid: decoded.uid,
      email: decoded.email || "",
      role: profile.role,
      profile
    };

    next();
  } catch (error) {
    console.error("[Authentication]", error);
    return sendError(res, 401, "ログイン認証に失敗しました。再ログインしてください。");
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
// システム設定
// ========================================

async function getSystemSettings() {
  const snap = await db.collection("settings").doc("system").get();

  if (!snap.exists) {
    return DEFAULT_SETTINGS;
  }

  return {
    ...DEFAULT_SETTINGS,
    ...snap.data()
  };
}

async function checkMaintenance(req, res, next) {
  try {
    const settings = await getSystemSettings();

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
// システム状態
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

app.get("/api/me", authenticate, (req, res) => {
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
});

// ========================================
// LiveKit授業参加トークン発行
// ========================================

app.post(
  "/api/livekit/token",
  authenticate,
  checkMaintenance,
  async (req, res) => {
    try {
      const lessonId = req.body?.lessonId;

      if (
        typeof lessonId !== "string" ||
        !lessonId.trim() ||
        lessonId.length > 150
      ) {
        return sendError(res, 400, "授業IDが正しくありません。");
      }

      const livekit = getLiveKitConfig();

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
        return sendError(res, 403, "この授業に参加する権限がありません。");
      }

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
        return sendError(res, 400, "授業日時の設定が正しくありません。");
      }

      const now = new Date();
      const allowedStart = startAt.getTime() - 5 * 60 * 1000;
      const allowedEnd = endAt.getTime() + 30 * 60 * 1000;

      if (now.getTime() < allowedStart) {
        return sendError(
          res,
          403,
          "授業開始時刻の5分前から参加できます。"
        );
      }

      if (now.getTime() > allowedEnd) {
        return sendError(
          res,
          403,
          "この授業の参加可能時間は終了しました。"
        );
      }

      if (lesson.status === "scheduled" && now >= startAt) {
        await lessonRef.update({
          status: "in_progress",
          updatedAt: serverTimestamp()
        });
      }

      const roomName = `lesson-${lessonId}`;

      const participantName =
        req.user.profile.displayName ||
        req.user.profile.name ||
        req.user.email ||
        req.user.uid;

      const accessToken = new AccessToken(
        livekit.apiKey,
        livekit.apiSecret,
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

      accessToken.addGrant({
        roomJoin: true,
        room: roomName,
        canPublish: true,
        canSubscribe: true,
        canPublishData: true
      });

      const jwt = await accessToken.toJwt();

      console.log(
        `[LiveKit] Token issued: lesson=${lessonId}, role=${req.user.role}`
      );

      // urlとserverUrlの両方を返す。クライアントとの互換性を確保。
      return res.json({
        success: true,
        token: jwt,
        url: livekit.url,
        serverUrl: livekit.url,
        roomName,
        lessonId,
        participantName
      });

    } catch (error) {
      console.error("[LiveKit Token]", error);

      return sendError(
        res,
        500,
        "授業への接続準備に失敗しました。サーバーログを確認してください。"
      );
    }
  }
);

// ========================================
// 管理者：システム設定更新
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
        if (
          field in updates &&
          typeof updates[field] !== "boolean"
        ) {
          return sendError(res, 400, `${field}の値が不正です。`);
        }
      }

      if (
        "maintenanceMessage" in updates &&
        typeof updates.maintenanceMessage !== "string"
      ) {
        return sendError(res, 400, "メッセージの形式が不正です。");
      }

      updates.updatedAt = serverTimestamp();

      await db.collection("settings").doc("system").set(
        updates,
        { merge: true }
      );

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
