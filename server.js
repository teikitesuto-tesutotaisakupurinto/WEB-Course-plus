"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const admin = require("firebase-admin");
const { AccessToken } = require("livekit-server-sdk");

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 1. 基本設定
// ==========================================

app.disable("x-powered-by");

app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
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

// ==========================================
// 3. Firebase Admin 初期化
// ==========================================

if (!FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.error(
    "FIREBASE_SERVICE_ACCOUNT_JSON が設定されていません。"
  );
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
  console.error("FirebaseサービスアカウントJSONの解析に失敗しました。");
  console.error(error.message);
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

// ==========================================
// 4. LiveKit設定確認
// ==========================================

if (!LIVEKIT_API_KEY || !LIVEKIT_API_SECRET || !LIVEKIT_URL) {
  console.error("LiveKitの環境変数が不足しています。");
  process.exit(1);
}

// ==========================================
// 5. Firestore初期化
// ==========================================

async function initializeFirestore() {
  const systemRef = db.collection("settings").doc("system");
  const systemSnapshot = await systemRef.get();

  if (!systemSnapshot.exists) {
    await systemRef.set({
      maintenance: false,
      maintenanceMessage: "",
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });

    console.log("Firestore: settings/system を作成しました。");
  } else {
    console.log("Firestore: settings/system を確認しました。");
  }
}

// ==========================================
// 6. 共通関数
// ==========================================

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message
  });
}

function getBearerToken(req) {
  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return null;
  }

  return authorization.slice(7).trim();
}

function isActiveProfile(profile) {
  if (!profile) return false;

  if (profile.active === false) return false;

  if (
    ["inactive", "disabled", "suspended", "deleted"]
      .includes(String(profile.status || "").toLowerCase())
  ) {
    return false;
  }

  return true;
}

function isValidRole(role) {
  return ["admin", "teacher", "student"].includes(role);
}

function toSafeUser(doc) {
  const data = doc.data();

  return {
    uid: doc.id,
    email: data.email || "",
    displayName: data.displayName || "",
    role: data.role || "",
    status: data.status || "active",
    active: data.active !== false
  };
}

// ==========================================
// 7. Firebase認証ミドルウェア
// ==========================================

async function authenticate(req, res, next) {
  try {
    const idToken = getBearerToken(req);

    if (!idToken) {
      return sendError(res, 401, "ログインが必要です。");
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);

    const userRef = db.collection("users").doc(decodedToken.uid);
    const userSnapshot = await userRef.get();

    if (!userSnapshot.exists) {
      return sendError(
        res,
        403,
        "ユーザー情報が登録されていません。"
      );
    }

    const profile = userSnapshot.data();

    if (!isActiveProfile(profile)) {
      return sendError(
        res,
        403,
        "このアカウントは利用停止中です。"
      );
    }

    if (!isValidRole(profile.role)) {
      return sendError(
        res,
        403,
        "ユーザー権限が正しくありません。"
      );
    }

    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email || profile.email || null,
      profile
    };

    return next();
  } catch (error) {
    console.error("認証エラー:", error.message);

    return sendError(
      res,
      401,
      "認証に失敗しました。再度ログインしてください。"
    );
  }
}

// ==========================================
// 8. 管理者権限確認
// ==========================================

function requireAdmin(req, res, next) {
  if (req.user?.profile?.role !== "admin") {
    return sendError(res, 403, "管理者権限が必要です。");
  }

  return next();
}

// ==========================================
// 9. 管理者操作ログ
// ==========================================

async function writeAdminLog(
  req,
  action,
  targetUid = null,
  details = {}
) {
  await db.collection("adminLogs").add({
    adminUid: req.user.uid,
    adminEmail: req.user.email || "",
    action,
    targetUid,
    details,
    createdAt: FieldValue.serverTimestamp()
  });
}

// ==========================================
// 10. ヘルスチェック
// UptimeRobotからアクセスするURL
// ==========================================

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    service: "WEB Course-plus",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "ok",
    service: "WEB Course-plus",
    timestamp: new Date().toISOString()
  });
});

// ==========================================
// 11. システム状態取得
// ログイン前のメンテナンス確認用
// ==========================================

app.get("/api/system/status", async (req, res) => {
  try {
    const snapshot = await db
      .collection("settings")
      .doc("system")
      .get();

    if (!snapshot.exists) {
      return res.json({
        success: true,
        maintenance: false,
        maintenanceMessage: ""
      });
    }

    const settings = snapshot.data();

    return res.json({
      success: true,
      maintenance: settings.maintenance === true,
      maintenanceMessage: settings.maintenanceMessage || ""
    });
  } catch (error) {
    console.error("システム状態取得エラー:", error);

    return sendError(
      res,
      500,
      "システム状態を取得できませんでした。"
    );
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
      displayName: req.user.profile.displayName || "",
      status: req.user.profile.status || "active"
    }
  });
});

// ==========================================
// 13. 管理者：システム概要
// ==========================================

app.get(
  "/api/admin/overview",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const usersSnapshot = await db.collection("users").get();

      const overview = {
        totalUsers: usersSnapshot.size,
        admins: 0,
        teachers: 0,
        students: 0,
        activeUsers: 0,
        inactiveUsers: 0
      };

      usersSnapshot.forEach((doc) => {
        const user = doc.data();

        if (user.role === "admin") overview.admins++;
        if (user.role === "teacher") overview.teachers++;
        if (user.role === "student") overview.students++;

        if (isActiveProfile(user)) {
          overview.activeUsers++;
        } else {
          overview.inactiveUsers++;
        }
      });

      return res.json({
        success: true,
        overview
      });
    } catch (error) {
      console.error("管理者概要取得エラー:", error);

      return sendError(
        res,
        500,
        "システム概要を取得できませんでした。"
      );
    }
  }
);

// ==========================================
// 14. 管理者：ユーザー一覧
// ==========================================

app.get(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const limit = Math.min(
        Math.max(Number(req.query.limit) || 100, 1),
        200
      );

      const snapshot = await db
        .collection("users")
        .limit(limit)
        .get();

      const users = snapshot.docs.map(toSafeUser);

      return res.json({
        success: true,
        users,
        count: users.length
      });
    } catch (error) {
      console.error("ユーザー一覧取得エラー:", error);

      return sendError(
        res,
        500,
        "ユーザー一覧を取得できませんでした。"
      );
    }
  }
);

// ==========================================
// 15. 管理者：ユーザー情報変更
// ==========================================

app.patch(
  "/api/admin/users/:uid",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const targetUid = String(req.params.uid || "").trim();

      if (!targetUid || targetUid.length > 128) {
        return sendError(
          res,
          400,
          "ユーザーIDが正しくありません。"
        );
      }

      if (targetUid === req.user.uid) {
        return sendError(
          res,
          400,
          "自分自身のアカウントは変更できません。"
        );
      }

      const userRef = db.collection("users").doc(targetUid);
      const userSnapshot = await userRef.get();

      if (!userSnapshot.exists) {
        return sendError(res, 404, "ユーザーが見つかりません。");
      }

      const targetUser = userSnapshot.data();

      // 既存の管理者アカウントは変更対象外
      if (targetUser.role === "admin") {
        return sendError(
          res,
          403,
          "システム管理者のアカウントはこの画面から変更できません。"
        );
      }

      const updates = {};
      const logDetails = {};

      // 権限変更
      if (req.body.role !== undefined) {
        if (!["teacher", "student"].includes(req.body.role)) {
          return sendError(
            res,
            400,
            "指定できる権限はteacherまたはstudentです。"
          );
        }

        updates.role = req.body.role;
        logDetails.role = req.body.role;
      }

      // 利用状態変更
      if (req.body.status !== undefined) {
        if (!["active", "suspended"].includes(req.body.status)) {
          return sendError(
            res,
            400,
            "statusはactiveまたはsuspendedを指定してください。"
          );
        }

        updates.status = req.body.status;
        updates.active = req.body.status === "active";

        logDetails.status = req.body.status;
        logDetails.active = updates.active;
      }

      // 表示名変更
      if (req.body.displayName !== undefined) {
        if (typeof req.body.displayName !== "string") {
          return sendError(
            res,
            400,
            "表示名が正しくありません。"
          );
        }

        updates.displayName =
          req.body.displayName.trim().slice(0, 100);

        logDetails.displayName = updates.displayName;
      }

      if (Object.keys(updates).length === 0) {
        return sendError(
          res,
          400,
          "変更する項目がありません。"
        );
      }

      // Firebase Authenticationの利用停止状態も変更
      if (typeof updates.active === "boolean") {
        await admin.auth().updateUser(targetUid, {
          disabled: !updates.active
        });
      }

      updates.updatedAt = FieldValue.serverTimestamp();

      await userRef.update(updates);

      await writeAdminLog(
        req,
        "user_updated",
        targetUid,
        logDetails
      );

      return res.json({
        success: true,
        message: "ユーザー情報を更新しました。"
      });
    } catch (error) {
      console.error("ユーザー更新エラー:", error);

      return sendError(
        res,
        500,
        "ユーザー情報を更新できませんでした。"
      );
    }
  }
);

// ==========================================
// 16. 管理者：システム設定取得
// ==========================================

app.get(
  "/api/admin/settings",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const snapshot = await db
        .collection("settings")
        .doc("system")
        .get();

      const settings = snapshot.exists
        ? snapshot.data()
        : {};

      return res.json({
        success: true,
        settings: {
          maintenance: settings.maintenance === true,
          maintenanceMessage: settings.maintenanceMessage || ""
        }
      });
    } catch (error) {
      console.error("管理者設定取得エラー:", error);

      return sendError(
        res,
        500,
        "設定を取得できませんでした。"
      );
    }
  }
);

// ==========================================
// 17. 管理者：システム設定変更
// ==========================================

app.patch(
  "/api/admin/settings",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const updates = {};
      const logDetails = {};

      if (typeof req.body.maintenance === "boolean") {
        updates.maintenance = req.body.maintenance;
        logDetails.maintenance = req.body.maintenance;
      }

      if (typeof req.body.maintenanceMessage === "string") {
        updates.maintenanceMessage =
          req.body.maintenanceMessage.slice(0, 1000);

        logDetails.maintenanceMessage =
          updates.maintenanceMessage;
      }

      if (Object.keys(updates).length === 0) {
        return sendError(
          res,
          400,
          "変更する設定がありません。"
        );
      }

      updates.updatedAt = FieldValue.serverTimestamp();

      await db
        .collection("settings")
        .doc("system")
        .set(updates, { merge: true });

      await writeAdminLog(
        req,
        "system_settings_updated",
        null,
        logDetails
      );

      return res.json({
        success: true,
        message: "システム設定を更新しました。"
      });
    } catch (error) {
      console.error("設定変更エラー:", error);

      return sendError(
        res,
        500,
        "設定を更新できませんでした。"
      );
    }
  }
);

// ==========================================
// 18. 管理者：操作ログ一覧
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

      const snapshot = await db
        .collection("adminLogs")
        .orderBy("createdAt", "desc")
        .limit(limit)
        .get();

      const logs = snapshot.docs.map((doc) => {
        const data = doc.data();

        return {
          id: doc.id,
          adminUid: data.adminUid || "",
          adminEmail: data.adminEmail || "",
          action: data.action || "",
          targetUid: data.targetUid || null,
          details: data.details || {},
          createdAt: data.createdAt
            ? data.createdAt.toDate().toISOString()
            : null
        };
      });

      return res.json({
        success: true,
        logs
      });
    } catch (error) {
      console.error("管理ログ取得エラー:", error);

      return sendError(
        res,
        500,
        "操作ログを取得できませんでした。"
      );
    }
  }
);

// ==========================================
// 19. 日時変換
// ==========================================

function toDate(value) {
  if (!value) return null;

  if (value instanceof Date) {
    return value;
  }

  if (typeof value.toDate === "function") {
    return value.toDate();
  }

  if (typeof value === "number") {
    return new Date(value);
  }

  if (typeof value === "string") {
    const parsed = new Date(value);

    return Number.isNaN(parsed.getTime())
      ? null
      : parsed;
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

    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
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

    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }

  if (start && Number(lesson.durationMinutes) > 0) {
    return new Date(
      start.getTime() +
      Number(lesson.durationMinutes) * 60000
    );
  }

  return null;
}

// ==========================================
// 20. LiveKit授業参加トークン発行
// ==========================================

app.post(
  "/api/livekit/token",
  authenticate,
  async (req, res) => {
    try {
      const profile = req.user.profile;
      const uid = req.user.uid;

      // adminは授業機能を利用できない
      // 授業情報を取得する前に拒否する
      if (profile.role === "admin") {
        return sendError(
          res,
          403,
          "システム管理者は授業に参加できません。"
        );
      }

      const lessonId = String(req.body.lessonId || "").trim();

      if (!lessonId) {
        return sendError(
          res,
          400,
          "授業IDが指定されていません。"
        );
      }

      if (lessonId.length > 150) {
        return sendError(
          res,
          400,
          "授業IDが正しくありません。"
        );
      }

      // 授業情報を取得
      const lessonRef = db.collection("lessons").doc(lessonId);
      const lessonSnapshot = await lessonRef.get();

      if (!lessonSnapshot.exists) {
        return sendError(res, 404, "授業が見つかりません。");
      }

      const lesson = lessonSnapshot.data();

      // 授業への参加権限を確認
      const isTeacher = profile.role === "teacher";

      const isStudent =
        profile.role === "student" &&
        lesson.studentId === uid;

      if (!isTeacher && !isStudent) {
        return sendError(
          res,
          403,
          "この授業に参加する権限がありません。"
        );
      }

      // 授業状態を確認
      const allowedStatuses = [
        "scheduled",
        "in_progress"
      ];

      if (!allowedStatuses.includes(lesson.status)) {
        return sendError(
          res,
          403,
          "現在この授業には入室できません。"
        );
      }

      // 授業開始5分前から終了30分後まで入室可能
      const start = getLessonStart(lesson);
      const end = getLessonEnd(lesson, start);
      const now = Date.now();

      if (
        start &&
        now < start.getTime() - 5 * 60 * 1000
      ) {
        return sendError(
          res,
          403,
          "授業開始5分前から入室できます。"
        );
      }

      if (
        end &&
        now > end.getTime() + 30 * 60 * 1000
      ) {
        return sendError(
          res,
          403,
          "この授業の入室可能時間は終了しました。"
        );
      }

      // LiveKitルーム名
      const roomName = `lesson-${lessonId}`;

      const displayName =
        profile.displayName ||
        req.user.email ||
        (profile.role === "teacher" ? "先生" : "生徒");

      // LiveKitアクセストークン作成
      const accessToken = new AccessToken(
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

      accessToken.addGrant({
        roomJoin: true,
        room: roomName,
        canPublish: true,
        canSubscribe: true,
        canPublishData: true
      });

      const token = await accessToken.toJwt();

      return res.json({
        success: true,
        url: LIVEKIT_URL,
        token,
        roomName,
        identity: uid,
        name: displayName
      });

    } catch (error) {
      console.error("LiveKitトークン発行エラー:", error);

      return sendError(
        res,
        500,
        "授業室への接続準備に失敗しました。"
      );
    }
  }
);

// ==========================================
// 21. 静的ファイル配信
// ==========================================

const publicDirectory = path.join(__dirname, "public");

if (fs.existsSync(publicDirectory)) {
  app.use(
    express.static(publicDirectory, {
      index: false,
      extensions: ["html"],
      maxAge: "1h"
    })
  );

  app.get("/", (req, res) => {
    const loginPath = path.join(
      publicDirectory,
      "login.html"
    );

    const indexPath = path.join(
      publicDirectory,
      "index.html"
    );

    if (fs.existsSync(loginPath)) {
      return res.sendFile(loginPath);
    }

    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }

    return res.status(404).send("WEB Course-plus");
  });
}

// ==========================================
// 22. API 404
// ==========================================

app.use("/api", (req, res) => {
  sendError(res, 404, "指定されたAPIは存在しません。");
});

// ==========================================
// 23. その他の404
// ==========================================

app.use((req, res) => {
  res.status(404).send("ページが見つかりません。");
});

// ==========================================
// 24. エラー処理
// ==========================================

app.use((error, req, res, next) => {
  console.error("サーバーエラー:", error);

  if (res.headersSent) {
    return next(error);
  }

  return sendError(
    res,
    500,
    "サーバー内部でエラーが発生しました。"
  );
});

// ==========================================
// 25. サーバー起動
// ==========================================

async function startServer() {
  try {
    await initializeFirestore();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("--------------------------------------");
      console.log("WEB Course-plus");
      console.log("Server: running");
      console.log(`Port: ${PORT}`);
      console.log("Firebase: initialized");
      console.log("Firestore: initialized");
      console.log("LiveKit: configured");
      console.log("Admin API: enabled");
      console.log("Health: /health");
      console.log("--------------------------------------");
    });
  } catch (error) {
    console.error("サーバー起動に失敗しました:", error);
    process.exit(1);
  }
}

startServer();
