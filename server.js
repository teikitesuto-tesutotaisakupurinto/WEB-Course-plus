require("dotenv").config();

const express = require("express");
const path = require("path");
const admin = require("firebase-admin");
const { AccessToken } = require("livekit-server-sdk");

const app = express();

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault()
  });
}

const db = admin.firestore();
const auth = admin.auth();

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "WEB Course-plus" });
});

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return res.status(401).json({ error: "ログインが必要です。" });

    req.user = await auth.verifyIdToken(token);

    const userDoc = await db.collection("users").doc(req.user.uid).get();
    if (!userDoc.exists || userDoc.data().status !== "active") {
      return res.status(403).json({ error: "利用できるアカウントではありません。" });
    }

    req.profile = userDoc.data();
    next();
  } catch {
    res.status(401).json({ error: "認証を確認できませんでした。" });
  }
}

app.post("/api/livekit/token", authenticate, async (req, res) => {
  try {
    const { lessonId } = req.body;

    if (!lessonId || typeof lessonId !== "string") {
      return res.status(400).json({ error: "授業IDが必要です。" });
    }

    const lessonDoc = await db.collection("lessons").doc(lessonId).get();
    if (!lessonDoc.exists) {
      return res.status(404).json({ error: "授業が見つかりません。" });
    }

    const lesson = lessonDoc.data();
    const uid = req.user.uid;
    const role = req.profile.role;

    const authorized =
      (role === "student" && lesson.studentId === uid) ||
      (role === "teacher" && lesson.teacherId === uid) ||
      role === "admin";

    if (!authorized) {
      return res.status(403).json({ error: "この授業に参加する権限がありません。" });
    }

    if (!["scheduled", "in_progress"].includes(lesson.status)) {
      return res.status(403).json({ error: "現在参加できる授業ではありません。" });
    }

    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;
    const serverUrl = process.env.LIVEKIT_URL;

    if (!apiKey || !apiSecret || !serverUrl) {
      return res.status(503).json({ error: "LiveKitの本番設定が完了していません。" });
    }

    const roomName = `lesson-${lessonId}`;
    const participant = new AccessToken(apiKey, apiSecret, {
      identity: uid,
      ttl: "2h"
    });

    participant.addGrant({
      roomJoin: true,
      room: roomName,
      canPublish: true,
      canSubscribe: true,
      canPublishData: true
    });

    res.json({
      token: await participant.toJwt(),
      serverUrl,
      roomName
    });
  } catch (error) {
    console.error("LiveKit token error:", error);
    res.status(500).json({ error: "授業接続の準備に失敗しました。" });
  }
});

const port = Number(process.env.PORT || 3000);

app.listen(port, "0.0.0.0", () => {
  console.log(`WEB Course-plus server running on port ${port}`);
});
