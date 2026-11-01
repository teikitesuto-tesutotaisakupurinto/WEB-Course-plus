import { auth, db } from "./firebase.js";

import {
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

export const Auth = {
  async getCurrentUser() {
    const user = auth.currentUser;

    if (!user) {
      throw new Error("ログインが必要です。");
    }

    const token = await user.getIdToken();

    return {
      uid: user.uid,
      email: user.email,
      token
    };
  },

  async getProfile(uid) {
    const snapshot = await getDoc(doc(db, "users", uid));

    if (!snapshot.exists()) {
      throw new Error("アカウント情報がありません。");
    }

    const profile = snapshot.data();

    if (profile.status !== "active") {
      throw new Error("このアカウントは利用できません。");
    }

    return profile;
  },

  async requireRole(expectedRole) {
    return new Promise((resolve, reject) => {
      const unsubscribe = onAuthStateChanged(auth, async user => {
        unsubscribe();

        if (!user) {
          location.replace(`/${expectedRole}/login.html`);
          return reject(new Error("ログインが必要です。"));
        }

        try {
          const profile = await this.getProfile(user.uid);

          if (profile.role !== expectedRole && profile.role !== "admin") {
            location.replace("/");
            return reject(new Error("アクセス権限がありません。"));
          }

          resolve({ user, profile });
        } catch (error) {
          await signOut(auth);
          location.replace(`/${expectedRole}/login.html`);
          reject(error);
        }
      });
    });
  },

  async logout() {
    await signOut(auth);
    location.replace("/");
  }
};

export async function getAccessToken() {
  const user = auth.currentUser;

  if (!user) {
    throw new Error("ログインしてください。");
  }

  return user.getIdToken();
}
