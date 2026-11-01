import { initializeApp } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-app.js";

import {
  getAuth,
  GoogleAuthProvider
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

import {
  getFirestore
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyDp2DSKd6bNGChI24pTjK3wR_iuw2cP-bY",
  authDomain: "viewr-3a9f1.firebaseapp.com",
  projectId: "viewr-3a9f1",
  storageBucket: "viewr-3a9f1.firebasestorage.app",
  messagingSenderId: "152244813389",
  appId: "1:152244813389:web:148327467918012825e604"
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();

googleProvider.setCustomParameters({
  prompt: "select_account"
});

export default app;
