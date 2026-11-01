
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-app.js";

import {
  getAuth,
  GoogleAuthProvider,
  setPersistence,
  browserLocalPersistence
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-auth.js";

import {
  getFirestore,
  serverTimestamp,
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  addDoc,
  updateDoc,
  deleteDoc,
  query,
  where,
  orderBy,
  limit,
  onSnapshot,
  Timestamp
} from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

// ========================================
// Firebase configuration
// ========================================

const firebaseConfig = {
  apiKey: "AIzaSyDp2DSKd6bNGChI24pTjK3wR_iuw2cP-bY",
  authDomain: "viewr-3a9f1.firebaseapp.com",
  projectId: "viewr-3a9f1",
  storageBucket: "viewr-3a9f1.firebasestorage.app",
  messagingSenderId: "152244813389",
  appId: "1:152244813389:web:148327467918012825e604"
};

// ========================================
// Initialize Firebase
// ========================================

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);

// Google authentication provider
export const googleProvider = new GoogleAuthProvider();

googleProvider.setCustomParameters({
  prompt: "select_account"
});

// ========================================
// Authentication persistence
// ========================================

export const authPersistenceReady = setPersistence(
  auth,
  browserLocalPersistence
);

// ========================================
// Firestore utilities
// ========================================

export {
  serverTimestamp,
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  addDoc,
  updateDoc,
  deleteDoc,
  query,
  where,
  orderBy,
  limit,
  onSnapshot,
  Timestamp
};

// ========================================
// Application information
// ========================================

export const APP_NAME = "WEB Course-plus";

export const APP_VERSION = "1.0.0";

export default app;
