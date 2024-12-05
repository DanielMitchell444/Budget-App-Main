// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import { getAuth, GoogleAuthProvider, signInWithPopup } from "firebase/auth"
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyCaUm8HcEpHWsHg9wkoUXMiurJMh7Q9Gqk",
  authDomain: "budget-app-119b0.firebaseapp.com",
  projectId: "budget-app-119b0",
  storageBucket: "budget-app-119b0.firebasestorage.app",
  messagingSenderId: "885418135964",
  appId: "1:885418135964:web:c37a5acae908438a977859",
  measurementId: "G-LB2FQ4J5MC"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();

export { auth, googleProvider, signInWithPopup };