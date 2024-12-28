
import { initializeApp } from "firebase/app";
import {getAuth, GoogleAuthProvider, signInWithPopup} from "firebase/auth"

const firebaseConfig = {
  apiKey: "AIzaSyCeonVP1_YEZ4Zez21sY8NxlAk9RyKYaDg",
  authDomain: "blogging-web-2dc3d.firebaseapp.com",
  projectId: "blogging-web-2dc3d",
  storageBucket: "blogging-web-2dc3d.firebasestorage.app",
  messagingSenderId: "73217396033",
  appId: "1:73217396033:web:864a8bcd00ffed568265c0"
};


const app = initializeApp(firebaseConfig);

//google auth
const provider = new GoogleAuthProvider();

const auth =  getAuth();

export const authWithGoogle = async () => {
  let user = null;

  await signInWithPopup(auth, provider)
    .then((result) => {
      user = result.user;
    })
    .catch((error) => {
      console.log(error);
    });

  return user;
};
