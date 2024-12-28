import express, { json } from 'express';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import admin from "firebase-admin";
import serviceAccountKey from "./blogging-web-2dc3d-firebase-adminsdk-c3zcg-385b601b83.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";

// Schema import
import User from "./Schema/User.js";

const server = express();
let PORT = 3000;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

// Regex patterns
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());
server.use(cors());

// Connecting to MongoDB
mongoose.connect(process.env.DB_LOCATION, { autoIndex: true });

// Utility functions
const formateDatatoSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );

  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

const generateUsername = async (email) => {
  let username = email.split("@")[0];
  let UsernameExists = await User.exists({
    "personal_info.username": username,
  });
  if (UsernameExists) {
    username += nanoid().substring(0, 5);
  }
  return username;
};

// Signup Route
server.post("/signup", async (req, res) => {
  try {
    const { fullname, email, password } = req.body;

    if (fullname.length < 3) {
      return res
        .status(403)
        .json({ error: "Fullname must be at least 3 letters long" });
    }
    if (!emailRegex.test(email)) {
      return res.status(403).json({ error: "Email is invalid" });
    }
    if (!passwordRegex.test(password)) {
      return res.status(403).json({
        error:
          "Password should be 6 to 20 characters long with a numeric value, 1 lowercase, and 1 uppercase letter",
      });
    }

    const hashed_password = await bcrypt.hash(password, 10);
    const username = await generateUsername(email);

    const user = new User({
      personal_info: { fullname, email, password: hashed_password, username },
    });

    const savedUser = await user.save();
    return res.status(200).json(formateDatatoSend(savedUser));
  } catch (err) {
    if (err.code === 11000) {
      return res.status(500).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: err.message });
  }
});

// Signin Route
server.post("/signin", (req, res) => {
  const { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email is not found" });
      }

      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res
              .status(403)
              .json({ error: "Error occurred while logging in. Please try again." });
          }
          if (!result) {
            return res.status(403).json({ error: "Password is incorrect" });
          }
          return res.status(200).json(formateDatatoSend(user));
        });
      } else {
        return res.status(403).json({
          error: "Account was created using Google. Try logging in with Google.",
        });
      }
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

// Google Auth Route
server.post("/google-auth", async (req, res) => {
  const { access_token } = req.body;

  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      const { email, name, picture } = decodedUser;
      const updatedPicture = picture.replace("s96-c", "s384-c");

      let user = await User.findOne({ "personal_info.email": email })
        .select("personal_info.fullname personal_info.username personal_info.profile_img google_auth")
        .then((u) => u || null)
        .catch((err) => res.status(500).json({ error: err.message }));

      if (user) {
        if (!user.google_auth) {
          return res.status(403).json({
            error: "This email was signed up without Google. Log in with a password to access the account.",
          });
        }
      } else {
        const username = await generateUsername(email);

        user = new User({
          personal_info: {
            fullname: name,
            email,
            username,
            profile_img: updatedPicture,
          },
          google_auth: true,
        });

        await user.save().catch((err) => {
          return res.status(500).json({ error: err.message });
        });
      }

      return res.status(200).json(formateDatatoSend(user));
    })
    .catch(() => {
      return res.status(500).json({
        error: "Failed to authenticate with Google. Try using another account.",
      });
    });
});

// Start the server
server.listen(PORT, () => {
  console.log("Listening on port " + PORT);
});
