import express, { json } from 'express'
import mongoose from 'mongoose'
import 'dotenv/config'
import bcrypt from 'bcrypt'
import { nanoid } from 'nanoid'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import admin from "firebase-admin"
import seviceAccountKey from "./blogging-web-2dc3d-firebase-adminsdk-c3zcg-385b601b83.json" assert { type: "json"}
import { getAuth} from "firebase-admin/auth"

//Schema below
import User from './Schema/User.js'

const server = express();
let PORT = 3000;

admin.initializeApp({
    credential: admin.credential.cert(seviceAccountKey)
})

let emailRegex = /^\w+([\.-]?\w+)@\w+([\.-]?\w+)(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.\d)(?=.[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors());

//connecting to database
mongoose.connect(process.env.DB_LOCATION,{
    autoIndex: true
})
// mongoose.connect(process.env.DB_LOCATION, { autoIndex: true })
//   .then(() => console.log("Connected to MongoDB"))
//   .catch((err) => {
//     console.error("Failed to connect to MongoDB:", err.message);
//   });

const formateDatatoSend = (user) => {

    const access_token = jwt.sign({id: user._id}, process.env.SECRET_ACCESS_KEY)

    return{
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname
    }
}

const generateUsername = async (email) => {
    let username = email.split("@")[0];

    let UsernameExists = await User.exists({"personal_info.username" : username}).then((result) => result);

    UsernameExists ? username += nanoid().substring(0, 5) : "";

    return username;
}

//signup
server.post("/signup", (req,res) => {
    let {fullname, email , password} = req.body;

    //validating data from fronted
    if(fullname.length < 3){
        return res.status(403).json({"error" : "Fullname must be atleast 3 letters long"}) 
    }
    if(!email.length){
        return res.status(403).json({"error":"Enter Email"})
    }
    if(!emailRegex.test(email)){
        return res.status(403).json({"error": "Email is invalid"})
    }
    if(!passwordRegex.test(password)){
        return res.status(403).json({"error": "password should be 6 to 20 character long with numeric, 1 lowercase and 1 uppercase letters"})
    }

     bcrypt.hash(password, 10, async (err, hashed_password) => {
        let username = await generateUsername(email);
        let user = new User({
            personal_info: { fullname, email, password: hashed_password, username}
        })

        user.save().then((u) => {
            return res.status(200).json(formateDatatoSend(u))
        })

        .catch(err => {
            if(err.code == 11000){
                return res.status(500).json({"error": "Email already exists"})
            }

            return res.status(500).json({"error": err.message})
        })
     })
    // return res.status(200).json({"status": "okay"})
})

//signin process
server.post("/signin", (req, res) => {
    let {email , password} = req.body;

    User.findOne({"personal_info.email": email})
    .then((user) => {
        if(!user){
            return res.status(403).json({"error": "Email is not found"})
        }

        if(!user.google_auth){
            bcrypt.compare(password, user.personal_info.password, (err, result) => {
                if(err){
                    return res.status(403).json({"error": "Error occured while login plese try again"})
                }
                if(!result){
                    return res.status(403).json({"error": "Password is incorrect"})
                }else{
                    return res.status(200).json(formateDatatoSend(user))
                }
            })

        }else{
            return res.status(403).json({"error": "Acount was created using google. Try logging in with google"});
        }

    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({"error": err.message})
    })
})

server.post("/google-auth", async(req, res) => {
    let { access_token } = req.body;

    getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
        let { email, name, picture} = decodedUser;

        picture = picture.replace("s96-c", "s384-c");

        let user = await User.findOne({"personal_info.email": email}).select("personal_info.fullname personal_info.usename personal_info.profile_img google_auth").then((u) => {
            return u || null
        })
        .catch(err => {
            return res.status(500).json({"error": err.message})
        })

        if(user){//login
            if(!user.google_auth){
                return res.status(403).json({"error": "This email was signed up without google. Please log in with password to access the account"});
            }
        }
        else{//signup
            let username = await generateUsername(email);

            user = new User({
                personal_info: { fullname: name, email, username},
                google_auth: true
            })

            await user.save().then((u) => {
                user = u;
            })
            .catch(err => {
                return res.status(500).json({ "error" : err.message});
            })
        }

        return res.status(200).json(formateDatatoSend(user));
    })
    .catch(err => {
        return res.status(500).json({"error" : "Failed to authenticate you with google. Try with some other google account"});
    })
})


server.listen(PORT, () => {
    console.log('listing ->' + PORT );
})