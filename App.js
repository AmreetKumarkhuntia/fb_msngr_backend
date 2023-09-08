const express = require('express');
const cors = require('cors');
const Facebook = require('facebook-js-sdk');
const fetch = require('node-fetch');
const mongo = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const port = process.env.PORT || 8080;
const app_id = process.env.APP_ID;
const app_secret = process.env.APP_SECRET;
const jwt_secret = process.env.JWT_SECRET;
const monogo_URL = process.env.MONGO_URL;
const frontend_URL = process.env.FRONTEND_URL;
const salt = bcrypt.genSaltSync(10);

//SETUP APP
const app = express();
const cors_options = {
    origin: frontend_URL,
    Credentials: true,
};
app.use(cors(cors_options));

//SCHEMA SETUP

const userSchema = new mongo.Schema({
    email: {
        type: String,
        unique: [true, 'Email already available']
    },
    name: String,
    password: String,
    facebookId: String,
    pageName: String,
    accessToken: String,
    status: String,
});

const user = mongo.model('user', userSchema);

//MONGO DB SETUP

async function connectDB() {
    await mongo.connect(monogo_URL);
    console.log('connected to database :)');
}

//FACEBOOK LOGIN SETUP
app.get("/facebook/login", function (req, res) {
    // step 1: initialize Facebook class with config
    const currEmail = req.query.email;

    const facebook = new Facebook({
        appId: app_id,
        appSecret: app_secret,
        redirectUrl: `http://localhost:2000/facebook/callback/${currEmail}`,
        graphVersion: "v17.0",
    });


    // step 2: get Facebook oauth login URL using facebook.getLoginUrl()
    const url = facebook.getLoginUrl(["email"]);

    res.status(200).send({
        LoginURL: url
    });
});

// step 3: oauth login redirects back to callback page and we send code GET param to facebook.callback() and fetch access_token
app.get("/facebook/callback/:email", async function (req, res) {
    try{

        const currEmail = req.params.email;
    
        const facebook = new Facebook({
            appId: app_id,
            appSecret: app_secret,
            redirectUrl: `http://localhost:2000/facebook/callback/${currEmail}`,
            graphVersion: "v17.0",
        });
    
        if (req.query.code) {
            facebook
                .callback(req.query.code)
                .then((response) => {
                    const user_access_token = response.data.access_token;
                    const base_url = `https://graph.facebook.com/`;
    
                    fetch(`${base_url}oauth/access_token?grant_type=fb_exchange_token&
                    client_id=${app_id}&
                    client_secret=${app_secret}&
                    fb_exchange_token=${user_access_token}`).then(res => res.json()).then(
                        async res => {
                            const LongLiveAccessToken = res.access_token;
    
                            await user.updateOne({ email: currEmail }, {
                                accessToken: LongLiveAccessToken
                            });
    
                            fetch(`https://graph.facebook.com/v17.0/me?access_token=${LongLiveAccessToken}`).then(res => res.json()).then(async res => {
                                await user.updateOne({ email: currEmail }, {
                                    facebookId: res.id,
                                    pageName: res.name,
                                    status: "connected",
                                });
    
                            })
                        }
                    );
                    res.redirect('http://localhost:3000/login');
                })
                .catch((error) => {
                    res.send(error.response.data);
                });
        }
    }
    catch (error) {
        res.status(404).send(error);
    }
});

app.delete("/facebook/logout", async function (req, res) {

    try{
        const email = req.query.email;
    
        await user.updateOne({ email: email }, {
            facebookId: null,
            pageName: null,
            accessToken: null,
            status: 'not connected',
        });
    
        const result = await user.findOne({ email: email });
    
        res.status(200).send({
            email: result.email,
            name: result.name,
            facebookId: result.facebookId,
            pageName: result.pageName,
            accessToken: result.accessToken,
            status: result.status,
    
        });
    }
    catch(err){
        res.send(404).send({Error: err});
    }
});

//sign up request
app.post('/signup', async (reqs, res) => {
    try {
        const req = reqs.query;

        //creating user
        const new_user = user({
            email: req.email,
            name: req.name,
            password: bcrypt.hashSync(req.password,salt),
            facebookId: null,
            pageName: null,
            accessToken: null,
            status: "not connected",
        });

        const result = await user.find({ email: new_user.email });

        if (result.length > 0) {
            res.status(500).send({ Error: "User already exists" });
        }
        else {
            new_user.save();
            var para = {
                Error: "None"
            }
            res.status(200).send(para);
        }
    }
    catch(err) {
        res.status(404).send({ Error: err });
    }
});

//login request
app.get('/login', async (req, res) => {
    try {
        console.log(req.cookies);

        const check_user = req.query;

        const userFound = await user.findOne({ email: check_user.email });

        if (userFound != null && userFound.email === check_user.email) {
            if (bcrypt.compareSync(check_user.password, userFound.password)) {

                const sentParameters = {
                    email: userFound.email,
                    name: userFound.name,
                    facebookId: userFound.facebookId,
                    pageName: userFound.pageName,
                    accessToken: userFound.accessToken,
                    status: userFound.status,
                    Error: "None",
                    Login: true,
                };

                jwt.sign(
                    {
                      email: userFound.email,
                      id: userFound._id,
                    },
                    jwt_secret,
                    {},
                    (err, token) => {
                      if (err) throw err;

                      res.cookie("token", token).json(sentParameters);
                    }
                  );
            }
            else {
                const sentParameters = {
                    email: userFound.email,
                    name: userFound.name,
                    Error: "Password Incorrect",
                    Login: false,
                };
                res.status(422).json(sentParameters);
            }
        }
        else {
            res.status(422).json({
                Error: "user doesn't exist",
                Login: false,
            });
        }
    }
    catch (err){
        console.log(err);
        res.status(404).send({ Error: err });
    }

});


//port on which to connect
app.listen(port, async () => {
    try{
        connectDB().catch(err => { console.log(err) });
        console.log("listening on port " + port);
    }
    catch(err){
        console.log(err);
    }
});