const passport = require('passport');
const passportJWT = require("passport-jwt");
require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const app = express();
const cors = require("cors");
const userService = require("./user-service.js");
const jwt = require('jsonwebtoken');

let ExtractJwt = passportJWT.ExtractJwt;
let JwtStrategy = passportJWT.Strategy;

let jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("JWT");
jwtOptions.secretOrKey = process.env.JWT_SECRET;

let strategy = new JwtStrategy(jwtOptions, (jwt_payload, next) => {
  if (jwt_payload) {
    return next(null, jwt_payload);
  } else {
    return next(null, false);
  }
});

passport.use(strategy);
app.use(passport.initialize());

mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log("MongoDB connected");
  })
  .catch((err) => {
    console.log("MongoDB error:", err);
  });
  
const HTTP_PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(cors());

app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
    .then((msg) => {
        res.json({ "message": msg });
    }).catch((msg) => {
        res.status(422).json({ "message": msg });
    });
});

app.post("/api/user/login", (req, res) => {
  userService.checkUser(req.body)
  .then((user) => {
   console.log(user);
    const payload = {
      _id: user._id,
      userName: user.userName
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET);

    res.json({ "message": "login successful", token });

  }).catch(msg => {
    res.status(422).json({ "message": msg });
  });
});

app.get("/api/user/favourites", passport.authenticate('jwt', { session: false }), (req, res) => {
  userService.getFavourites(req.user._id)
    .then(data => res.json(data))
    .catch(err => res.status(500).json(err));
});

app.put("/api/user/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
  userService.addFavourite(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(err => res.status(500).json(err));
});

app.delete("/api/user/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
  userService.removeFavourite(req.user._id, req.params.id)
    .then(data => res.json(data))
    .catch(err => res.status(500).json(err));
});

userService.connect()
.then(() => {
    app.listen(HTTP_PORT, () => { console.log("API listening on: " + HTTP_PORT) });
})
.catch((err) => {
    console.log("unable to start the server: " + err);
    process.exit();
});