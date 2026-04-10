require('dotenv').config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();


const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;


const jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("JWT");


jwtOptions.secretOrKey = process.env.JWT_SECRET || "fallbackSecret";

const strategy = new JwtStrategy(jwtOptions, (jwt_payload, next) => {
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

app.use(express.json());
app.use(cors());


const User = mongoose.model("User", new mongoose.Schema({
  userName: String,
  password: String,
  favourites: [String],
}));




app.post("/api/user/register", async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
      userName: req.body.userName,
      password: hash,
      favourites: [],
    });

    await newUser.save();

    res.json({ message: "User created" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.post("/api/user/login", async (req, res) => {
  try {
    const user = await User.findOne({ userName: req.body.userName });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const valid = await bcrypt.compare(req.body.password, user.password);

    if (!valid) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const payload = {
      _id: user._id,
      userName: user.userName,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET || "fallbackSecret");

    res.json({ message: "Login successful", token: token });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.get("/api/user/favourites",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {

    const user = await User.findById(req.user._id);

    res.json(user.favourites);
  }
);


app.put("/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {

    await User.updateOne(
      { _id: req.user._id },
      { $addToSet: { favourites: req.params.id } }
    );

    res.json({ message: "Added to favourites" });
  }
);


app.delete("/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {

    await User.updateOne(
      { _id: req.user._id },
      { $pull: { favourites: req.params.id } }
    );

    res.json({ message: "Removed from favourites" });
  }
);


const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});