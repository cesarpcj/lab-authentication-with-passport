"use strict";

// Passport Strategy configuration
const passport = require("passport");
const passportLocal = require("passport-local");
const bcrypt = require("bcrypt");

const Strategy = passportLocal.Strategy;

const User = require("./models/user");

passport.serializeUser((user, callback) => {
  callback(null, user._id);
});

passport.deserializeUser((id, callback) => {
  User.findById(id)
    .then((user) => {
      console.log(user);
      callback(null, user);
    })
    .catch((err) => {
      callback(err);
    });
});

passport.use(
  "sign-up",
  new Strategy({}, (username, password, callback) => {
    bcrypt
      .hash(password, 10)
      .then((hash) => {
        return User.create({
          username,
          passwordHash: hash,
        });
      })
      .then((user) => {
        callback(null, user);
      })
      .catch((err) => {
        callback(err);
      });
  })
);

passport.use(
  "sign-in",
  new Strategy({}, (username, password, callback) => {
    let user;
    User.findOne({
      username,
    })
      .then((doc) => {
        user = doc;
        return bcrypt.compare(password, user.passwordHash);
      })
      .then((result) => {
        if (result) {
          callback(null, user);
        } else {
          return Promise.reject(new Error("Passwords do not match."));
        }
      })
      .catch((error) => {
        callback(error);
      });
  })
);
