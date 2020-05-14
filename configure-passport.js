"use strict";

// Passport Strategy configuration
const passport = require("passport");
const passportLocal = require("passport-local");
const bcrypt = require("bcrypt");
const passportGithub = require("passport-github");

const Strategy = passportLocal.Strategy;
const GithubStrategy = passportGithub.Strategy;

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
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT,
      clientSecret: process.env.GITHUB_SECRET,
      callbackURL: "http://localhost:3000/authentication/githubcb",
      scope: "user:email",
    },
    (accessToken, refreshToken, profile, callback) => {
      const name = profile.displayName;
      console.log(profile);
      const email = profile.emails.length ? profile.emails[0].value : null;
      const photo = profile._json.avatar_url;
      const githubId = profile.id;
      User.findOne({
        githubId,
      })
        .then((user) => {
          if (user) {
            return Promise.resolve(user);
          } else {
            return User.create({
              email,
              name,
              photo,
              githubId,
            });
          }
        })
        .then((user) => {
          callback(null, user);
        })
        .catch((error) => {
          callback(error);
        });
    }
  )
);

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
