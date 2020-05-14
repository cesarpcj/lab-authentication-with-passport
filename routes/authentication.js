"use strict";

const { Router } = require("express");
const authenticationRouter = Router();
const passport = require("passport");
const routeGuard = require("./../middleware/route-guard");

authenticationRouter.get("/sign-in", (req, res, next) => {
  res.render("authentication/sign-in");
});

authenticationRouter.get("/sign-up", (req, res, next) => {
  res.render("authentication/sign-up");
});

authenticationRouter.post(
  "/sign-in",
  passport.authenticate("sign-in", {
    successRedirect: "/",
    failureRedirect: "/authentication/sign-up",
  })
);

authenticationRouter.post(
  "/sign-up",
  passport.authenticate("sign-up", {
    successRedirect: "/",
    failureRedirect: "/authentication/sign-up",
  })
);

authenticationRouter.get("/private", routeGuard, (req, res, next) => {
  res.render("authentication/private");
});

authenticationRouter.post("/sign-out", (req, res, next) => {
  req.logout();
  res.redirect("/");
});

authenticationRouter.get(
  "/github",
  passport.authenticate("github", {
    successRedirect: "/",
    failureRedirect: "/error",
  })
);

authenticationRouter.get(
  "/githubcb",
  passport.authenticate("github", {
    successRedirect: "/",
    failureRedirect: "/error",
  })
);

module.exports = authenticationRouter;
