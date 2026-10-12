const express = require("express");
const session = require("express-session");
const passport = require("passport");
const SteamStrategy = require("passport-steam").Strategy;
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const STEAM_API_KEY = process.env.STEAM_API_KEY;

if (!BASE_URL || !SESSION_SECRET || !STEAM_API_KEY) {
  console.error("Missing environment variables: BASE_URL, SESSION_SECRET, STEAM_API_KEY");
  process.exit(1);
}

app.set("trust proxy", 1);
app.use(session({
  name: "newmahals.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: "auto", sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(new SteamStrategy({
returnURL: `${BASE_URL.replace(/\/$/, "")}/auth/steam/return`,
realm: `${BASE_URL.replace(/\/$/, "")}/`,
  apiKey: STEAM_API_KEY
}, (_identifier, profile, done) => {
  done(null, {
    steamId: profile.id,
    displayName: profile.displayName,
    profileUrl: profile._json && profile._json.profileurl ? profile._json.profileurl : "",
    avatar: profile.photos && profile.photos[2] ? profile.photos[2].value :
      (profile.photos && profile.photos[0] ? profile.photos[0].value : "")
  });
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/auth/steam", passport.authenticate("steam"));
app.get("/auth/steam/return",
  passport.authenticate("steam", { failureRedirect: "/?steam_login=failed" }),
  (_req, res) => res.redirect("/?steam_login=success")
);
app.get("/api/me", (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) return res.status(401).json({ loggedIn: false });
  res.json({ loggedIn: true, user: req.user });
});
app.post("/auth/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});
app.get("/health", (_req, res) => res.json({ ok: true }));
app.use(express.static(path.join(__dirname)));
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/auth/") || req.path.startsWith("/api/")) return res.status(404).json({ error: "Not found" });
  res.sendFile(path.join(__dirname, "index.html"), err => { if (err) next(err); });
});
app.listen(PORT, "0.0.0.0", () => console.log(`NEWMAHALS backend listening on port ${PORT}`));
