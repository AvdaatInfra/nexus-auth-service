import express from "express";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const app = express();
const PORT = process.env.PORT || 3005;

// ── Required env vars ────────────────────────────────────────────────────────
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const JWT_SECRET           = process.env.JWT_SECRET!;
const AUTH_DOMAIN          = process.env.AUTH_DOMAIN || "auth.avdaat.biz";

// Comma-separated list of allowed Gmail addresses
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || "")
  .split(",")
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean);

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !JWT_SECRET) {
  throw new Error(
    "Missing required env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET"
  );
}

// ── Middleware ───────────────────────────────────────────────────────────────
app.set("trust proxy", 1);
app.use(cookieParser());
app.use(express.json());

// ── Passport Google Strategy ─────────────────────────────────────────────────
passport.use(
  new GoogleStrategy(
    {
      clientID:     GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL:  `https://${AUTH_DOMAIN}/auth/google/callback`,
      scope:        ["email", "profile"],
    },
    (_accessToken, _refreshToken, profile, done) => {
      const email = profile.emails?.[0]?.value?.toLowerCase();
      if (!email) return done(new Error("No email returned from Google"));

      if (ALLOWED_EMAILS.length > 0 && !ALLOWED_EMAILS.includes(email)) {
        return done(null, false);
      }

      return done(null, {
        email,
        name:    profile.displayName,
        picture: profile.photos?.[0]?.value ?? null,
        googleId: profile.id,
      });
    }
  )
);

app.use(passport.initialize());

// ── Helpers ───────────────────────────────────────────────────────────────────
function issueToken(user: object) {
  return jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
}

function setAuthCookie(res: express.Response, token: string) {
  res.cookie("nexus_token", token, {
    domain:   ".avdaat.biz",
    httpOnly: true,
    secure:   true,
    sameSite: "lax",
    maxAge:   7 * 24 * 60 * 60 * 1000,
  });
}

function safeRedirect(req: express.Request): string {
  try {
    const raw = req.query.state as string;
    const decoded = Buffer.from(raw, "base64url").toString("utf8");
    const { redirect } = JSON.parse(decoded);
    const url = new URL(redirect);
    if (url.hostname.endsWith(".avdaat.biz") || url.hostname === "avdaat.biz") {
      return redirect;
    }
  } catch {}
  return "https://app.avdaat.biz";
}

// ── Routes ────────────────────────────────────────────────────────────────────

// Root: redirect to /login
app.get("/", (req, res) => {
    const redirect = (req.query.redirect as string) || "https://app.avdaat.biz";
    res.redirect("/login?redirect=" + encodeURIComponent(redirect));
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("/verify", (req, res) => {
  const token = req.cookies?.nexus_token;
  if (!token) return res.status(401).json({ ok: false, error: "No token" });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    res.json({ ok: true, user });
  } catch {
    res.status(401).json({ ok: false, error: "Invalid or expired token" });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("nexus_token", {
    domain:   ".avdaat.biz",
    httpOnly: true,
    secure:   true,
    sameSite: "lax",
  });
  const redirect = (req.query.redirect as string) || "https://app.avdaat.biz";
  res.redirect(redirect);
});

app.get("/login", (req, res, next) => {
  const redirect = (req.query.redirect as string) || "https://app.avdaat.biz";
  const state = Buffer.from(JSON.stringify({ redirect })).toString("base64url");
  passport.authenticate("google", { scope: ["email", "profile"], state })(
    req, res, next
  );
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/unauthorized",
  }),
  (req: any, res) => {
    const token = issueToken(req.user);
    setAuthCookie(res, token);
    res.redirect(safeRedirect(req));
  }
);

app.get("/unauthorized", (_req, res) => {
  res.status(403).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Access Denied — NEXUS</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#fff;
         display:flex;align-items:center;justify-content:center;min-height:100vh}
    .card{text-align:center;padding:2.5rem 3rem;background:#111;border:1px solid #222;
          border-radius:1rem;max-width:420px}
    .icon{font-size:3rem;margin-bottom:1rem}
    h1{font-size:1.5rem;margin-bottom:.5rem}
    p{color:#888;font-size:.95rem;line-height:1.5;margin-bottom:1.5rem}
    a{display:inline-block;padding:.6rem 1.4rem;background:#7c3aed;color:#fff;
      border-radius:.5rem;text-decoration:none;font-size:.9rem}
    a:hover{background:#6d28d9}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>Access Denied</h1>
    <p>Your Google account is not authorised to access NEXUS.<br>
       Contact the admin to request access.</p>
    <a href="/login">Try a different account</a>
  </div>
</body>
</html>`);
});

app.listen(PORT, () => {
  console.log(`[auth-service] Listening on port ${PORT}`);
  console.log(`[auth-service] Domain  : ${AUTH_DOMAIN}`);
  console.log(`[auth-service] Allowlist (${ALLOWED_EMAILS.length} emails): ${
    ALLOWED_EMAILS.length ? ALLOWED_EMAILS.join(", ") : "(open — no allowlist set)"
  }`);
});
