
const express = require("express");
const path = require("path");
const Unblocker = require("unblocker");

const app = express();
const PORT = process.env.PORT || 3000;
const ACCESS_KEY = process.env.ACCESS_KEY;

if (!ACCESS_KEY) {
  throw new Error("Missing ACCESS_KEY environment variable");
}

app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false, limit: "2kb" }));

function hasAccess(req) {
  const cookie = req.headers.cookie || "";
  return cookie.split(";").some(part => {
    const [name, ...rest] = part.trim().split("=");
    return name === "vb_access" &&
      decodeURIComponent(rest.join("=")) === ACCESS_KEY;
  });
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/session", (req, res) => {
  res.sendStatus(hasAccess(req) ? 200 : 401);
});

app.post("/unlock", (req, res) => {
  if (req.body.key !== ACCESS_KEY) {
    return res.redirect("/?error=1");
  }

  res.cookie("vb_access", ACCESS_KEY, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000
  });

  res.redirect("/");
});

app.get("/go", (req, res) => {
  if (!hasAccess(req)) return res.redirect("/");

  let destination;
  try {
    destination = new URL(req.query.url);
  } catch {
    return res.status(400).send("Enter a valid web address.");
  }

  if (!["http:", "https:"].includes(destination.protocol)) {
    return res.status(400).send("Only HTTP and HTTPS are supported.");
  }

  const host = destination.hostname.toLowerCase();

  // Basic protection against local and private destinations.
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    host.startsWith("169.254.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  ) {
    return res.status(403).send("That destination is not allowed.");
  }

  res.redirect("/proxy/" + destination.href);
});

app.use((req, res, next) => {
  if (req.path.startsWith("/proxy/") && !hasAccess(req)) {
    return res.status(401).send("Please unlock VoidBrowse first.");
  }
  next();
});

const unblocker = new Unblocker({ prefix: "/proxy/" });
app.use(unblocker);

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`VoidBrowse listening on port ${PORT}`);
});

server.on("upgrade", unblocker.onUpgrade);
