
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const DB_PATH = process.env.DB_PATH || "./data/finmitra.db";

if (!JWT_SECRET || !ADMIN_TOKEN) {
  console.error("Missing JWT_SECRET or ADMIN_TOKEN environment variable.");
  process.exit(1);
}

fs.mkdirSync(path.dirname(path.resolve(DB_PATH)), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mobile TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan TEXT NOT NULL,
    district TEXT NOT NULL,
    state TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

function clean(value, max = 100) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function authUser(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Login required." });
  }
}

function authAdmin(req, res, next) {
  if (!ADMIN_TOKEN || req.headers["x-admin-token"] !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "Admin access denied." });
  }
  next();
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "FinMitra AEPS API" });
});

// Create user account and registration application
app.post("/api/register", async (req, res) => {
  try {
    const name = clean(req.body.name, 80);
    const mobile = clean(req.body.mobile, 10);
    const password = typeof req.body.password === "string"
      ? req.body.password : "";
    const plan = clean(req.body.plan, 30);
    const district = clean(req.body.district, 80);
    const state = clean(req.body.state, 80);

    if (!name || !/^[6-9]\d{9}$/.test(mobile)) {
      return res.status(400).json({ error: "Valid name and 10-digit mobile required." });
    }
    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: "Password must be 8 to 72 characters." });
    }
    if (!["Retailer", "Distributor"].includes(plan)) {
      return res.status(400).json({ error: "Select a valid plan." });
    }
    if (!district || !state) {
      return res.status(400).json({ error: "District and state required." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const create = db.transaction(() => {
      const result = db.prepare(
        "INSERT INTO users (name, mobile, password_hash) VALUES (?, ?, ?)"
      ).run(name, mobile, passwordHash);

      db.prepare(
        "INSERT INTO applications (user_id, plan, district, state) VALUES (?, ?, ?, ?)"
      ).run(result.lastInsertRowid, plan, district, state);

      return result.lastInsertRowid;
    });

    const userId = create();
    const token = jwt.sign({ id: userId, mobile }, JWT_SECRET, {
      expiresIn: "2h"
    });

    res.status(201).json({
      message: "Registration successful.",
      token,
      user: { id: userId, name, mobile },
      application: { plan, district, state, status: "Pending" }
    });
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "Mobile number already registered." });
    }
    console.error("Registration error:", error.message);
    res.status(500).json({ error: "Could not complete registration." });
  }
});

// Login using registered mobile number and password
app.post("/api/login", async (req, res) => {
  const mobile = clean(req.body.mobile, 10);
  const password = typeof req.body.password === "string"
    ? req.body.password : "";

  if (!/^[6-9]\d{9}$/.test(mobile) || !password || password.length > 72) {
    return res.status(400).json({ error: "Valid mobile and password required." });
  }

  const user = db.prepare(
    "SELECT id, name, mobile, password_hash FROM users WHERE mobile = ?"
  ).get(mobile);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Invalid mobile number or password." });
  }

  const token = jwt.sign(
    { id: user.id, mobile: user.mobile },
    JWT_SECRET,
    { expiresIn: "2h" }
  );

  res.json({
    message: "Login successful.",
    token,
    user: { id: user.id, name: user.name, mobile: user.mobile }
  });
});

// User views their own applications
app.get("/api/my-applications", authUser, (req, res) => {
  const rows = db.prepare(`
    SELECT id, plan, district, state, status, created_at
    FROM applications WHERE user_id = ? ORDER BY id DESC
  `).all(req.user.id);

  res.json({ applications: rows });
});

// Admin lists applications
app.get("/api/admin/applications", authAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT a.id, u.name, u.mobile, a.plan, a.district, a.state,
           a.status, a.created_at
    FROM applications a
    JOIN users u ON u.id = a.user_id
    ORDER BY a.id DESC
    LIMIT 500
  `).all();

  res.json({ applications: rows });
});

// Admin updates application status
app.patch("/api/admin/applications/:id", authAdmin, (req, res) => {
  const id = Number(req.params.id);
  const status = clean(req.body.status, 20);

  if (!Number.isInteger(id) || id < 1 ||
      !["Pending", "Approved", "Rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid ID or status." });
  }

  const result = db.prepare(
    "UPDATE applications SET status = ? WHERE id = ?"
  ).run(status, id);

  if (!result.changes) {
    return res.status(404).json({ error: "Application not found." });
  }

  res.json({ message: "Application status updated.", id, status });
});

app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found." });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`FinMitra AEPS API running on port ${PORT}`);
});
