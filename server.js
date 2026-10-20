const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable is required");
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());

app.use(cors({
  origin: "https://finmitraaeps.github.io",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "10kb" }));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

const db = new Database("./finmitra.db");

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mobile TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL,
    district TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

const findUser = db.prepare(
  "SELECT * FROM users WHERE mobile = ?"
);

const createUser = db.prepare(`
  INSERT INTO users
    (name, mobile, password_hash, plan, district, state)
  VALUES
    (?, ?, ?, ?, ?, ?)
`);

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "FinMitra AEPS API"
  });
});

app.post("/api/register", async (req, res) => {
  try {
    const {
      name,
      mobile,
      password,
      plan,
      district,
      state
    } = req.body || {};

    if (
      typeof name !== "string" ||
      typeof mobile !== "string" ||
      typeof password !== "string" ||
      typeof district !== "string" ||
      typeof state !== "string"
    ) {
      return res.status(400).json({
        error: "Please fill all required fields."
      });
    }

    if (
      !name.trim() ||
      !/^[6-9][0-9]{9}$/.test(mobile) ||
      password.length < 8 ||
      password.length > 72 ||
      !district.trim() ||
      !state.trim()
    ) {
      return res.status(400).json({
        error: "Please check your registration details."
      });
    }

    if (!["Retailer", "Distributor"].includes(plan)) {
      return res.status(400).json({
        error: "Invalid registration plan."
      });
    }

    if (findUser.get(mobile)) {
      return res.status(409).json({
        error: "This mobile number is already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = createUser.run(
      name.trim(),
      mobile,
      passwordHash,
      plan,
      district.trim(),
      state.trim()
    );

    return res.status(201).json({
      success: true,
      message: "Registration successful. Your account is pending approval.",
      user: {
        id: result.lastInsertRowid,
        name: name.trim(),
        mobile,
        plan,
        district: district.trim(),
        state: state.trim()
      }
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "This mobile number is already registered."
      });
    }

    console.error("Registration error:", error.message);

    return res.status(500).json({
      error: "Registration failed. Please try again."
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { mobile, password } = req.body || {};

    if (
      typeof mobile !== "string" ||
      typeof password !== "string" ||
      !/^[6-9][0-9]{9}$/.test(mobile) ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "Invalid mobile number or password."
      });
    }

    const user = findUser.get(mobile);

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Invalid mobile number or password."
      });
    }

    const token = jwt.sign(
      { userId: user.id, mobile: user.mobile },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    return res.json({
      success: true,
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        mobile: user.mobile,
        plan: user.plan,
        district: user.district,
        state: user.state
      }
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "Login failed. Please try again."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`FinMitra AEPS API listening on port ${PORT}`);
});
