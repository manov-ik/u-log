require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-prod";

// ── NeonDB connection ──────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── Create tables on startup ───────────────────────────────────
pool
  .query(
    `
  CREATE TABLE IF NOT EXISTS users (
    id         SERIAL PRIMARY KEY,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS entries (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    cause      TEXT,
    place      TEXT,
    note       TEXT,
    level      INTEGER,
    why        TEXT,
    thought    TEXT,
    how_long   TEXT,
    what_done  TEXT,
    entry_time TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  -- add entry_time to existing tables if column is missing
  ALTER TABLE entries ADD COLUMN IF NOT EXISTS entry_time TIMESTAMPTZ DEFAULT NOW();
`,
  )
  .then(() => console.log("Tables ready"))
  .catch((err) => console.error("Table init error:", err.message));

// ── Auth middleware ────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res.status(401).json({ ok: false, error: "Not logged in" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res
      .status(401)
      .json({ ok: false, error: "Session expired, please log in again" });
  }
}

// ── POST /api/register ─────────────────────────────────────────
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username?.trim() || !password)
    return res
      .status(400)
      .json({ ok: false, error: "Username and password required" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1,$2) RETURNING id, username",
      [username.trim().toLowerCase(), hash],
    );
    const token = jwt.sign(
      { id: result.rows[0].id, username: result.rows[0].username },
      JWT_SECRET,
      { expiresIn: "7d" },
    );
    res.json({ ok: true, token, username: result.rows[0].username });
  } catch (err) {
    if (err.code === "23505")
      return res
        .status(400)
        .json({ ok: false, error: "Username already taken" });
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── POST /api/login ────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ ok: false, error: "Username and password required" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [
      username.trim().toLowerCase(),
    ]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res
        .status(401)
        .json({ ok: false, error: "Invalid username or password" });
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "7d" },
    );
    res.json({ ok: true, token, username: user.username });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── POST /api/entries ──────────────────────────────────────────
app.post("/api/entries", auth, async (req, res) => {
  const {
    cause,
    place,
    note,
    level,
    why,
    thought,
    how_long,
    what_done,
    entry_time,
  } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO entries (user_id, cause, place, note, level, why, thought, how_long, what_done, entry_time)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [
        req.user.id,
        cause,
        place,
        note,
        level,
        why,
        thought,
        how_long,
        what_done,
        entry_time || new Date(),
      ],
    );
    res.json({ ok: true, entry: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/entries?page=1&limit=10 ──────────────────────────
app.get("/api/entries", auth, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(50, parseInt(req.query.limit) || 10);
  const offset = (page - 1) * limit;
  try {
    const [rows, count] = await Promise.all([
      pool.query(
        `SELECT * FROM entries WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
        [req.user.id, limit, offset],
      ),
      pool.query(`SELECT COUNT(*) FROM entries WHERE user_id=$1`, [
        req.user.id,
      ]),
    ]);
    res.json({
      ok: true,
      entries: rows.rows,
      total: parseInt(count.rows[0].count),
      page,
      limit,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── Fallback ───────────────────────────────────────────────────
app.get("*", (_, res) => res.sendFile(path.join(__dirname, "index.html")));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
