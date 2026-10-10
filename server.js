const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const multer = require("multer");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const IS_PROD = process.env.NODE_ENV === "production";

const SESSION_SECRET = process.env.SESSION_SECRET || "salaksak-art-net-secret-key";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@salaksak.art.net";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// Optional: extra origins allowed to make state-changing requests
// (comma separated, e.g. "https://www.example.com,https://example.com").
const EXTRA_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

// Never run a public site with the built-in default secrets.
if (IS_PROD && (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD)) {
    console.error("SESSION_SECRET and ADMIN_PASSWORD must be set when NODE_ENV=production.");
    process.exit(1);
}

/*
 * DATA_DIR is where the database and uploaded images live.
 * On a server/host with a persistent disk, point it at that disk
 * (for example DATA_DIR=/var/data). Locally it defaults to the project folder.
 */
const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });

const uploadDir = path.join(DATA_DIR, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

/* ------------------------------------------------------------------ */
/* HELPERS                                                             */
/* ------------------------------------------------------------------ */

// An error that carries the HTTP status it should be reported with.
class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

/* ---------- Upload handling (images only; PDF allowed for portfolios) ---------- */

const IMAGE_TYPES = {
    ".jpg": ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".png": ["image/png"],
    ".gif": ["image/gif"],
    ".webp": ["image/webp"]
};
const SERVE_INLINE_EXT = [...Object.keys(IMAGE_TYPES), ".pdf"];

function makeFileFilter(allowPdf) {
    return (req, file, cb) => {
        const ext = path.extname(file.originalname || "").toLowerCase();
        const mime = String(file.mimetype || "").toLowerCase();
        const isImage = IMAGE_TYPES[ext] && IMAGE_TYPES[ext].includes(mime);
        const isPdf = allowPdf && ext === ".pdf" && mime === "application/pdf";

        if (isImage || isPdf) return cb(null, true);
        cb(new Error(
            allowPdf
                ? "Only JPG, PNG, GIF, WebP images or PDF files are allowed."
                : "Only JPG, PNG, GIF or WebP images are allowed."
        ));
    };
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        // Never trust the client's file name: random name + vetted extension.
        const ext = path.extname(file.originalname || "").toLowerCase();
        cb(null, Date.now() + "-" + crypto.randomBytes(8).toString("hex") + ext);
    }
});

function deleteUploadedFiles(req) {
    const files = Array.isArray(req.files) ? req.files : [];
    for (const file of files) {
        if (file && file.path) fs.unlink(file.path, () => {});
    }
}

// Wraps a multer middleware so upload errors become clean JSON 400s.
function withUpload(middleware) {
    return (req, res, next) => {
        middleware(req, res, err => {
            if (err) {
                deleteUploadedFiles(req);
                const msg = err.code === "LIMIT_FILE_SIZE"
                    ? "File is too large (max 10 MB)."
                    : err.message;
                return res.status(400).json({ success: false, error: "Upload failed: " + msg });
            }
            next();
        });
    };
}

const imageUpload = withUpload(multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024, files: 1 },
    fileFilter: makeFileFilter(false)
}).any());

const portfolioUpload = withUpload(multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024, files: 1 },
    fileFilter: makeFileFilter(true)
}).any());

// For login/register: accepts multipart text fields but NEVER writes a file to disk.
const textOnly = withUpload(multer().none());

/* ---------- Tiny in-memory rate limiter (no extra dependency) ---------- */

function rateLimit({ windowMs, max, message }) {
    const hits = new Map();

    setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of hits) {
            if (entry.reset <= now) hits.delete(key);
        }
    }, windowMs).unref();

    return (req, res, next) => {
        const now = Date.now();
        const key = req.ip;
        let entry = hits.get(key);

        if (!entry || entry.reset <= now) {
            entry = { count: 0, reset: now + windowMs };
            hits.set(key, entry);
        }

        entry.count++;
        if (entry.count > max) {
            res.setHeader("Retry-After", Math.ceil((entry.reset - now) / 1000));
            return res.status(429).json({ success: false, error: message });
        }
        next();
    };
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: "Too many attempts. Please try again in a few minutes."
});
const signupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 15,
    message: "Too many sign-up attempts. Please try again later."
});

/* ------------------------------------------------------------------ */
/* BASIC MIDDLEWARE & SECURITY HEADERS                                 */
/* ------------------------------------------------------------------ */

app.disable("x-powered-by");

// Behind Nginx / a host's HTTPS proxy: needed for secure cookies and req.ip to work.
app.set("trust proxy", 1);

// Lightweight equivalent of the most useful helmet headers.
app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    if (IS_PROD) {
        res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
    }
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/*
 * CSRF defence: browsers always attach Origin (or Referer) to cross-site
 * POST/PUT/PATCH/DELETE requests. Reject any whose origin is not this site.
 * Requests with neither header (curl, server-to-server) carry no browser
 * cookies, so they are let through.
 */
function sameOriginGuard(req, res, next) {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();

    const source = req.get("origin") || req.get("referer");
    if (!source) return next();

    let origin = "";
    try {
        origin = new URL(source).origin;
    } catch (e) {
        origin = "";
    }

    const host = String(req.get("x-forwarded-host") || req.get("host") || "").split(",")[0].trim();
    const own = `${req.protocol}://${host}`;

    if (origin && (origin === own || EXTRA_ORIGINS.includes(origin))) return next();

    return res.status(403).json({ success: false, error: "Cross-site request blocked." });
}
app.use("/api", sameOriginGuard);

// Uploaded files: images/PDFs render normally; anything else (e.g. legacy
// .html/.svg uploads) is forced to download and sandboxed so it cannot run scripts.
app.use("/uploads", express.static(uploadDir, {
    index: false,
    dotfiles: "deny",
    setHeaders: (res, filePath) => {
        const ext = path.extname(filePath).toLowerCase();
        if (!SERVE_INLINE_EXT.includes(ext)) {
            res.setHeader("Content-Disposition", "attachment");
            res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
        }
    }
}));

/* ------------------------------------------------------------------ */
/* DATABASE                                                            */
/* ------------------------------------------------------------------ */

const db = new sqlite3.Database(path.join(DATA_DIR, "database.sqlite"), err => {
    if (err) console.error("Database connection error:", err.message);
    else console.log("Database connected.");
});

function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

function get(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function all(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

/*
 * SQLite uses ONE shared connection here, so two transactions running at the
 * same time would collide on BEGIN TRANSACTION. This queue makes sure only
 * one locked operation runs at a time.
 */
let dbQueue = Promise.resolve();
function withLock(fn) {
    const p = dbQueue.then(() => fn());
    dbQueue = p.catch(() => {});
    return p;
}

// Runs fn inside a locked transaction: COMMIT on success, ROLLBACK on error.
function transaction(fn) {
    return withLock(async () => {
        await run("BEGIN TRANSACTION");
        try {
            const result = await fn();
            await run("COMMIT");
            return result;
        } catch (err) {
            await run("ROLLBACK").catch(() => {});
            throw err;
        }
    });
}

async function addColumn(table, column, definition) {
    try {
        await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    } catch (err) {
        if (!/duplicate column name/i.test(err.message)) throw err;
    }
}

/* ---------- Persistent session store (replaces the leaky MemoryStore) ---------- */

const SESSION_MAX_AGE = 1000 * 60 * 60 * 24 * 7; // stay signed in for 7 days

class SqliteSessionStore extends session.Store {
    get(sid, cb) {
        get(`SELECT sess FROM sessions WHERE sid=? AND expires>?`, [sid, Date.now()])
            .then(row => {
                if (!row) return cb(null, null);
                let data = null;
                try {
                    data = JSON.parse(row.sess);
                } catch (e) {
                    return cb(e);
                }
                cb(null, data);
            }, err => cb(err));
    }

    set(sid, sess, cb) {
        const expires = sess && sess.cookie && sess.cookie.expires
            ? new Date(sess.cookie.expires).getTime()
            : Date.now() + SESSION_MAX_AGE;

        withLock(() => run(
            `INSERT OR REPLACE INTO sessions(sid,sess,expires) VALUES(?,?,?)`,
            [sid, JSON.stringify(sess), expires]
        )).then(() => cb && cb(null), err => cb && cb(err));
    }

    destroy(sid, cb) {
        withLock(() => run(`DELETE FROM sessions WHERE sid=?`, [sid]))
            .then(() => cb && cb(null), err => cb && cb(err));
    }

    touch(sid, sess, cb) {
        const expires = sess && sess.cookie && sess.cookie.expires
            ? new Date(sess.cookie.expires).getTime()
            : Date.now() + SESSION_MAX_AGE;

        withLock(() => run(`UPDATE sessions SET expires=? WHERE sid=?`, [expires, sid]))
            .then(() => cb && cb(null), err => cb && cb(err));
    }
}

setInterval(() => {
    run(`DELETE FROM sessions WHERE expires<?`, [Date.now()]).catch(() => {});
}, 60 * 60 * 1000).unref();

app.use(session({
    store: new SqliteSessionStore(),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: IS_PROD,          // cookie only sent over HTTPS when online
        httpOnly: true,
        sameSite: "lax",
        maxAge: SESSION_MAX_AGE
    }
}));

// Creates a brand-new session id on sign-in (prevents session fixation).
function startSession(req, user) {
    return new Promise((resolve, reject) => {
        req.session.regenerate(err => {
            if (err) return reject(err);

            req.session.userId = user.id;
            req.session.role = user.role;
            req.session.status = user.status;
            req.session.name = user.name;
            req.session.email = user.email;

            req.session.save(saveErr => (saveErr ? reject(saveErr) : resolve()));
        });
    });
}

/* ------------------------------------------------------------------ */
/* SCHEMA                                                              */
/* ------------------------------------------------------------------ */

async function initializeDatabase() {
    await run(`
        CREATE TABLE IF NOT EXISTS sessions (
            sid TEXT PRIMARY KEY,
            sess TEXT NOT NULL,
            expires INTEGER NOT NULL
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            store_name TEXT,
            portfolio_url TEXT,
            role TEXT DEFAULT 'buyer',
            status TEXT DEFAULT 'approved',
            has_seen_approval INTEGER DEFAULT 1
        )
    `);

    await addColumn("users", "store_name", "TEXT");
    await addColumn("users", "portfolio_url", "TEXT");
    await addColumn("users", "role", "TEXT DEFAULT 'buyer'");
    await addColumn("users", "status", "TEXT DEFAULT 'approved'");
    await addColumn("users", "has_seen_approval", "INTEGER DEFAULT 1");

    await run(`
        CREATE TABLE IF NOT EXISTS artworks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            artist TEXT,
            store_name TEXT,
            medium TEXT,
            price REAL DEFAULT 0,
            image_url TEXT,
            stock INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    await addColumn("artworks", "user_id", "INTEGER");
    await addColumn("artworks", "artist", "TEXT");
    await addColumn("artworks", "store_name", "TEXT");
    await addColumn("artworks", "medium", "TEXT");
    await addColumn("artworks", "price", "REAL DEFAULT 0");
    await addColumn("artworks", "image_url", "TEXT");
    await addColumn("artworks", "stock", "INTEGER DEFAULT 1");
    await addColumn("artworks", "created_at", "TEXT");
    await run(`UPDATE artworks SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL`);
    await run(`UPDATE artworks SET stock = 1 WHERE stock IS NULL`);

    await run(`
        CREATE TABLE IF NOT EXISTS cart_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            artwork_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, artwork_id)
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            buyer_id INTEGER NOT NULL,
            total REAL NOT NULL DEFAULT 0,
            full_name TEXT,
            email TEXT,
            contact_number TEXT,
            address TEXT,
            country TEXT,
            payment_method TEXT DEFAULT 'COD',
            status TEXT DEFAULT 'Pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            artwork_id INTEGER,
            seller_id INTEGER,
            title TEXT,
            price REAL NOT NULL DEFAULT 0,
            quantity INTEGER NOT NULL DEFAULT 1,
            subtotal REAL NOT NULL DEFAULT 0
        )
    `);

    // Per-item status so each seller only controls their own part of an order.
    await addColumn("order_items", "status", "TEXT");
    await run(`
        UPDATE order_items
        SET status = COALESCE((SELECT o.status FROM orders o WHERE o.id = order_items.order_id), 'Pending')
        WHERE status IS NULL
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            artwork_id INTEGER,
            order_id INTEGER,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            order_id INTEGER,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    /*
     * Admin bootstrap. The password is only set when the account is first
     * created. To deliberately reset it later, start once with
     * RESET_ADMIN_PASSWORD=true.
     */
    const admin = await get(`SELECT id FROM users WHERE email = ?`, [ADMIN_EMAIL]);

    if (!admin) {
        const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
        await run(`
            INSERT INTO users
            (name,email,password,store_name,role,status,has_seen_approval)
            VALUES (?,?,?,?,?,?,?)
        `, [
            "System Admin",
            ADMIN_EMAIL,
            hash,
            "Salaksak HQ",
            "admin",
            "approved",
            1
        ]);
    } else {
        await run(`
            UPDATE users
            SET role='admin', status='approved'
            WHERE email=?
        `, [ADMIN_EMAIL]);

        if (process.env.RESET_ADMIN_PASSWORD === "true") {
            const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
            await run(`UPDATE users SET password=? WHERE email=?`, [hash, ADMIN_EMAIL]);
            console.log("Admin password was reset from ADMIN_PASSWORD (RESET_ADMIN_PASSWORD=true).");
        }
    }

    console.log("Database ready.");
}

/* ------------------------------------------------------------------ */
/* AUTH MIDDLEWARE                                                     */
/* ------------------------------------------------------------------ */

function loadUser(req, res, next) {
    if (!req.session.userId) {
        req.user = null;
        return next();
    }

    db.get(
        `SELECT * FROM users WHERE id = ?`,
        [req.session.userId],
        (err, user) => {
            if (err || !user) {
                req.user = null;
                return next();
            }

            req.user = user;
            req.session.role = user.role;
            req.session.status = user.status;
            req.session.name = user.name;
            req.session.email = user.email;
            next();
        }
    );
}

function requireLogin(req, res, next) {
    loadUser(req, res, () => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: "Please sign in first."
            });
        }
        next();
    });
}

function isCreator(user) {
    return !!user && (user.role === "seller" || user.role === "admin");
}

function requireCreator(req, res, next) {
    loadUser(req, res, () => {
        if (!isCreator(req.user)) {
            return res.status(403).json({
                success: false,
                error: "Seller access required."
            });
        }
        next();
    });
}

function requireAdmin(req, res, next) {
    loadUser(req, res, () => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: "Please sign in first." });
        }
        if (req.user.role !== "admin") {
            return res.status(403).json({ success: false, error: "Admin access required." });
        }
        next();
    });
}

function validId(value) {
    return Number.isInteger(Number(value)) && Number(value) > 0;
}

// Sends a JSON error using the HttpError status when there is one.
function sendError(res, err, logLabel, fallbackMessage) {
    if (err instanceof HttpError) {
        return res.status(err.status).json({ success: false, error: err.message });
    }
    console.error(logLabel + ":", err);
    return res.status(500).json({ success: false, error: fallbackMessage });
}

// The database page is only served to signed-in admins.
app.get("/admin.html", (req, res, next) => {
    loadUser(req, res, () => {
        if (!req.user || req.user.role !== "admin") {
            return res.redirect("/login.html?next=admin.html");
        }
        next();
    });
});

app.use(express.static(path.join(__dirname, "public")));

/* ------------------------------------------------------------------ */
/* SESSION                                                             */
/* ------------------------------------------------------------------ */

app.get("/api/session", loadUser, (req, res) => {
    if (!req.user) return res.json({ loggedIn: false });

    res.json({
        loggedIn: true,
        userId: req.user.id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role,
        status: req.user.status,
        has_seen_approval: req.user.has_seen_approval,
        notification_message:
            req.user.status === "pending"
                ? "Your seller application is under review."
                : req.user.status === "approved" && req.user.role === "seller"
                    ? "Your seller application has been approved."
                    : ""
    });
});

/* ------------------------------------------------------------------ */
/* AUTH                                                                */
/* ------------------------------------------------------------------ */

app.post("/api/register", signupLimiter, textOnly, async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                error: "All fields are required."
            });
        }

        const existing = await get(`SELECT id FROM users WHERE email=?`, [email]);
        if (existing) {
            return res.status(400).json({
                success: false,
                error: "Email is already registered. Please sign in."
            });
        }

        const hashed = await bcrypt.hash(password, 10);

        const result = await run(`
            INSERT INTO users
            (name,email,password,store_name,role,status,has_seen_approval)
            VALUES (?,?,?,?,?,?,?)
        `, [
            name,
            email,
            hashed,
            name + "'s Collection",
            "buyer",
            "approved",
            1
        ]);

        await startSession(req, {
            id: result.lastID,
            role: "buyer",
            status: "approved",
            name,
            email
        });

        res.json({ success: true, redirect: "index.html" });
    } catch (err) {
        console.error("REGISTER ERROR:", err);
        res.status(500).json({ success: false, error: "Registration failed." });
    }
});

app.post("/api/login", loginLimiter, textOnly, async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: "Email and password are required."
            });
        }

        const user = await get(`SELECT * FROM users WHERE email=?`, [email]);

        if (!user || !user.password) {
            return res.status(401).json({
                success: false,
                error: "Invalid email or password."
            });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({
                success: false,
                error: "Invalid email or password."
            });
        }

        await startSession(req, user);

        const redirect =
            user.role === "admin"
                ? "dashboard.html"
                : user.status === "pending"
                    ? "pending.html"
                    : user.role === "seller"
                        ? "dashboard.html"
                        : "index.html";

        res.json({ success: true, redirect });
    } catch (err) {
        console.error("LOGIN ERROR:", err);
        res.status(500).json({ success: false, error: "Login failed." });
    }
});

app.post("/api/apply-seller", loadUser, signupLimiter, portfolioUpload, async (req, res) => {
    try {
        const storeName = String(req.body.store_name || "My Art Studio").trim();
        const file = req.files && req.files[0];
        const portfolioUrl = file ? `/uploads/${file.filename}` : "";

        if (!req.user) {
            const name = String(req.body.name || "").trim();
            const email = String(req.body.email || "").trim().toLowerCase();
            const password = String(req.body.password || "");

            if (!name || !email || !password) {
                deleteUploadedFiles(req);
                return res.status(400).json({
                    success: false,
                    error: "Name, email, and password are required."
                });
            }

            const existing = await get(`SELECT id FROM users WHERE email=?`, [email]);
            if (existing) {
                deleteUploadedFiles(req);
                return res.status(400).json({
                    success: false,
                    error: "Email already exists. Please sign in first."
                });
            }

            const hashed = await bcrypt.hash(password, 10);
            const result = await run(`
                INSERT INTO users
                (name,email,password,store_name,portfolio_url,role,status,has_seen_approval)
                VALUES (?,?,?,?,?,?,?,?)
            `, [
                name, email, hashed, storeName, portfolioUrl,
                "buyer", "pending", 0
            ]);

            await startSession(req, {
                id: result.lastID,
                role: "buyer",
                status: "pending",
                name,
                email
            });

            return res.json({ success: true, redirect: "pending.html" });
        }

        // Existing sellers/admins must not be demoted by re-applying.
        if (req.user.role === "seller" || req.user.role === "admin") {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Your account already has seller access."
            });
        }

        await run(`
            UPDATE users
            SET store_name=?,
                portfolio_url=CASE WHEN ? <> '' THEN ? ELSE portfolio_url END,
                role='buyer',
                status='pending',
                has_seen_approval=0
            WHERE id=?
        `, [storeName, portfolioUrl, portfolioUrl, req.user.id]);

        req.session.role = "buyer";
        req.session.status = "pending";

        res.json({ success: true, redirect: "pending.html" });
    } catch (err) {
        console.error("SELLER APPLICATION ERROR:", err);
        deleteUploadedFiles(req);
        res.status(500).json({
            success: false,
            error: "Seller application failed."
        });
    }
});

app.post("/api/logout", (req, res) => {
    req.session.destroy(() => {
        res.clearCookie("connect.sid");
        res.json({ success: true });
    });
});

app.post("/api/mark-approval-seen", requireLogin, async (req, res) => {
    try {
        await run(`UPDATE users SET has_seen_approval=1 WHERE id=?`, [req.user.id]);
        res.json({ success: true });
    } catch {
        res.status(500).json({ success: false, error: "Database error." });
    }
});

/* ------------------------------------------------------------------ */
/* ADMIN                                                               */
/* ------------------------------------------------------------------ */

app.get("/api/admin/applications", requireAdmin, async (req, res) => {
    try {
        const rows = await all(`
            SELECT id,name,email,store_name,portfolio_url,status,role
            FROM users
            WHERE role='buyer' AND status='pending'
            ORDER BY id DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error." });
    }
});

app.post("/api/admin/review-seller", requireAdmin, async (req, res) => {
    const userId = Number(req.body.userId);
    const decision = req.body.decision;

    if (!validId(userId) || !["approved", "rejected"].includes(decision)) {
        return res.status(400).json({
            success: false,
            error: "Invalid application decision."
        });
    }

    try {
        const role = decision === "approved" ? "seller" : "buyer";

        // Only pending buyer applications can be reviewed (never touches admins).
        const result = await run(`
            UPDATE users
            SET role=?, status=?, has_seen_approval=0
            WHERE id=? AND role='buyer' AND status='pending'
        `, [role, decision, userId]);

        if (result.changes !== 1) {
            return res.status(404).json({
                success: false,
                error: "No pending application found for this user."
            });
        }

        res.json({ success: true });
    } catch {
        res.status(500).json({
            success: false,
            error: "Could not review application."
        });
    }
});

/* ------------------------------------------------------------------ */
/* ARTWORK CATALOG                                                     */
/* ------------------------------------------------------------------ */

app.get("/api/artworks", async (req, res) => {
    try {
        const rows = await all(`
            SELECT
                a.id,
                a.user_id,
                a.title,
                a.artist,
                a.store_name,
                a.medium,
                a.price,
                a.image_url,
                COALESCE(a.stock,1) AS stock,
                a.created_at,
                u.name AS seller_name,
                u.email AS seller_email
            FROM artworks a
            LEFT JOIN users u ON u.id=a.user_id
            ORDER BY a.id DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error("GET ARTWORKS ERROR:", err);
        res.status(500).json({ error: "Database error loading artworks." });
    }
});

// One handler, two paths (kept so existing front-end code keeps working).
async function listOwnArtworks(req, res) {
    try {
        const rows = req.user.role === "admin"
            ? await all(`
                SELECT a.*, COALESCE(a.stock,1) AS stock
                FROM artworks a
                ORDER BY a.id DESC
            `)
            : await all(`
                SELECT a.*, COALESCE(a.stock,1) AS stock
                FROM artworks a
                WHERE a.user_id=?
                ORDER BY a.id DESC
            `, [req.user.id]);

        res.json(rows);
    } catch (err) {
        console.error("OWN ARTWORKS ERROR:", err);
        res.status(500).json({
            success: false,
            error: "Could not load your collection."
        });
    }
}

app.get("/api/my-artworks", requireCreator, listOwnArtworks);
app.get("/api/seller/artworks", requireCreator, listOwnArtworks);

app.post("/api/artworks", requireCreator, imageUpload, async (req, res) => {
    try {
        const title = String(req.body.title || "").trim();
        const artist = String(req.body.artist || req.user.name || "").trim();
        const medium = String(req.body.medium || "").trim();

        const priceRaw = req.body.price;
        const stockRaw = req.body.stock;
        const price = priceRaw === undefined || String(priceRaw).trim() === "" ? 0 : Number(priceRaw);
        const stock = stockRaw === undefined || String(stockRaw).trim() === "" ? 1 : Number(stockRaw);

        const file = req.files && req.files[0];
        const imageUrl = file ? `/uploads/${file.filename}` : "";
        const storeName = req.user.store_name || "Studio Gallery";

        if (!title) {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Title is required."
            });
        }

        if (!Number.isFinite(price) || price < 0) {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Price must be a valid non-negative number."
            });
        }

        if (!Number.isInteger(stock) || stock < 0) {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Stock must be a whole number of 0 or greater."
            });
        }

        const result = await run(`
            INSERT INTO artworks
            (user_id,title,artist,store_name,medium,price,image_url,stock,created_at)
            VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
        `, [
            req.user.id, title, artist, storeName,
            medium, price, imageUrl, stock
        ]);

        res.json({ success: true, artworkId: result.lastID });
    } catch (err) {
        console.error("CREATE ARTWORK ERROR:", err);
        deleteUploadedFiles(req);
        res.status(500).json({
            success: false,
            error: "Failed to add artwork."
        });
    }
});

/*
 * EDIT ARTWORK
 * Accepts JSON or multipart (when the seller replaces the image).
 * Medium is not required: older artworks with an empty medium
 * used to be impossible to edit.
 */
app.put("/api/artworks/:id", requireCreator, imageUpload, async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!validId(id)) {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Invalid artwork ID."
            });
        }

        const old = await get("SELECT * FROM artworks WHERE id = ?", [id]);

        if (!old) {
            deleteUploadedFiles(req);
            return res.status(404).json({
                success: false,
                error: "Artwork not found."
            });
        }

        if (req.user.role !== "admin" && Number(old.user_id) !== Number(req.user.id)) {
            deleteUploadedFiles(req);
            return res.status(403).json({
                success: false,
                error: "You can only edit your own artwork."
            });
        }

        const body = req.body || {};

        const title = String(body.title ?? old.title ?? "").trim();
        const artist = String(body.artist ?? old.artist ?? req.user.name ?? "").trim();
        const medium =
            String(body.medium ?? "").trim() ||
            String(old.medium || "").trim() ||
            "Uncategorized";
        const priceText = String(body.price ?? old.price ?? 0).trim();
        const stockText = String(body.stock ?? old.stock ?? 1).trim();
        const price = Number(priceText);
        const stock = Number(stockText);

        if (!title) {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Title is required."
            });
        }

        if (priceText === "" || !Number.isFinite(price) || price < 0) {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Price must be a valid non-negative number."
            });
        }

        if (stockText === "" || !Number.isInteger(stock) || stock < 0) {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Stock must be a whole number of 0 or greater."
            });
        }

        const file = Array.isArray(req.files) ? req.files[0] : null;
        const imageUrl = file ? `/uploads/${file.filename}` : (old.image_url || "");

        await run(`
            UPDATE artworks
            SET title=?, artist=?, medium=?, price=?, stock=?, image_url=?
            WHERE id=?
        `, [title, artist, medium, price, stock, imageUrl, id]);

        if (file && old.image_url && old.image_url.startsWith("/uploads/")) {
            const oldFile = path.join(uploadDir, path.basename(old.image_url));
            if (fs.existsSync(oldFile)) {
                fs.unlink(oldFile, err => {
                    if (err) console.error("Could not delete old image:", err.message);
                });
            }
        }

        return res.json({
            success: true,
            message: "Artwork updated successfully.",
            artwork: { id, title, artist, medium, price, stock, image_url: imageUrl }
        });
    } catch (err) {
        console.error("EDIT ARTWORK ERROR:", err);
        deleteUploadedFiles(req);
        return res.status(500).json({
            success: false,
            error: "Failed to update artwork."
        });
    }
});

app.delete("/api/artworks/:id", requireCreator, async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!validId(id)) {
            return res.status(400).json({
                success: false,
                error: "Invalid artwork ID."
            });
        }

        const old = await get(`SELECT * FROM artworks WHERE id=?`, [id]);

        if (!old) {
            return res.status(404).json({
                success: false,
                error: "Artwork not found."
            });
        }

        if (req.user.role !== "admin" && Number(old.user_id) !== Number(req.user.id)) {
            return res.status(403).json({
                success: false,
                error: "You can only delete your own artwork."
            });
        }

        await transaction(async () => {
            await run(`DELETE FROM cart_items WHERE artwork_id=?`, [id]);
            await run(`DELETE FROM artworks WHERE id=?`, [id]);
        });

        if (old.image_url && old.image_url.startsWith("/uploads/")) {
            const file = path.join(uploadDir, path.basename(old.image_url));
            if (fs.existsSync(file)) fs.unlink(file, () => {});
        }

        res.json({ success: true });
    } catch (err) {
        console.error("DELETE ARTWORK ERROR:", err);
        res.status(500).json({
            success: false,
            error: "Failed to delete artwork."
        });
    }
});

/* ------------------------------------------------------------------ */
/* CART                                                                */
/* ------------------------------------------------------------------ */

app.get("/api/cart", requireLogin, async (req, res) => {
    try {
        const rows = await all(`
            SELECT
                c.id,
                c.artwork_id,
                c.quantity,
                a.title,
                a.artist,
                a.price,
                a.image_url,
                a.stock,
                a.user_id AS seller_id,
                a.store_name
            FROM cart_items c
            JOIN artworks a ON a.id=c.artwork_id
            WHERE c.user_id=?
            ORDER BY c.id DESC
        `, [req.user.id]);

        res.json(rows);
    } catch (err) {
        console.error("CART GET ERROR:", err);
        res.status(500).json({ error: "Could not load cart." });
    }
});

app.post("/api/cart", requireLogin, async (req, res) => {
    try {
        const artworkId = Number(req.body.artworkId);
        const quantityRaw = req.body.quantity === undefined || req.body.quantity === ""
            ? 1
            : Number(req.body.quantity);

        if (!validId(artworkId)) {
            return res.status(400).json({ error: "Invalid artwork." });
        }

        if (!Number.isInteger(quantityRaw) || quantityRaw < 1) {
            return res.status(400).json({ error: "Quantity must be a whole number of 1 or more." });
        }

        const quantity = quantityRaw;

        const artwork = await get(
            `SELECT id,stock FROM artworks WHERE id=?`,
            [artworkId]
        );

        if (!artwork) {
            return res.status(404).json({ error: "Artwork not found." });
        }

        if (Number(artwork.stock) <= 0) {
            return res.status(400).json({ error: "This artwork is sold out." });
        }

        const existing = await get(`
            SELECT id,quantity
            FROM cart_items
            WHERE user_id=? AND artwork_id=?
        `, [req.user.id, artworkId]);

        const newQuantity = existing
            ? Number(existing.quantity) + quantity
            : quantity;

        if (newQuantity > Number(artwork.stock)) {
            return res.status(400).json({
                error: `Only ${artwork.stock} item(s) left in stock.`
            });
        }

        if (existing) {
            await run(
                `UPDATE cart_items SET quantity=? WHERE id=?`,
                [newQuantity, existing.id]
            );
        } else {
            await run(`
                INSERT INTO cart_items(user_id,artwork_id,quantity)
                VALUES(?,?,?)
            `, [req.user.id, artworkId, quantity]);
        }

        res.json({ success: true });
    } catch (err) {
        console.error("CART ADD ERROR:", err);
        res.status(500).json({ error: "Could not add item to cart." });
    }
});

app.patch("/api/cart/:id", requireLogin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        const quantity = Number(req.body.quantity);

        const item = await get(`
            SELECT c.*,a.stock
            FROM cart_items c
            JOIN artworks a ON a.id=c.artwork_id
            WHERE c.id=? AND c.user_id=?
        `, [id, req.user.id]);

        if (!item) {
            return res.status(404).json({ error: "Cart item not found." });
        }

        if (!Number.isInteger(quantity)) {
            return res.status(400).json({ error: "Quantity must be a whole number." });
        }

        if (quantity <= 0) {
            await run(`DELETE FROM cart_items WHERE id=? AND user_id=?`, [id, req.user.id]);
            return res.json({ success: true });
        }

        if (quantity > Number(item.stock)) {
            return res.status(400).json({
                error: `Only ${item.stock} item(s) available.`
            });
        }

        await run(`UPDATE cart_items SET quantity=? WHERE id=? AND user_id=?`, [quantity, id, req.user.id]);
        res.json({ success: true });
    } catch (err) {
        console.error("CART UPDATE ERROR:", err);
        res.status(500).json({ error: "Could not update cart." });
    }
});

app.delete("/api/cart/:id", requireLogin, async (req, res) => {
    try {
        await run(
            `DELETE FROM cart_items WHERE id=? AND user_id=?`,
            [Number(req.params.id), req.user.id]
        );

        res.json({ success: true });
    } catch {
        res.status(500).json({ error: "Could not remove cart item." });
    }
});

/* ------------------------------------------------------------------ */
/* CHECKOUT                                                            */
/* ------------------------------------------------------------------ */

app.post("/api/checkout", requireLogin, async (req, res) => {
    try {
        const fullName = String(req.body.fullName || "").trim();
        const email = String(req.body.email || req.user.email || "").trim();
        const contactNumber = String(req.body.contactNumber || "").trim();
        const address = String(req.body.address || "").trim();
        const country = String(req.body.country || "").trim();
        const paymentMethod = String(req.body.paymentMethod || "COD").trim();

        if (!fullName || !email || !contactNumber || !address || !country) {
            return res.status(400).json({
                success: false,
                error: "Please complete all buyer information."
            });
        }

        // The cart is read INSIDE the transaction, so what we validate is
        // exactly what we charge for and what we take out of stock.
        const orderId = await transaction(async () => {
            const cart = await all(`
                SELECT
                    c.artwork_id,
                    c.quantity,
                    a.title,
                    a.price,
                    a.stock,
                    a.user_id AS seller_id
                FROM cart_items c
                JOIN artworks a ON a.id=c.artwork_id
                WHERE c.user_id=?
            `, [req.user.id]);

            if (!cart.length) {
                throw new HttpError(400, "Your cart is empty.");
            }

            for (const item of cart) {
                if (Number(item.quantity) > Number(item.stock)) {
                    throw new HttpError(400, `"${item.title}" does not have enough stock.`);
                }
            }

            const total = cart.reduce(
                (sum, item) => sum + Number(item.price || 0) * Number(item.quantity),
                0
            );

            const order = await run(`
                INSERT INTO orders
                (buyer_id,total,full_name,email,contact_number,address,country,payment_method,status)
                VALUES (?,?,?,?,?,?,?,?,?)
            `, [
                req.user.id,
                total,
                fullName,
                email,
                contactNumber,
                address,
                country,
                paymentMethod,
                "Pending"
            ]);

            for (const item of cart) {
                const subtotal = Number(item.price || 0) * Number(item.quantity);

                await run(`
                    INSERT INTO order_items
                    (order_id,artwork_id,seller_id,title,price,quantity,subtotal,status)
                    VALUES (?,?,?,?,?,?,?,?)
                `, [
                    order.lastID,
                    item.artwork_id,
                    item.seller_id,
                    item.title,
                    item.price,
                    item.quantity,
                    subtotal,
                    "Pending"
                ]);

                const stockUpdate = await run(`
                    UPDATE artworks
                    SET stock=stock-?
                    WHERE id=? AND stock>=?
                `, [item.quantity, item.artwork_id, item.quantity]);

                if (stockUpdate.changes !== 1) {
                    throw new HttpError(400, `Insufficient stock for "${item.title}".`);
                }

                /*
                 * Notify the seller. Older artworks may have no seller
                 * (user_id is NULL); the notifications table requires a
                 * user_id, so skip those instead of failing the order.
                 */
                if (item.seller_id) {
                    await run(`
                        INSERT INTO notifications(user_id,order_id,message)
                        VALUES(?,?,?)
                    `, [
                        item.seller_id,
                        order.lastID,
                        `🛒 New order #${order.lastID}: ${item.quantity} × "${item.title}" ordered by ${fullName} (${country}).`
                    ]);
                }
            }

            await run(`DELETE FROM cart_items WHERE user_id=?`, [req.user.id]);

            return order.lastID;
        });

        res.json({ success: true, orderId });
    } catch (err) {
        sendError(res, err, "CHECKOUT ERROR", "Checkout failed.");
    }
});

/* ------------------------------------------------------------------ */
/* ORDERS                                                              */
/* ------------------------------------------------------------------ */

// Buyer order history (new).
app.get("/api/orders/mine", requireLogin, async (req, res) => {
    try {
        const orders = await all(`
            SELECT id,total,full_name,email,contact_number,address,country,
                   payment_method,status,created_at
            FROM orders
            WHERE buyer_id=?
            ORDER BY id DESC
        `, [req.user.id]);

        const items = await all(`
            SELECT
                oi.order_id,
                oi.artwork_id,
                oi.title,
                oi.price,
                oi.quantity,
                oi.subtotal,
                COALESCE(oi.status,'Pending') AS status,
                a.image_url
            FROM order_items oi
            JOIN orders o ON o.id=oi.order_id
            LEFT JOIN artworks a ON a.id=oi.artwork_id
            WHERE o.buyer_id=?
            ORDER BY oi.id ASC
        `, [req.user.id]);

        const byOrder = new Map(orders.map(o => [o.id, { ...o, items: [] }]));
        for (const item of items) {
            const order = byOrder.get(item.order_id);
            if (order) order.items.push(item);
        }

        res.json([...byOrder.values()]);
    } catch (err) {
        console.error("MY ORDERS ERROR:", err);
        res.status(500).json({ error: "Could not load your orders." });
    }
});

app.get("/api/orders/seller", requireCreator, async (req, res) => {
    try {
        const where = req.user.role === "admin" ? "" : "WHERE oi.seller_id=?";
        const params = req.user.role === "admin" ? [] : [req.user.id];

        const rows = await all(`
            SELECT
                o.id AS order_id,
                oi.id AS order_item_id,
                oi.seller_id,
                oi.artwork_id,
                oi.title,
                oi.quantity,
                oi.price,
                oi.subtotal,
                o.full_name,
                o.email,
                o.contact_number,
                o.address,
                o.country,
                o.payment_method,
                COALESCE(oi.status, o.status) AS order_status,
                o.created_at
            FROM order_items oi
            JOIN orders o ON o.id=oi.order_id
            ${where}
            ORDER BY o.id DESC
        `, params);

        res.json(rows);
    } catch (err) {
        console.error("SELLER ORDERS ERROR:", err);
        res.status(500).json({ error: "Could not load orders." });
    }
});

/*
 * Status is tracked per order ITEM, so a seller only changes their own
 * items in a mixed order. The order's overall status is derived from its items.
 * Cancelling puts the stock back; re-opening a cancelled item takes it again.
 */
app.patch("/api/orders/:id/status", requireCreator, async (req, res) => {
    try {
        const orderId = Number(req.params.id);
        const status = String(req.body.status || "Pending");

        const allowed = [
            "Pending",
            "Processing",
            "Shipped",
            "Completed",
            "Cancelled"
        ];

        if (!validId(orderId) || !allowed.includes(status)) {
            return res.status(400).json({
                success: false,
                error: "Invalid order ID or status."
            });
        }

        await transaction(async () => {
            const items = req.user.role === "admin"
                ? await all(`
                    SELECT id,artwork_id,title,quantity,COALESCE(status,'Pending') AS status
                    FROM order_items
                    WHERE order_id=?
                `, [orderId])
                : await all(`
                    SELECT id,artwork_id,title,quantity,COALESCE(status,'Pending') AS status
                    FROM order_items
                    WHERE order_id=? AND seller_id=?
                `, [orderId, req.user.id]);

            if (!items.length) {
                throw new HttpError(403, "You cannot update this order.");
            }

            for (const item of items) {
                if (item.status === status) continue;

                if (status === "Cancelled" && item.artwork_id) {
                    await run(
                        `UPDATE artworks SET stock=COALESCE(stock,0)+? WHERE id=?`,
                        [item.quantity, item.artwork_id]
                    );
                }

                if (item.status === "Cancelled" && item.artwork_id) {
                    const art = await get(`SELECT stock FROM artworks WHERE id=?`, [item.artwork_id]);

                    // If the artwork was deleted meanwhile there is no stock to take back.
                    if (art) {
                        const take = await run(
                            `UPDATE artworks SET stock=stock-? WHERE id=? AND stock>=?`,
                            [item.quantity, item.artwork_id, item.quantity]
                        );
                        if (take.changes !== 1) {
                            throw new HttpError(
                                400,
                                `Cannot re-open: not enough stock left for "${item.title}".`
                            );
                        }
                    }
                }

                await run(`UPDATE order_items SET status=? WHERE id=?`, [status, item.id]);
            }

            // Derive the overall order status from all of its items.
            const all_items = await all(
                `SELECT COALESCE(status,'Pending') AS status FROM order_items WHERE order_id=?`,
                [orderId]
            );
            const active = [...new Set(all_items.map(i => i.status).filter(s => s !== "Cancelled"))];

            let overall;
            if (!all_items.length) overall = status;
            else if (!active.length) overall = "Cancelled";
            else if (active.length === 1) overall = active[0];
            else overall = "Processing";

            await run(`UPDATE orders SET status=? WHERE id=?`, [overall, orderId]);
        });

        res.json({ success: true });
    } catch (err) {
        sendError(res, err, "ORDER STATUS ERROR", "Could not update order.");
    }
});

/* ------------------------------------------------------------------ */
/* MESSAGES                                                            */
/* ------------------------------------------------------------------ */

app.get("/api/messages/unread-count", requireLogin, async (req, res) => {
    try {
        const row = await get(`
            SELECT COUNT(*) AS count
            FROM messages
            WHERE receiver_id=? AND is_read=0
        `, [req.user.id]);

        res.json({ count: Number(row.count || 0) });
    } catch (err) {
        console.error("UNREAD COUNT ERROR:", err);
        res.status(500).json({ count: 0 });
    }
});

app.get("/api/messages/contacts", requireLogin, async (req, res) => {
    try {
        const rows = await all(`
            SELECT
                u.id,
                u.name,
                u.email,
                u.role,
                (
                    SELECT COUNT(*) FROM messages m2
                    WHERE m2.sender_id=u.id AND m2.receiver_id=? AND m2.is_read=0
                ) AS unread
            FROM users u
            WHERE u.id IN (
                SELECT sender_id FROM messages WHERE receiver_id=?
                UNION
                SELECT receiver_id FROM messages WHERE sender_id=?
            )
            AND u.id<>?
            ORDER BY u.name
        `, [req.user.id, req.user.id, req.user.id, req.user.id]);

        res.json(rows);
    } catch (err) {
        console.error("CONTACTS ERROR:", err);
        res.status(500).json({ error: "Could not load contacts." });
    }
});

app.get("/api/messages/:otherUserId", requireLogin, async (req, res) => {
    try {
        const other = Number(req.params.otherUserId);

        if (!validId(other) || other === req.user.id) {
            return res.status(400).json({ error: "Invalid contact." });
        }

        const rows = await all(`
            SELECT
                id,
                sender_id,
                receiver_id,
                artwork_id,
                order_id,
                message,
                is_read,
                created_at
            FROM messages
            WHERE
                (sender_id=? AND receiver_id=?)
                OR
                (sender_id=? AND receiver_id=?)
            ORDER BY id ASC
        `, [
            req.user.id,
            other,
            other,
            req.user.id
        ]);

        await run(`
            UPDATE messages
            SET is_read=1
            WHERE sender_id=? AND receiver_id=?
        `, [other, req.user.id]);

        res.json(rows);
    } catch (err) {
        console.error("LOAD MESSAGES ERROR:", err);
        res.status(500).json({ error: "Could not load messages." });
    }
});

app.post("/api/messages", requireLogin, async (req, res) => {
    try {
        const receiverId = Number(req.body.receiverId);
        const hasArtwork = req.body.artworkId !== undefined &&
            req.body.artworkId !== null &&
            String(req.body.artworkId).trim() !== "";
        const artworkId = hasArtwork ? Number(req.body.artworkId) : null;
        const message = String(req.body.message || "").trim();

        if (!validId(receiverId) || !message) {
            return res.status(400).json({
                success: false,
                error: "Receiver and message are required."
            });
        }

        if (receiverId === req.user.id) {
            return res.status(400).json({
                success: false,
                error: "You cannot message yourself."
            });
        }

        const receiver = await get(
            `SELECT id FROM users WHERE id=?`,
            [receiverId]
        );

        if (!receiver) {
            return res.status(404).json({
                success: false,
                error: "User not found."
            });
        }

        if (hasArtwork) {
            if (!validId(artworkId)) {
                return res.status(400).json({
                    success: false,
                    error: "Invalid artwork."
                });
            }

            const artwork = await get(`SELECT id FROM artworks WHERE id=?`, [artworkId]);
            if (!artwork) {
                return res.status(404).json({
                    success: false,
                    error: "Artwork not found."
                });
            }
        }

        const result = await run(`
            INSERT INTO messages
            (sender_id,receiver_id,artwork_id,message)
            VALUES(?,?,?,?)
        `, [
            req.user.id,
            receiverId,
            artworkId,
            message
        ]);

        res.json({
            success: true,
            messageId: result.lastID
        });
    } catch (err) {
        console.error("MESSAGE ERROR:", err);
        res.status(500).json({
            success: false,
            error: "Could not send message."
        });
    }
});

/* ------------------------------------------------------------------ */
/* NOTIFICATIONS                                                       */
/* ------------------------------------------------------------------ */

app.get("/api/notifications/unread-count", requireLogin, async (req, res) => {
    try {
        const row = await get(`
            SELECT COUNT(*) AS count
            FROM notifications
            WHERE user_id=? AND is_read=0
        `, [req.user.id]);

        res.json({ count: Number(row.count || 0) });
    } catch (err) {
        console.error("NOTIFICATION COUNT ERROR:", err);
        res.status(500).json({ count: 0 });
    }
});

app.get("/api/notifications", requireLogin, async (req, res) => {
    try {
        const rows = await all(`
            SELECT id,order_id,message,is_read,created_at
            FROM notifications
            WHERE user_id=?
            ORDER BY id DESC
        `, [req.user.id]);

        res.json(rows);
    } catch (err) {
        console.error("NOTIFICATIONS ERROR:", err);
        res.status(500).json({ error: "Could not load notifications." });
    }
});

app.post("/api/notifications/read", requireLogin, async (req, res) => {
    try {
        await run(
            `UPDATE notifications SET is_read=1 WHERE user_id=?`,
            [req.user.id]
        );

        res.json({ success: true });
    } catch (err) {
        console.error("MARK NOTIFICATIONS READ ERROR:", err);
        res.status(500).json({
            success: false,
            error: "Could not update notifications."
        });
    }
});

/* ------------------------------------------------------------------ */
/* ADMIN DATABASE VIEWER                                               */
/* ------------------------------------------------------------------ */

const DB_TABLES = ["users", "artworks", "orders", "order_items", "cart_items", "messages", "notifications"];
const HIDDEN_COLUMNS = { users: ["password"] };       // never sent to the browser
const DELETABLE_TABLES = ["users", "artworks", "cart_items", "messages", "notifications"];

async function visibleColumns(table) {
    const info = await all(`PRAGMA table_info("${table}")`);
    const hidden = HIDDEN_COLUMNS[table] || [];
    return info.map(c => c.name).filter(n => !hidden.includes(n));
}

function csvCell(value) {
    if (value === null || value === undefined) return "";
    let text = String(value);
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;   // stop spreadsheet formula injection
    return /[",\n\r]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
}

app.get("/api/admin/db/overview", requireAdmin, async (req, res) => {
    try {
        const tables = [];
        for (const name of DB_TABLES) {
            const row = await get(`SELECT COUNT(*) AS c FROM "${name}"`);
            tables.push({ name, count: Number(row.c || 0) });
        }

        let dbSize = 0;
        try { dbSize = fs.statSync(path.join(DATA_DIR, "database.sqlite")).size; } catch (e) {}

        res.json({ tables, dbSize, dataDir: DATA_DIR, production: IS_PROD });
    } catch (err) {
        console.error("DB OVERVIEW ERROR:", err);
        res.status(500).json({ error: "Could not read the database." });
    }
});

app.get("/api/admin/db/table/:name", requireAdmin, async (req, res) => {
    try {
        const table = req.params.name;
        if (!DB_TABLES.includes(table)) return res.status(404).json({ error: "Unknown table." });

        const columns = await visibleColumns(table);
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));
        const q = String(req.query.q || "").trim();

        let where = "";
        const params = [];
        if (q) {
            where = "WHERE " + columns.map(c => `CAST("${c}" AS TEXT) LIKE ?`).join(" OR ");
            columns.forEach(() => params.push(`%${q}%`));
        }

        const sort = columns.includes(req.query.sort)
            ? req.query.sort
            : (columns.includes("id") ? "id" : columns[0]);
        const dir = req.query.dir === "asc" ? "ASC" : "DESC";

        const totalRow = await get(`SELECT COUNT(*) AS c FROM "${table}" ${where}`, params);
        const rows = await all(
            `SELECT ${columns.map(c => `"${c}"`).join(",")} FROM "${table}" ${where}
             ORDER BY "${sort}" ${dir} LIMIT ? OFFSET ?`,
            [...params, limit, (page - 1) * limit]
        );

        res.json({
            table, columns, rows,
            total: Number(totalRow.c || 0),
            page, limit, sort, dir: dir.toLowerCase(),
            deletable: DELETABLE_TABLES.includes(table)
        });
    } catch (err) {
        console.error("DB TABLE ERROR:", err);
        res.status(500).json({ error: "Could not read this table." });
    }
});

app.get("/api/admin/db/export/:name", requireAdmin, async (req, res) => {
    try {
        const table = req.params.name;
        if (!DB_TABLES.includes(table)) return res.status(404).json({ error: "Unknown table." });

        const columns = await visibleColumns(table);
        const rows = await all(
            `SELECT ${columns.map(c => `"${c}"`).join(",")} FROM "${table}" ORDER BY 1 DESC LIMIT 50000`
        );

        const lines = [columns.map(csvCell).join(",")];
        for (const r of rows) lines.push(columns.map(c => csvCell(r[c])).join(","));

        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="${table}.csv"`);
        res.send("\uFEFF" + lines.join("\r\n"));
    } catch (err) {
        console.error("DB EXPORT ERROR:", err);
        res.status(500).json({ error: "Export failed." });
    }
});

// Download a consistent copy of the whole database file (contains password hashes: keep it private).
app.get("/api/admin/db/backup", requireAdmin, async (req, res) => {
    const tmp = path.join(DATA_DIR, `backup-${Date.now()}.sqlite`);
    try {
        try {
            await withLock(() => run(`VACUUM INTO ?`, [tmp]));
        } catch (e) {
            // Older SQLite without VACUUM INTO: fall back to a plain file copy.
            await fs.promises.copyFile(path.join(DATA_DIR, "database.sqlite"), tmp);
        }

        const stamp = new Date().toISOString().slice(0, 10);
        res.download(tmp, `salaksak-backup-${stamp}.sqlite`, () => fs.unlink(tmp, () => {}));
    } catch (err) {
        console.error("DB BACKUP ERROR:", err);
        fs.unlink(tmp, () => {});
        res.status(500).json({ error: "Backup failed." });
    }
});

app.delete("/api/admin/db/row/:table/:id", requireAdmin, async (req, res) => {
    try {
        const table = req.params.table;
        const id = Number(req.params.id);

        if (!DELETABLE_TABLES.includes(table)) {
            return res.status(400).json({ success: false, error: "Rows in this table cannot be deleted here." });
        }
        if (!validId(id)) return res.status(400).json({ success: false, error: "Invalid ID." });

        let imageToRemove = null;

        // Every delete runs inside the lock + a transaction so it can never
        // interleave with a checkout.
        await transaction(async () => {
            if (table === "users") {
                if (id === req.user.id) {
                    throw new HttpError(400, "You cannot delete your own account.");
                }

                const target = await get(`SELECT id,role FROM users WHERE id=?`, [id]);
                if (!target) throw new HttpError(404, "User not found.");
                if (target.role === "admin") {
                    throw new HttpError(400, "Admin accounts cannot be deleted.");
                }

                const art = await get(`SELECT COUNT(*) AS c FROM artworks WHERE user_id=?`, [id]);
                const ord = await get(`SELECT COUNT(*) AS c FROM orders WHERE buyer_id=?`, [id]);
                if (Number(art.c) > 0 || Number(ord.c) > 0) {
                    throw new HttpError(
                        400,
                        "This user still has artworks or orders. Delete their artworks first; orders are kept as records."
                    );
                }

                await run(`DELETE FROM cart_items WHERE user_id=?`, [id]);
                await run(`DELETE FROM messages WHERE sender_id=? OR receiver_id=?`, [id, id]);
                await run(`DELETE FROM notifications WHERE user_id=?`, [id]);
                await run(`DELETE FROM users WHERE id=?`, [id]);
                return;
            }

            if (table === "artworks") {
                const old = await get(`SELECT image_url FROM artworks WHERE id=?`, [id]);
                if (!old) throw new HttpError(404, "Artwork not found.");

                await run(`DELETE FROM cart_items WHERE artwork_id=?`, [id]);
                await run(`DELETE FROM artworks WHERE id=?`, [id]);
                imageToRemove = old.image_url;
                return;
            }

            await run(`DELETE FROM "${table}" WHERE id=?`, [id]);
        });

        if (imageToRemove && imageToRemove.startsWith("/uploads/")) {
            const file = path.join(uploadDir, path.basename(imageToRemove));
            if (fs.existsSync(file)) fs.unlink(file, () => {});
        }

        res.json({ success: true });
    } catch (err) {
        sendError(res, err, "DB DELETE ERROR", "Could not delete this row.");
    }
});

app.patch("/api/admin/users/:id", requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!validId(id)) return res.status(400).json({ success: false, error: "Invalid user ID." });

        const target = await get(`SELECT id,role,email,status FROM users WHERE id=?`, [id]);
        if (!target) return res.status(404).json({ success: false, error: "User not found." });
        if (target.role === "admin" || target.email === ADMIN_EMAIL) {
            return res.status(400).json({ success: false, error: "Admin accounts cannot be changed here." });
        }

        const role = req.body.role === undefined ? target.role : String(req.body.role);
        let status = req.body.status;

        if (!["buyer", "seller"].includes(role)) {
            return res.status(400).json({ success: false, error: "Role must be buyer or seller." });
        }
        if (status !== undefined && !["approved", "pending", "rejected"].includes(status)) {
            return res.status(400).json({ success: false, error: "Invalid status." });
        }

        if (status === undefined) {
            status = role === "seller" ? "approved" : target.status;
        }

        await run(
            `UPDATE users SET role=?, status=?, has_seen_approval=0 WHERE id=?`,
            [role, status, id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error("ADMIN USER UPDATE ERROR:", err);
        res.status(500).json({ success: false, error: "Could not update user." });
    }
});

/* ------------------------------------------------------------------ */
/* API FALLBACK & ERROR HANDLER                                        */
/* ------------------------------------------------------------------ */

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        error: "API endpoint not found."
    });
});

app.use((err, req, res, next) => {
    if (res.headersSent) {
        return next(err);
    }

    // Malformed JSON / oversized body etc. are the client's fault, not a 500.
    const status = Number(err && err.status);
    if (status >= 400 && status < 500) {
        return res.status(status).json({
            success: false,
            error: "Invalid request."
        });
    }

    console.error("SERVER ERROR:", err);
    res.status(500).json({
        success: false,
        error: "An unexpected server error occurred."
    });
});

/* ------------------------------------------------------------------ */
/* START SERVER                                                        */
/* ------------------------------------------------------------------ */

initializeDatabase()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Salaksak.art.net running at http://localhost:${PORT}`);
        });
    })
    .catch(err => {
        console.error("DATABASE INITIALIZATION FAILED:");
        console.error(err);
        process.exit(1);
    });