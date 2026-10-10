const express = require("express");
const session = require("express-session");
const { createClient } = require("@libsql/client");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const IS_PROD = process.env.NODE_ENV === "production";

const SESSION_SECRET = process.env.SESSION_SECRET || "salaksak-art-net-secret-key";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@salaksak.art.net";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// Never run a public site with the built-in default secrets.
if (IS_PROD && (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD)) {
    console.error("SESSION_SECRET and ADMIN_PASSWORD must be set when NODE_ENV=production.");
    process.exit(1);
}

/*
 * DATABASE: Turso (libSQL) in the cloud, so your data survives Render sleeping,
 * restarting and redeploying. Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN.
 * Without them the app falls back to a local file (database.sqlite) so you can
 * still develop on your own computer.
 */
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DB_URL = process.env.TURSO_DATABASE_URL ||
    "file:" + (process.env.DATA_DIR ? path.join(DATA_DIR, "database.sqlite") : "database.sqlite");
const IS_LOCAL_DB = DB_URL.startsWith("file:");
const RESET_ADMIN_PASSWORD = process.env.RESET_ADMIN_PASSWORD === "true";

// Online, a local file would be erased on every restart: refuse to run that way by accident.
if (IS_PROD && IS_LOCAL_DB && !process.env.DATA_DIR) {
    console.error("TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must be set when NODE_ENV=production.");
    process.exit(1);
}
if (IS_LOCAL_DB && process.env.DATA_DIR) fs.mkdirSync(DATA_DIR, { recursive: true });

const client = createClient({
    url: DB_URL,
    authToken: process.env.TURSO_AUTH_TOKEN || undefined
});

function rowToObject(columns, row) {
    const obj = {};
    columns.forEach((name, i) => { obj[name] = row[i]; });
    return obj;
}

function cleanArgs(params) {
    return params.map(v => (v === undefined ? null : v));
}

function toRunResult(rs) {
    return {
        lastID: rs.lastInsertRowid === undefined || rs.lastInsertRowid === null
            ? undefined
            : Number(rs.lastInsertRowid),
        changes: rs.rowsAffected
    };
}

async function run(sql, params = []) {
    return toRunResult(await client.execute({ sql, args: cleanArgs(params) }));
}

async function get(sql, params = []) {
    const rs = await client.execute({ sql, args: cleanArgs(params) });
    return rs.rows.length ? rowToObject(rs.columns, rs.rows[0]) : undefined;
}

async function all(sql, params = []) {
    const rs = await client.execute({ sql, args: cleanArgs(params) });
    return rs.rows.map(r => rowToObject(rs.columns, r));
}

/*
 * Run several statements as ONE all-or-nothing transaction.
 * fn receives { run, get, all } bound to the transaction.
 */
async function inTransaction(fn) {
    const tx = await client.transaction("write");
    const t = {
        run: async (sql, params = []) => toRunResult(await tx.execute({ sql, args: cleanArgs(params) })),
        get: async (sql, params = []) => {
            const rs = await tx.execute({ sql, args: cleanArgs(params) });
            return rs.rows.length ? rowToObject(rs.columns, rs.rows[0]) : undefined;
        },
        all: async (sql, params = []) => {
            const rs = await tx.execute({ sql, args: cleanArgs(params) });
            return rs.rows.map(r => rowToObject(rs.columns, r));
        }
    };

    try {
        const result = await fn(t);
        await tx.commit();
        return result;
    } catch (err) {
        try { await tx.rollback(); } catch (e) { /* already closed */ }
        throw err;
    } finally {
        tx.close();
    }
}

/* ---------- UPLOADED IMAGES (stored inside the database) ---------- */

const MAX_IMAGE_BYTES = 4 * 1024 * 1024;   // 4 MB per image

const multerUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_IMAGE_BYTES }
});

// Detect the real image type from the file's first bytes (never trust the file name).
function sniffImageType(buf) {
    if (!buf || buf.length < 12) return null;
    if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return "image/jpeg";
    if (buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return "image/png";
    const head = buf.slice(0, 6).toString("ascii");
    if (head === "GIF87a" || head === "GIF89a") return "image/gif";
    if (buf.slice(0, 4).toString("ascii") === "RIFF" && buf.slice(8, 12).toString("ascii") === "WEBP") return "image/webp";
    return null;
}

// Same API as before (upload.any()), but only real images are accepted.
const upload = {
    any() {
        const handler = multerUpload.any();
        return (req, res, next) => handler(req, res, err => {
            if (err) return next(err);
            const bad = (req.files || []).find(f => !sniffImageType(f.buffer));
            if (bad) return next(new Error("Only JPG, PNG, GIF or WebP images are allowed."));
            next();
        });
    }
};

async function saveImage(file) {
    const mime = sniffImageType(file.buffer);
    if (!mime) throw new Error("Only JPG, PNG, GIF or WebP images are allowed.");
    const result = await run(`INSERT INTO images (mime, data) VALUES (?, ?)`, [mime, file.buffer]);
    return `/uploads/img-${result.lastID}`;
}

async function deleteStoredImage(url) {
    const m = /^\/uploads\/img-(\d+)$/.exec(String(url || ""));
    if (m) await run(`DELETE FROM images WHERE id=?`, [Number(m[1])]).catch(() => {});
}

// Files are now in memory, so there is nothing to clean up. Kept so existing calls still work.
function deleteUploadedFiles() {}

/* ---------- SESSIONS (stored in the database, so logins survive restarts) ---------- */

class DbSessionStore extends session.Store {
    get(sid, cb) {
        get(`SELECT sess, expires FROM sessions WHERE sid=?`, [sid])
            .then(row => {
                if (!row) return cb(null, null);
                if (Number(row.expires) < Date.now()) {
                    run(`DELETE FROM sessions WHERE sid=?`, [sid]).catch(() => {});
                    return cb(null, null);
                }
                cb(null, JSON.parse(row.sess));
            })
            .catch(err => cb(err));
    }

    set(sid, sess, cb) {
        const exp = sess && sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : NaN;
        const expires = Number.isFinite(exp) ? exp : Date.now() + 7 * 24 * 60 * 60 * 1000;
        run(
            `INSERT INTO sessions (sid, sess, expires) VALUES (?,?,?)
             ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expires=excluded.expires`,
            [sid, JSON.stringify(sess), expires]
        ).then(() => cb && cb(null)).catch(err => cb && cb(err));
    }

    touch(sid, sess, cb) {
        const exp = sess && sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : NaN;
        if (!Number.isFinite(exp)) return cb && cb(null);
        run(`UPDATE sessions SET expires=? WHERE sid=?`, [exp, sid])
            .then(() => cb && cb(null)).catch(err => cb && cb(err));
    }

    destroy(sid, cb) {
        run(`DELETE FROM sessions WHERE sid=?`, [sid])
            .then(() => cb && cb(null)).catch(err => cb && cb(err));
    }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve uploaded images from the database.
app.get("/uploads/:name", async (req, res) => {
    const m = /^img-(\d+)$/.exec(req.params.name);
    if (!m) return res.status(404).end();
    try {
        const row = await get(`SELECT mime, data FROM images WHERE id=?`, [Number(m[1])]);
        if (!row) return res.status(404).end();
        res.set({
            "Content-Type": row.mime,
            "Cache-Control": "public, max-age=31536000, immutable",
            "X-Content-Type-Options": "nosniff"
        });
        res.send(Buffer.from(row.data));
    } catch (err) {
        console.error("IMAGE ERROR:", err);
        res.status(500).end();
    }
});

// Behind Nginx / a host's HTTPS proxy: needed for secure cookies to work.
app.set("trust proxy", 1);

app.use(session({
    store: new DbSessionStore(),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: IS_PROD,          // cookie only sent over HTTPS when online
        httpOnly: true,
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 24 * 7   // stay signed in for 7 days
    }
}));

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

async function addColumn(table, column, definition) {
    // Only needed for old local files; a fresh cloud database already has every column.
    if (!IS_LOCAL_DB) return;
    try {
        await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    } catch (err) {
        if (!/duplicate column name/i.test(err.message)) throw err;
    }
}

async function initializeDatabase() {
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

    await run(`
        CREATE TABLE IF NOT EXISTS sessions (
            sid TEXT PRIMARY KEY,
            sess TEXT NOT NULL,
            expires INTEGER NOT NULL
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mime TEXT NOT NULL,
            data BLOB NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    const admin = await get(`SELECT id FROM users WHERE email = ?`, [ADMIN_EMAIL]);

    if (!admin) {
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
    } else if (RESET_ADMIN_PASSWORD) {
        // Only when you set RESET_ADMIN_PASSWORD=true for one deploy.
        await run(`
            UPDATE users
            SET password=?, role='admin', status='approved'
            WHERE email=?
        `, [hash, ADMIN_EMAIL]);
        console.log("Admin password was reset from ADMIN_PASSWORD.");
    } else {
        await run(`
            UPDATE users
            SET role='admin', status='approved'
            WHERE email=?
        `, [ADMIN_EMAIL]);
    }

    console.log(IS_LOCAL_DB ? "Database ready (local file)." : "Database ready (Turso cloud).");
}

async function loadUser(req, res, next) {
    if (!req.session || !req.session.userId) {
        req.user = null;
        return next();
    }

    try {
        const user = await get(`SELECT * FROM users WHERE id = ?`, [req.session.userId]);

        if (!user) {
            req.user = null;
        } else {
            req.user = user;

            // Only touch the session when something changed (each change is a database write).
            if (
                req.session.role !== user.role ||
                req.session.status !== user.status ||
                req.session.name !== user.name ||
                req.session.email !== user.email
            ) {
                req.session.role = user.role;
                req.session.status = user.status;
                req.session.name = user.name;
                req.session.email = user.email;
            }
        }
    } catch (err) {
        console.error("LOAD USER ERROR:", err);
        req.user = null;
    }

    next();
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

/* SESSION */

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

/* AUTH */

app.post("/api/register", upload.any(), async (req, res) => {
    deleteUploadedFiles(req);

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

        req.session.userId = result.lastID;
        req.session.role = "buyer";
        req.session.status = "approved";
        req.session.name = name;
        req.session.email = email;

        res.json({ success: true, redirect: "index.html" });
    } catch (err) {
        console.error("REGISTER ERROR:", err);
        res.status(500).json({ success: false, error: "Registration failed." });
    }
});

app.post("/api/login", upload.any(), async (req, res) => {
    deleteUploadedFiles(req);

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

        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.status = user.status;
        req.session.name = user.name;
        req.session.email = user.email;

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

app.post("/api/apply-seller", loadUser, (req, res) => {
    upload.any()(req, res, async uploadErr => {
        if (uploadErr) {
            return res.status(400).json({
                success: false,
                error: "File upload failed: " + uploadErr.message
            });
        }

        try {
            const storeName = String(req.body.store_name || "My Art Studio").trim();
            const file = req.files && req.files[0];
            const portfolioUrl = file ? await saveImage(file) : "";

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

                req.session.userId = result.lastID;
                req.session.role = "buyer";
                req.session.status = "pending";
                req.session.name = name;
                req.session.email = email;

                return res.json({ success: true, redirect: "pending.html" });
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
});

app.post("/api/logout", (req, res) => {
    req.session.destroy(() => {
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

/* ADMIN */

app.get("/api/admin/applications", requireLogin, async (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Unauthorized." });
    }

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

app.post("/api/admin/review-seller", requireLogin, async (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({ success: false, error: "Unauthorized." });
    }

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

        await run(`
            UPDATE users
            SET role=?, status=?, has_seen_approval=0
            WHERE id=?
        `, [role, decision, userId]);

        res.json({ success: true });
    } catch {
        res.status(500).json({
            success: false,
            error: "Could not review application."
        });
    }
});

/* ARTWORK CATALOG */

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

app.get("/api/my-artworks", requireCreator, async (req, res) => {
    try {
        const rows = req.user.role === "admin"
            ? await all("SELECT a.*, COALESCE(a.stock, 1) AS stock FROM artworks a ORDER BY a.id DESC")
            : await all(
                "SELECT a.*, COALESCE(a.stock, 1) AS stock FROM artworks a WHERE a.user_id = ? ORDER BY a.id DESC",
                [req.user.id]
            );

        res.json(rows);
    } catch (err) {
        console.error("MY ARTWORKS ERROR:", err);
        res.status(500).json({
            success: false,
            error: "Could not load your collection."
        });
    }
});

app.get("/api/seller/artworks", requireCreator, async (req, res) => {
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
        console.error("SELLER ARTWORKS ERROR:", err);
        res.status(500).json({ error: "Could not load your collection." });
    }
});

app.post("/api/artworks", requireCreator, (req, res) => {
    upload.any()(req, res, async uploadErr => {
        if (uploadErr) {
            return res.status(400).json({
                success: false,
                error: "Image upload failed: " + uploadErr.message
            });
        }

        try {
            const title = String(req.body.title || "").trim();
            const artist = String(req.body.artist || req.user.name || "").trim();
            const medium = String(req.body.medium || "").trim();
            const price = Number(req.body.price || 0);
            const stock = Math.max(0, Number(req.body.stock ?? 1));
            const file = req.files && req.files[0];
            const imageUrl = file ? await saveImage(file) : "";
            const storeName = req.user.store_name || "Studio Gallery";

            if (!title) {
                deleteUploadedFiles(req);
                return res.status(400).json({
                    success: false,
                    error: "Title is required."
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
});

/*
 * EDIT ARTWORK
 * Accepts JSON or multipart (when the seller replaces the image).
 * Medium is no longer required: older artworks with an empty medium
 * used to be impossible to edit.
 */
app.put("/api/artworks/:id", requireCreator, (req, res) => {
    upload.any()(req, res, async uploadErr => {
        if (uploadErr) {
            deleteUploadedFiles(req);
            return res.status(400).json({
                success: false,
                error: "Image upload failed: " + uploadErr.message
            });
        }

        try {
            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id <= 0) {
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
            const imageUrl = file ? await saveImage(file) : (old.image_url || "");

            await run(`
                UPDATE artworks
                SET title=?, artist=?, medium=?, price=?, stock=?, image_url=?
                WHERE id=?
            `, [title, artist, medium, price, stock, imageUrl, id]);

            if (file) await deleteStoredImage(old.image_url);

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
});

app.delete("/api/artworks/:id", requireCreator, async (req, res) => {
    try {
        const id = Number(req.params.id);
        const old = await get(`SELECT * FROM artworks WHERE id=?`, [id]);

        if (!old) {
            return res.status(404).json({
                success: false,
                error: "Artwork not found."
            });
        }

        if (req.user.role !== "admin" && old.user_id !== req.user.id) {
            return res.status(403).json({
                success: false,
                error: "You can only delete your own artwork."
            });
        }

        await run(`DELETE FROM artworks WHERE id=?`, [id]);

        await deleteStoredImage(old.image_url);

        res.json({ success: true });
    } catch (err) {
        console.error("DELETE ARTWORK ERROR:", err);
        res.status(500).json({
            success: false,
            error: "Failed to delete artwork."
        });
    }
});

/* CART */

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
        const quantity = Math.max(1, Number(req.body.quantity || 1));

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

        if (quantity <= 0) {
            await run(`DELETE FROM cart_items WHERE id=?`, [id]);
            return res.json({ success: true });
        }

        if (!Number.isInteger(quantity) || quantity > Number(item.stock)) {
            return res.status(400).json({
                error: `Only ${item.stock} item(s) available.`
            });
        }

        await run(`UPDATE cart_items SET quantity=? WHERE id=?`, [quantity, id]);
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

/* CHECKOUT */

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
            return res.status(400).json({
                success: false,
                error: "Your cart is empty."
            });
        }

        for (const item of cart) {
            if (Number(item.quantity) > Number(item.stock)) {
                return res.status(400).json({
                    success: false,
                    error: `"${item.title}" does not have enough stock.`
                });
            }
        }

        const total = cart.reduce(
            (sum, item) => sum + Number(item.price || 0) * Number(item.quantity),
            0
        );

        const orderId = await inTransaction(async t => {
            try {
                const order = await t.run(`
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

                    await t.run(`
                        INSERT INTO order_items
                        (order_id,artwork_id,seller_id,title,price,quantity,subtotal)
                        VALUES (?,?,?,?,?,?,?)
                    `, [
                        order.lastID,
                        item.artwork_id,
                        item.seller_id,
                        item.title,
                        item.price,
                        item.quantity,
                        subtotal
                    ]);

                    const stockUpdate = await t.run(`
                        UPDATE artworks
                        SET stock=stock-?
                        WHERE id=? AND stock>=?
                    `, [item.quantity, item.artwork_id, item.quantity]);

                    if (stockUpdate.changes !== 1) {
                        throw new Error(`Insufficient stock for "${item.title}".`);
                    }

                    /*
                     * Notify the seller. Older artworks may have no seller
                     * (user_id is NULL); the notifications table requires a
                     * user_id, so skip those instead of failing the order.
                     */
                    if (item.seller_id) {
                        await t.run(`
                            INSERT INTO notifications(user_id,order_id,message)
                            VALUES(?,?,?)
                        `, [
                            item.seller_id,
                            order.lastID,
                            `🛒 New order #${order.lastID}: ${item.quantity} × "${item.title}" ordered by ${fullName} (${country}).`
                        ]);
                    }
                }

                await t.run(`DELETE FROM cart_items WHERE user_id=?`, [req.user.id]);
                return order.lastID;
            } catch (err) {
                throw err;      // inTransaction() rolls everything back
            }
        });

        res.json({ success: true, orderId });
    } catch (err) {
        console.error("CHECKOUT ERROR:", err);
        res.status(400).json({
            success: false,
            error: err.message || "Checkout failed."
        });
    }
});

/* SELLER ORDERS */

app.get("/api/orders/seller", requireCreator, async (req, res) => {
    try {
        const where = req.user.role === "admin" ? "" : "WHERE oi.seller_id=?";
        const params = req.user.role === "admin" ? [] : [req.user.id];

        const rows = await all(`
            SELECT
                o.id AS order_id,
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
                o.status AS order_status,
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

        if (req.user.role !== "admin") {
            const owned = await get(`
                SELECT oi.id
                FROM order_items oi
                WHERE oi.order_id=? AND oi.seller_id=?
                LIMIT 1
            `, [orderId, req.user.id]);

            if (!owned) {
                return res.status(403).json({
                    success: false,
                    error: "You cannot update this order."
                });
            }
        }

        await run(`UPDATE orders SET status=? WHERE id=?`, [status, orderId]);
        res.json({ success: true });
    } catch (err) {
        console.error("ORDER STATUS ERROR:", err);
        res.status(500).json({
            success: false,
            error: "Could not update order."
        });
    }
});

/* MESSAGES */

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
        const artworkId = req.body.artworkId
            ? Number(req.body.artworkId)
            : null;
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

/* NOTIFICATIONS */

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

/* ADMIN DATABASE VIEWER */

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
        try {
            const sz = await get(
                `SELECT (SELECT page_count FROM pragma_page_count()) * (SELECT page_size FROM pragma_page_size()) AS bytes`
            );
            dbSize = Number((sz && sz.bytes) || 0);
        } catch (e) { /* size is optional */ }

        let where = "local file";
        if (!IS_LOCAL_DB) {
            try { where = "Turso cloud · " + new URL(DB_URL.replace(/^libsql:/, "https:")).hostname; }
            catch (e) { where = "Turso cloud"; }
        }

        res.json({ tables, dbSize, dataDir: where, production: IS_PROD, cloud: !IS_LOCAL_DB });
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

// Download all table data as one JSON file (contains password hashes: keep it private).
// Uploaded images stay in the database and are not part of this file.
app.get("/api/admin/db/backup", requireAdmin, async (req, res) => {
    try {
        const backup = { exportedAt: new Date().toISOString(), tables: {} };
        for (const name of DB_TABLES) {
            backup.tables[name] = await all(`SELECT * FROM "${name}"`);
        }
        backup.images = await all(`SELECT id, mime, created_at, LENGTH(data) AS bytes FROM images`);

        const stamp = new Date().toISOString().slice(0, 10);
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="salaksak-backup-${stamp}.json"`);
        res.send(JSON.stringify(backup, null, 2));
    } catch (err) {
        console.error("DB BACKUP ERROR:", err);
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

        if (table === "users") {
            if (id === req.user.id) {
                return res.status(400).json({ success: false, error: "You cannot delete your own account." });
            }
            const target = await get(`SELECT id,role FROM users WHERE id=?`, [id]);
            if (!target) return res.status(404).json({ success: false, error: "User not found." });
            if (target.role === "admin") {
                return res.status(400).json({ success: false, error: "Admin accounts cannot be deleted." });
            }

            const art = await get(`SELECT COUNT(*) AS c FROM artworks WHERE user_id=?`, [id]);
            const ord = await get(`SELECT COUNT(*) AS c FROM orders WHERE buyer_id=?`, [id]);
            if (Number(art.c) > 0 || Number(ord.c) > 0) {
                return res.status(400).json({
                    success: false,
                    error: "This user still has artworks or orders. Delete their artworks first; orders are kept as records."
                });
            }

            await client.batch([
                { sql: `DELETE FROM cart_items WHERE user_id=?`, args: [id] },
                { sql: `DELETE FROM messages WHERE sender_id=? OR receiver_id=?`, args: [id, id] },
                { sql: `DELETE FROM notifications WHERE user_id=?`, args: [id] },
                { sql: `DELETE FROM users WHERE id=?`, args: [id] }
            ], "write");
            return res.json({ success: true });
        }

        if (table === "artworks") {
            const old = await get(`SELECT image_url FROM artworks WHERE id=?`, [id]);
            if (!old) return res.status(404).json({ success: false, error: "Artwork not found." });

            await run(`DELETE FROM cart_items WHERE artwork_id=?`, [id]);
            await run(`DELETE FROM artworks WHERE id=?`, [id]);

            await deleteStoredImage(old.image_url);
            return res.json({ success: true });
        }

        await run(`DELETE FROM "${table}" WHERE id=?`, [id]);
        res.json({ success: true });
    } catch (err) {
        console.error("DB DELETE ERROR:", err);
        res.status(500).json({ success: false, error: "Could not delete this row." });
    }
});

app.patch("/api/admin/users/:id", requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!validId(id)) return res.status(400).json({ success: false, error: "Invalid user ID." });

        const target = await get(`SELECT id,role,email FROM users WHERE id=?`, [id]);
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
            const current = await get(`SELECT status FROM users WHERE id=?`, [id]);
            status = role === "seller" ? "approved" : current.status;
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

/* API FALLBACK */

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        error: "API endpoint not found."
    });
});

/* ERROR HANDLER */

app.use((err, req, res, next) => {
    console.error("SERVER ERROR:", err);

    if (res.headersSent) {
        return next(err);
    }

    res.status(500).json({
        success: false,
        error: "An unexpected server error occurred."
    });
});

/* START SERVER */

initializeDatabase()
    .then(() => {
        setInterval(() => {
            run(`DELETE FROM sessions WHERE expires < ?`, [Date.now()]).catch(() => {});
        }, 6 * 60 * 60 * 1000).unref();

        app.listen(PORT, () => {
            console.log(`Salaksak.art.net running at http://localhost:${PORT}`);
        });
    })
    .catch(err => {
        console.error("DATABASE INITIALIZATION FAILED:");
        console.error(err);
        process.exit(1);
    });