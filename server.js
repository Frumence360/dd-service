const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");

const ROOT = __dirname;
loadEnvFile();

const PORT = Number(process.env.PORT) || 3000;
const HTTPS_ENABLED = process.env.HTTPS_ENABLED === "true";
const HTTPS_PFX = process.env.HTTPS_PFX || path.join(ROOT, "certs", "localhost.pfx");
const HTTPS_PASSPHRASE = process.env.HTTPS_PASSPHRASE || "";
const IS_VERCEL = Boolean(process.env.VERCEL);
const DATA_DIR = path.join(ROOT, "data");
const SEED_DATA_FILE = path.join(DATA_DIR, "stock.json");
const RUNTIME_DATA_DIR = IS_VERCEL ? path.join(os.tmpdir(), "dd-service-data") : DATA_DIR;
const DATA_FILE = path.join(RUNTIME_DATA_DIR, "stock.json");
const BACKUP_DIR = path.join(RUNTIME_DATA_DIR, "backups");
const DATABASE_URL = process.env.DATABASE_URL || "";
const DATABASE_SSL = process.env.DATABASE_SSL !== "false";
const USER_ENV_KEYS = [
  { role: "admin", env: "ADMIN_PASSWORD_HASH" },
  { role: "magasinier", env: "MAGASINIER_PASSWORD_HASH" },
  { role: "lecture", env: "LECTURE_PASSWORD_HASH" }
];
const SESSION_COOKIE = "manfordSession";
const CSRF_COOKIE = "manfordCsrf";
const CSRF_HEADER = "x-csrf-token";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8;
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_MS = 1000 * 60 * 5;
const COOKIE_SECURE = HTTPS_ENABLED || IS_VERCEL || process.env.COOKIE_SECURE === "true";
const DEFAULT_COMPANY_NAME = "DD Service";
const DEFAULT_COMPANY_SLUG = "dd-service";
const loginAttempts = new Map();
const ALLOWED_CATEGORIES = new Set(["Materiaux", "Alimentation", "Equipement", "Autre"]);
const PRODUCT_FIELDS = new Set(["name", "category", "quantity", "threshold", "unitPrice", "updatedAt"]);
const HISTORY_FIELDS = new Set(["date", "product", "type", "quantity", "remaining", "note"]);
let pgPool = null;
let databaseReadyPromise = null;
let defaultCompanyId = null;
const USER_ROLES = new Set(["admin", "magasinier", "lecture"]);
const SUBSCRIPTION_PLANS = new Set(["free", "starter", "pro"]);
const INVITATION_ROLES = new Set(["admin", "magasinier", "lecture"]);
const USERNAME_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N} ._'-]{2,79}$/u;

function loadEnvFile() {
  const envFile = path.join(ROOT, ".env");
  if (!fs.existsSync(envFile)) return;

  fs.readFileSync(envFile, "utf8")
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith("#"))
    .forEach(line => {
      const index = line.indexOf("=");
      if (index === -1) return;

      const key = line.slice(0, index).trim();
      const value = line.slice(index + 1).trim().replace(/^["']|["']$/g, "");
      if (!process.env[key]) {
        process.env[key] = value;
      }
    });
}

const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".jpg": "image/jpeg",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".webp": "image/webp"
};

const securityHeaders = {
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-src https://www.google.com",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join("; "),
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "X-Frame-Options": "DENY"
};

function applySecurityHeaders(response) {
  Object.entries(securityHeaders).forEach(([name, value]) => {
    response.setHeader(name, value);
  });

  if (HTTPS_ENABLED) {
    response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}

function ensureDataFile() {
  fs.mkdirSync(RUNTIME_DATA_DIR, { recursive: true });
  fs.mkdirSync(BACKUP_DIR, { recursive: true });

  if (!fs.existsSync(DATA_FILE)) {
    if (IS_VERCEL && fs.existsSync(SEED_DATA_FILE)) {
      fs.copyFileSync(SEED_DATA_FILE, DATA_FILE);
      return;
    }

    fs.writeFileSync(DATA_FILE, JSON.stringify({ products: {}, history: [] }, null, 2));
  }
}

function backupStockFile() {
  ensureDataFile();

  if (!fs.existsSync(DATA_FILE)) return;

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupFile = path.join(BACKUP_DIR, `stock-${timestamp}.json`);
  fs.copyFileSync(DATA_FILE, backupFile);

  const backups = fs.readdirSync(BACKUP_DIR)
    .filter(file => /^stock-.+\.json$/.test(file))
    .sort();

  while (backups.length > 20) {
    fs.unlinkSync(path.join(BACKUP_DIR, backups.shift()));
  }
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function hashInvitationToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createInvitationToken() {
  return crypto.randomBytes(32).toString("hex");
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function configuredUsers() {
  return USER_ENV_KEYS
    .map(user => ({ role: user.role, passwordHash: process.env[user.env] }))
    .filter(user => Boolean(user.passwordHash));
}

function sessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;

  const hashes = configuredUsers().map(user => user.passwordHash).join("|");
  return crypto.createHash("sha256").update(`${hashes}|dd-service-session`).digest("hex");
}

function sign(value) {
  return crypto.createHmac("sha256", sessionSecret()).update(value).digest("base64url");
}

function createSessionToken(session) {
  const payload = base64UrlEncode(JSON.stringify(session));
  return `${payload}.${sign(payload)}`;
}

function readSessionToken(token) {
  const [payload, signature] = String(token || "").split(".");
  if (!payload || !signature) return null;

  const expectedSignature = sign(payload);
  if (signature.length !== expectedSignature.length) return null;

  try {
    const validSignature = crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );

    if (!validSignature) return null;
  } catch {
    return null;
  }

  try {
    return JSON.parse(base64UrlDecode(payload));
  } catch {
    return null;
  }
}

function findUserByPassword(password) {
  return configuredUsers().find(user => safePasswordHashMatch(password, user.passwordHash)) || null;
}

function parseCookies(request) {
  return Object.fromEntries(
    (request.headers.cookie || "")
      .split(";")
      .map(cookie => cookie.trim())
      .filter(Boolean)
      .map(cookie => {
        const index = cookie.indexOf("=");
        if (index === -1) return [cookie, ""];
        return [cookie.slice(0, index), safeDecodeURIComponent(cookie.slice(index + 1))];
      })
  );
}

function getSession(request) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token) return null;

  const session = readSessionToken(token);
  if (!session || session.expiresAt < Date.now()) {
    return null;
  }

  return session;
}

function cookie(name, value, { httpOnly = true, maxAge = SESSION_TTL_MS / 1000 } = {}) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${maxAge}`
  ];

  if (httpOnly) parts.push("HttpOnly");
  if (COOKIE_SECURE) parts.push("Secure");

  return parts.join("; ");
}

function sendJson(response, status, payload, headers = {}) {
  const responseHeaders = {
    "Content-Type": "application/json; charset=utf-8",
    ...headers
  };
  const setCookie = responseHeaders["Set-Cookie"];
  delete responseHeaders["Set-Cookie"];

  if (setCookie) {
    response.setHeader("Set-Cookie", setCookie);
  }

  response.writeHead(status, responseHeaders);
  response.end(JSON.stringify(payload));
}

function clientIp(request) {
  return request.socket.remoteAddress || "unknown";
}

function loginState(request) {
  const ip = clientIp(request);
  const state = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (state.lockedUntil && state.lockedUntil <= Date.now()) {
    loginAttempts.delete(ip);
    return { ip, state: { count: 0, lockedUntil: 0 } };
  }

  return { ip, state };
}

function recordLoginFailure(ip, state) {
  const nextCount = state.count + 1;
  loginAttempts.set(ip, {
    count: nextCount,
    lockedUntil: nextCount >= LOGIN_MAX_ATTEMPTS ? Date.now() + LOGIN_LOCK_MS : 0
  });
}

function clearLoginFailures(ip) {
  loginAttempts.delete(ip);
}

function normalizeName(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function productKey(value) {
  return normalizeName(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("fr-FR");
}

function assertKnownFields(item, allowedFields, label) {
  Object.keys(item).forEach(field => {
    if (!allowedFields.has(field)) {
      throw new Error(`${label}: champ non autorise "${field}"`);
    }
  });
}

function assertFiniteNumber(value, label, { integer = false, min = 0, max = 1_000_000_000 } = {}) {
  const number = Number(value);

  if (!Number.isFinite(number) || number < min || number > max || (integer && !Number.isInteger(number))) {
    throw new Error(`${label}: valeur numerique invalide`);
  }

  return number;
}

function assertText(value, label, { min = 1, max = 120 } = {}) {
  const text = normalizeName(value);

  if (text.length < min || text.length > max) {
    throw new Error(`${label}: texte invalide`);
  }

  return text;
}

function normalizeUsername(value) {
  return normalizeName(value).toLocaleLowerCase("fr-FR");
}

function validateUsername(value) {
  const username = assertText(value, "Compte.identifiant", { min: 3, max: 80 });
  if (!USERNAME_PATTERN.test(username)) {
    throw new Error("Compte.identifiant: utilisez 3 a 80 lettres, chiffres, espaces ou . _ - '");
  }
  return username;
}

function validateUserRole(value) {
  const role = String(value || "").trim();
  if (!USER_ROLES.has(role)) {
    throw new Error("Compte.role: role non autorise");
  }
  return role;
}

function validateUserPassword(value, { required = true } = {}) {
  if (!required && (value === undefined || value === null || value === "")) return null;

  const password = String(value || "");
  if (password.length < 8 || password.length > 128) {
    throw new Error("Compte.motDePasse: 8 a 128 caracteres requis");
  }
  return password;
}

function validateUserId(value) {
  const id = String(value || "").trim();
  if (!/^\d+$/.test(id) || Number(id) <= 0 || Number(id) > Number.MAX_SAFE_INTEGER) {
    throw new Error("Identifiant de compte invalide");
  }
  return id;
}

function safePasswordHashMatch(password, expectedHash) {
  const actual = Buffer.from(hashPassword(password), "utf8");
  const expected = Buffer.from(String(expectedHash || ""), "utf8");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function validateUserPayload(data, { partial = false } = {}) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Donnees de compte invalides");
  }

  const allowedFields = partial
    ? new Set(["username", "name", "role", "password", "active"])
    : new Set(["username", "name", "role", "password"]);
  assertKnownFields(data, allowedFields, "Compte");

  const rawUsername = data.username === undefined ? data.name : data.username;
  const result = {};
  if (!partial || rawUsername !== undefined) {
    result.username = validateUsername(rawUsername);
  }
  if (!partial || data.role !== undefined) {
    result.role = validateUserRole(data.role);
  }
  if (!partial || data.password !== undefined) {
    result.password = validateUserPassword(data.password, { required: !partial });
  }
  if (data.active !== undefined) {
    if (typeof data.active !== "boolean") throw new Error("Compte.actif: valeur booleenne requise");
    result.active = data.active;
  }

  return result;
}

function assertIsoDate(value, label) {
  const date = String(value || "");

  if (!date || Number.isNaN(Date.parse(date))) {
    throw new Error(`${label}: date invalide`);
  }

  return date;
}

function validateProduct(rawProduct) {
  if (!rawProduct || typeof rawProduct !== "object" || Array.isArray(rawProduct)) {
    throw new Error("Produit invalide");
  }

  assertKnownFields(rawProduct, PRODUCT_FIELDS, "Produit");

  const product = {
    name: assertText(rawProduct.name, "Produit.nom", { max: 80 }),
    category: assertText(rawProduct.category, "Produit.categorie", { max: 40 }),
    quantity: assertFiniteNumber(rawProduct.quantity, "Produit.quantite", { integer: true }),
    threshold: assertFiniteNumber(rawProduct.threshold, "Produit.seuil", { integer: true }),
    unitPrice: assertFiniteNumber(rawProduct.unitPrice, "Produit.prix", { integer: false }),
    updatedAt: rawProduct.updatedAt ? assertIsoDate(rawProduct.updatedAt, "Produit.date") : new Date().toISOString()
  };

  if (!ALLOWED_CATEGORIES.has(product.category)) {
    throw new Error("Produit.categorie: categorie non autorisee");
  }

  return product;
}

function validateHistoryItem(rawItem) {
  if (!rawItem || typeof rawItem !== "object" || Array.isArray(rawItem)) {
    throw new Error("Historique invalide");
  }

  assertKnownFields(rawItem, HISTORY_FIELDS, "Historique");

  const item = {
    date: assertIsoDate(rawItem.date, "Historique.date"),
    product: assertText(rawItem.product, "Historique.produit", { max: 80 }),
    type: assertText(rawItem.type, "Historique.type", { max: 20 }),
    quantity: assertFiniteNumber(rawItem.quantity, "Historique.quantite", { integer: true }),
    remaining: assertFiniteNumber(rawItem.remaining, "Historique.restant", { integer: true }),
    note: rawItem.note ? String(rawItem.note).trim().slice(0, 200) : ""
  };

  if (!["Entree", "Sortie"].includes(item.type)) {
    throw new Error("Historique.type: type non autorise");
  }

  return item;
}

function validateStockPayload(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Donnees de stock invalides");
  }

  assertKnownFields(data, new Set(["products", "history"]), "Stock");

  if (!data.products || typeof data.products !== "object" || Array.isArray(data.products)) {
    throw new Error("Stock.products invalide");
  }

  if (!Array.isArray(data.history)) {
    throw new Error("Stock.history invalide");
  }

  const products = {};
  Object.values(data.products).forEach(rawProduct => {
    const product = validateProduct(rawProduct);
    products[productKey(product.name)] = product;
  });

  return {
    products,
    history: data.history.slice(-200).map(validateHistoryItem)
  };
}

function useDatabase() {
  return Boolean(DATABASE_URL);
}

function getPgPool() {
  if (pgPool) return pgPool;

  let Pool;
  try {
    ({ Pool } = require("pg"));
  } catch {
    throw new Error("Le module PostgreSQL est manquant. Lance npm install avant d'utiliser DATABASE_URL.");
  }

  pgPool = new Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_SSL ? { rejectUnauthorized: false } : false
  });

  return pgPool;
}

async function queryDatabase(text, params = []) {
  const pool = getPgPool();
  return pool.query(text, params);
}

function productFromRow(row) {
  return {
    name: row.name,
    category: row.category,
    quantity: Number(row.quantity),
    threshold: Number(row.threshold),
    unitPrice: Number(row.unit_price),
    updatedAt: new Date(row.updated_at).toISOString()
  };
}

function historyFromRow(row) {
  return {
    date: new Date(row.date).toISOString(),
    product: row.product,
    type: row.type,
    quantity: Number(row.quantity),
    remaining: Number(row.remaining),
    note: row.note || ""
  };
}

async function ensureDatabase() {
  if (!useDatabase()) return;

  if (!databaseReadyPromise) {
    databaseReadyPromise = (async () => {
      await queryDatabase(`
        CREATE TABLE IF NOT EXISTS companies (
          id BIGSERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          slug TEXT NOT NULL UNIQUE,
          address TEXT NOT NULL DEFAULT '',
          phone TEXT NOT NULL DEFAULT '',
          logo_url TEXT NOT NULL DEFAULT '',
          currency TEXT NOT NULL DEFAULT 'USD',
          default_threshold INTEGER NOT NULL DEFAULT 10 CHECK (default_threshold >= 0),
          active BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);

      const companyResult = await queryDatabase(`
        INSERT INTO companies (name, slug)
        VALUES ($1, $2)
        ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, updated_at = now()
        RETURNING id
      `, [DEFAULT_COMPANY_NAME, DEFAULT_COMPANY_SLUG]);
      defaultCompanyId = String(companyResult.rows[0].id);
      await queryDatabase("ALTER TABLE companies ADD COLUMN IF NOT EXISTS address TEXT NOT NULL DEFAULT ''");
      await queryDatabase("ALTER TABLE companies ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT ''");
      await queryDatabase("ALTER TABLE companies ADD COLUMN IF NOT EXISTS logo_url TEXT NOT NULL DEFAULT ''");
      await queryDatabase("ALTER TABLE companies ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'USD'");
      await queryDatabase("ALTER TABLE companies ADD COLUMN IF NOT EXISTS default_threshold INTEGER NOT NULL DEFAULT 10");

      await queryDatabase(`
        CREATE TABLE IF NOT EXISTS products (
          key TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          category TEXT NOT NULL,
          quantity INTEGER NOT NULL CHECK (quantity >= 0),
          threshold INTEGER NOT NULL CHECK (threshold >= 0),
          unit_price NUMERIC(14, 2) NOT NULL CHECK (unit_price >= 0),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);

      await queryDatabase(`
        CREATE TABLE IF NOT EXISTS history (
          id BIGSERIAL PRIMARY KEY,
          date TIMESTAMPTZ NOT NULL DEFAULT now(),
          product TEXT NOT NULL,
          type TEXT NOT NULL CHECK (type IN ('Entree', 'Sortie')),
          quantity INTEGER NOT NULL CHECK (quantity >= 0),
          remaining INTEGER NOT NULL CHECK (remaining >= 0),
          note TEXT NOT NULL DEFAULT ''
        )
      `);

      await queryDatabase("ALTER TABLE products ADD COLUMN IF NOT EXISTS company_id BIGINT");
      await queryDatabase("ALTER TABLE history ADD COLUMN IF NOT EXISTS company_id BIGINT");
      await queryDatabase("UPDATE products SET company_id = $1 WHERE company_id IS NULL", [defaultCompanyId]);
      await queryDatabase("UPDATE history SET company_id = $1 WHERE company_id IS NULL", [defaultCompanyId]);
      await queryDatabase(`
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'products_company_id_fkey'
          ) THEN
            ALTER TABLE products
              ADD CONSTRAINT products_company_id_fkey
              FOREIGN KEY (company_id) REFERENCES companies(id);
          END IF;
          IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'history_company_id_fkey'
          ) THEN
            ALTER TABLE history
              ADD CONSTRAINT history_company_id_fkey
              FOREIGN KEY (company_id) REFERENCES companies(id);
          END IF;
        END $$;
      `);
      await queryDatabase("ALTER TABLE products ALTER COLUMN company_id SET NOT NULL");
      await queryDatabase("ALTER TABLE history ALTER COLUMN company_id SET NOT NULL");
      await queryDatabase(`
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'products_pkey' AND contype = 'p'
          ) THEN
            ALTER TABLE products DROP CONSTRAINT products_pkey;
            ALTER TABLE products ADD CONSTRAINT products_pkey PRIMARY KEY (company_id, key);
          END IF;
        END $$;
      `);
      await queryDatabase("CREATE INDEX IF NOT EXISTS products_company_id_idx ON products (company_id)");
      await queryDatabase("CREATE INDEX IF NOT EXISTS history_company_id_date_idx ON history (company_id, date DESC)");

      await queryDatabase(`
        CREATE TABLE IF NOT EXISTS users (
          id BIGSERIAL PRIMARY KEY,
          username TEXT NOT NULL UNIQUE,
          role TEXT NOT NULL CHECK (role IN ('admin', 'magasinier', 'lecture')),
          password_hash TEXT NOT NULL,
          active BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);

      await queryDatabase(`
        CREATE TABLE IF NOT EXISTS company_memberships (
          id BIGSERIAL PRIMARY KEY,
          company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          role TEXT NOT NULL CHECK (role IN ('admin', 'magasinier', 'lecture')),
          active BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE (company_id, user_id)
        )
      `);
      await queryDatabase(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id BIGSERIAL PRIMARY KEY,
          company_id BIGINT REFERENCES companies(id) ON DELETE SET NULL,
          actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
          action TEXT NOT NULL,
          entity_type TEXT NOT NULL,
          entity_id TEXT,
          metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
          ip_address INET,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      await queryDatabase(
        "CREATE INDEX IF NOT EXISTS audit_logs_company_date_idx ON audit_logs (company_id, created_at DESC)"
      );
      await queryDatabase(`
        CREATE TABLE IF NOT EXISTS subscriptions (
          company_id BIGINT PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
          plan TEXT NOT NULL DEFAULT 'free',
          status TEXT NOT NULL DEFAULT 'trialing',
          current_period_end TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '30 days'),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      await queryDatabase(`
        INSERT INTO subscriptions (company_id)
        SELECT id FROM companies
        WHERE NOT EXISTS (
          SELECT 1 FROM subscriptions WHERE subscriptions.company_id = companies.id
        )
      `);
      await queryDatabase(`
        CREATE TABLE IF NOT EXISTS invitations (
          id BIGSERIAL PRIMARY KEY,
          company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
          email TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('admin', 'magasinier', 'lecture')),
          token_hash TEXT NOT NULL UNIQUE,
          expires_at TIMESTAMPTZ NOT NULL,
          accepted_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      await queryDatabase("CREATE INDEX IF NOT EXISTS invitations_company_idx ON invitations (company_id, created_at DESC)");
      await queryDatabase(`
        INSERT INTO company_memberships (company_id, user_id, role)
        SELECT $1, id, role
        FROM users
        WHERE NOT EXISTS (
          SELECT 1
          FROM company_memberships membership
          WHERE membership.company_id = $1 AND membership.user_id = users.id
        )
      `, [defaultCompanyId]);

      const count = await queryDatabase("SELECT COUNT(*)::int AS count FROM products");
      if (count.rows[0].count === 0 && fs.existsSync(SEED_DATA_FILE)) {
        const seed = validateStockPayload(JSON.parse(fs.readFileSync(SEED_DATA_FILE, "utf8")));
        await writeStockToDatabase(seed);
      }
    })();
  }

  await databaseReadyPromise;
}

async function readStockFromDatabase(companyId = defaultCompanyId) {
  await ensureDatabase();

  const [productResult, historyResult] = await Promise.all([
    queryDatabase("SELECT * FROM products WHERE company_id = $1 ORDER BY name ASC", [companyId]),
    queryDatabase(`
      SELECT date, product, type, quantity, remaining, note
      FROM (
        SELECT id, date, product, type, quantity, remaining, note
        FROM history
        WHERE company_id = $1
        ORDER BY date DESC, id DESC
        LIMIT 200
      ) recent
      ORDER BY date ASC, id ASC
    `, [companyId])
  ]);

  const products = {};
  productResult.rows.forEach(row => {
    const product = productFromRow(row);
    products[row.key] = product;
  });

  return {
    products,
    history: historyResult.rows.map(historyFromRow)
  };
}

async function writeStockToDatabase(data, companyId = defaultCompanyId) {
  const payload = validateStockPayload(data);
  const pool = getPgPool();
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM history WHERE company_id = $1", [companyId]);
    await client.query("DELETE FROM products WHERE company_id = $1", [companyId]);

    for (const [key, product] of Object.entries(payload.products)) {
      await client.query(`
        INSERT INTO products (key, name, category, quantity, threshold, unit_price, updated_at, company_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [
        key,
        product.name,
        product.category,
        product.quantity,
        product.threshold,
        product.unitPrice,
        product.updatedAt,
        companyId
      ]);
    }

    for (const item of payload.history) {
      await client.query(`
        INSERT INTO history (date, product, type, quantity, remaining, note, company_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        item.date,
        item.product,
        item.type,
        item.quantity,
        item.remaining,
        item.note,
        companyId
      ]);
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function writeAuditLog({
  request,
  companyId = null,
  actorUserId = null,
  action,
  entityType,
  entityId = null,
  metadata = {}
}) {
  if (!useDatabase()) return;
  await ensureDatabase();
  await queryDatabase(`
    INSERT INTO audit_logs
      (company_id, actor_user_id, action, entity_type, entity_id, metadata, ip_address)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
  `, [
    companyId,
    actorUserId,
    action,
    entityType,
    entityId,
    JSON.stringify(metadata),
    request?.socket?.remoteAddress || null
  ]);
}

async function readAuditLogs(companyId, limit = 100) {
  await ensureDatabase();
  const result = await queryDatabase(`
    SELECT audit_logs.id, audit_logs.action, audit_logs.entity_type,
           audit_logs.entity_id, audit_logs.metadata, audit_logs.created_at,
           users.username AS actor
    FROM audit_logs
    LEFT JOIN users ON users.id = audit_logs.actor_user_id
    WHERE audit_logs.company_id = $1
    ORDER BY audit_logs.created_at DESC, audit_logs.id DESC
    LIMIT $2
  `, [companyId, limit]);
  return result.rows.map(row => ({
    id: String(row.id),
    action: row.action,
    entityType: row.entity_type,
    entityId: row.entity_id,
    metadata: row.metadata || {},
    actor: row.actor || "Système",
    createdAt: new Date(row.created_at).toISOString()
  }));
}

async function readSubscription(companyId) {
  const result = await queryDatabase(
    "SELECT company_id, plan, status, current_period_end, updated_at FROM subscriptions WHERE company_id = $1",
    [companyId]
  );
  return result.rows[0] ? {
    companyId: String(result.rows[0].company_id),
    plan: result.rows[0].plan,
    status: result.rows[0].status,
    currentPeriodEnd: new Date(result.rows[0].current_period_end).toISOString(),
    updatedAt: new Date(result.rows[0].updated_at).toISOString()
  } : null;
}

function validateInvitationEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254) {
    throw new Error("Adresse e-mail invalide");
  }
  return email;
}

async function readStockReport(companyId, reportType) {
  const stock = await readStock(companyId);
  const products = Object.values(stock.products);
  if (reportType === "inventory") return { products };
  if (reportType === "low-stock") {
    return { products: products.filter(product => product.quantity <= product.threshold) };
  }
  if (reportType === "stock-value") {
    return {
      currency: (await readCompanySettings(companyId))?.currency || "USD",
      total: products.reduce((sum, product) => sum + product.quantity * product.unitPrice, 0),
      products
    };
  }
  if (reportType === "movements") return { history: stock.history };
  throw new Error("Type de rapport invalide");
}

async function deleteProductFromDatabase(key, companyId = defaultCompanyId) {
  await ensureDatabase();
  const pool = getPgPool();
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    const productResult = await client.query(
      "DELETE FROM products WHERE key = $1 AND company_id = $2 RETURNING *",
      [key, companyId]
    );

    if (productResult.rowCount === 0) {
      await client.query("ROLLBACK");
      return false;
    }

    const product = productFromRow(productResult.rows[0]);
    await client.query(`
      INSERT INTO history (date, product, type, quantity, remaining, note, company_id)
      VALUES ($1, $2, 'Sortie', 0, 0, 'Produit supprime', $3)
    `, [new Date().toISOString(), product.name, companyId]);

    await client.query("COMMIT");
    return true;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function userFromRow(row) {
  return {
    id: String(row.id),
    username: row.username,
    role: row.role,
    active: Boolean(row.active),
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString()
  };
}

async function readUsersFromDatabase(companyId = null) {
  await ensureDatabase();
  const result = companyId
    ? await queryDatabase(`
        SELECT users.id, users.username, users.role AS account_role,
               company_memberships.role, company_memberships.active,
               users.created_at, company_memberships.updated_at
        FROM users
        INNER JOIN company_memberships ON company_memberships.user_id = users.id
        WHERE company_memberships.company_id = $1
        ORDER BY users.username ASC
      `, [companyId])
    : await queryDatabase(`
        SELECT id, username, role AS account_role, role, active, created_at, updated_at
        FROM users
        ORDER BY username ASC
      `);
  return result.rows.map(userFromRow);
}

async function findDatabaseUserById(id) {
  await ensureDatabase();
  const result = await queryDatabase(`
    SELECT id, username, role, password_hash, active, created_at, updated_at
    FROM users
    WHERE id = $1
  `, [id]);
  return result.rows[0] || null;
}

async function findDatabaseUserByUsername(username) {
  await ensureDatabase();
  const result = await queryDatabase(`
    SELECT id, username, role, password_hash, active, created_at, updated_at
    FROM users
    WHERE LOWER(username) = LOWER($1)
  `, [String(username || "").trim()]);
  return result.rows[0] || null;
}

async function ensureFallbackUserInDatabase(role, passwordHash) {
  await ensureDatabase();
  const username = role;
  const result = await queryDatabase(`
    INSERT INTO users (username, role, password_hash)
    VALUES ($1, $2, $3)
    ON CONFLICT (username) DO UPDATE
      SET role = EXCLUDED.role, password_hash = EXCLUDED.password_hash,
          active = TRUE, updated_at = now()
    RETURNING id, username, role, password_hash, active
  `, [username, role, passwordHash]);
  const user = result.rows[0];
  await queryDatabase(`
    INSERT INTO company_memberships (company_id, user_id, role)
    VALUES ($1, $2, $3)
    ON CONFLICT (company_id, user_id) DO UPDATE
      SET role = EXCLUDED.role, active = TRUE, updated_at = now()
  `, [defaultCompanyId, user.id, role]);
  return user;
}

function companyFromRow(row) {
  return {
    id: String(row.id),
    name: row.name,
    slug: row.slug,
    active: Boolean(row.active),
    address: row.address || "",
    phone: row.phone || "",
    logoUrl: row.logo_url || "",
    currency: row.currency || "USD",
    defaultThreshold: Number(row.default_threshold) || 0
  };
}

async function readCompaniesForUser(userId) {
  await ensureDatabase();
  const result = await queryDatabase(`
    SELECT companies.id, companies.name, companies.slug, companies.address,
           companies.phone, companies.logo_url, companies.currency,
           companies.default_threshold, companies.active
    FROM companies
    INNER JOIN company_memberships
      ON company_memberships.company_id = companies.id
    WHERE company_memberships.user_id = $1
      AND company_memberships.active = TRUE
      AND companies.active = TRUE
    ORDER BY companies.name ASC
  `, [userId]);
  return result.rows.map(companyFromRow);
}

const COMPANY_CURRENCIES = new Set(["USD", "EUR", "CAD", "GBP", "CHF", "XOF"]);

function validateCompanySettings(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Parametres d'entreprise invalides");
  }
  assertKnownFields(data, new Set(["name", "address", "phone", "logoUrl", "currency", "defaultThreshold"]), "Parametres");
  const currency = String(data.currency || "").trim().toUpperCase();
  if (!COMPANY_CURRENCIES.has(currency)) {
    throw new Error("Entreprise.devise: devise non autorisee");
  }
  const logoUrl = String(data.logoUrl || "").trim();
  if (logoUrl && !/^https?:\/\/[^\s]+$/i.test(logoUrl)) {
    throw new Error("Entreprise.logo: URL invalide");
  }
  return {
    name: validateCompanyName(data.name),
    address: String(data.address || "").trim().slice(0, 240),
    phone: String(data.phone || "").trim().slice(0, 40),
    logoUrl: logoUrl.slice(0, 500),
    currency,
    defaultThreshold: assertFiniteNumber(data.defaultThreshold, "Entreprise.seuil", { integer: true })
  };
}

async function readCompanySettings(companyId) {
  await ensureDatabase();
  const result = await queryDatabase(`
    SELECT id, name, slug, address, phone, logo_url, currency,
           default_threshold, active
    FROM companies
    WHERE id = $1 AND active = TRUE
  `, [companyId]);
  if (result.rowCount === 0) return null;
  return companyFromRow(result.rows[0]);
}

async function updateCompanySettings(companyId, settings) {
  await ensureDatabase();
  const result = await queryDatabase(`
    UPDATE companies
    SET name = $1, address = $2, phone = $3, logo_url = $4,
        currency = $5, default_threshold = $6, updated_at = now()
    WHERE id = $7 AND active = TRUE
    RETURNING id, name, slug, address, phone, logo_url, currency,
              default_threshold, active
  `, [
    settings.name,
    settings.address,
    settings.phone,
    settings.logoUrl,
    settings.currency,
    settings.defaultThreshold,
    companyId
  ]);
  return result.rowCount > 0 ? companyFromRow(result.rows[0]) : null;
}

async function hasActiveCompanyMembership(userId, companyId) {
  await ensureDatabase();
  const result = await queryDatabase(`
    SELECT 1
    FROM company_memberships
    INNER JOIN companies ON companies.id = company_memberships.company_id
    WHERE company_memberships.user_id = $1
      AND company_memberships.company_id = $2
      AND company_memberships.active = TRUE
      AND companies.active = TRUE
  `, [userId, companyId]);
  return result.rowCount > 0;
}

function validateCompanyId(value) {
  const id = String(value || "").trim();
  if (!/^\d+$/.test(id) || Number(id) <= 0 || Number(id) > Number.MAX_SAFE_INTEGER) {
    throw new Error("Identifiant d'entreprise invalide");
  }
  return id;
}

function validateCompanyName(value) {
  return assertText(value, "Entreprise.nom", { min: 2, max: 120 });
}

function validateCompanySlug(value) {
  const slug = String(value || "").trim().toLocaleLowerCase("fr-FR");
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug) || slug.length > 80) {
    throw new Error("Entreprise.identifiant: format invalide");
  }
  return slug;
}

async function getCompanyMembership(userId, companyId) {
  await ensureDatabase();
  const result = await queryDatabase(`
    SELECT company_id, user_id, role, active
    FROM company_memberships
    WHERE company_id = $1 AND user_id = $2
  `, [companyId, userId]);
  return result.rows[0] || null;
}

async function requireCompanyAdmin(request, response, companyId) {
  const session = await requireActiveSession(request, response);
  if (!session) return null;
  const membership = session.userId
    ? await getCompanyMembership(session.userId, companyId)
    : null;
  if (!membership || !membership.active || membership.role !== "admin") {
    sendJson(response, 403, { error: "Action reservee a l'administrateur de cette entreprise" });
    return null;
  }
  return session;
}

async function createCompanyInDatabase(name, slug, userId) {
  await ensureDatabase();
  const client = await getPgPool().connect();
  try {
    await client.query("BEGIN");
    const companyResult = await client.query(`
      INSERT INTO companies (name, slug)
      VALUES ($1, $2)
      RETURNING id, name, slug, active
    `, [name, slug]);
    const company = companyFromRow(companyResult.rows[0]);
    await client.query(`
      INSERT INTO company_memberships (company_id, user_id, role)
      VALUES ($1, $2, 'admin')
    `, [company.id, userId]);
    await client.query(`
      INSERT INTO subscriptions (company_id, plan, status)
      VALUES ($1, 'free', 'trialing')
    `, [company.id]);
    await client.query("COMMIT");
    return company;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function readCompanyMembers(companyId) {
  const result = await queryDatabase(`
    SELECT users.id, users.username, company_memberships.role,
           company_memberships.active, company_memberships.updated_at
    FROM company_memberships
    INNER JOIN users ON users.id = company_memberships.user_id
    WHERE company_memberships.company_id = $1
    ORDER BY users.username ASC
  `, [companyId]);
  return result.rows.map(row => ({
    id: String(row.id),
    username: row.username,
    role: row.role,
    active: Boolean(row.active),
    updatedAt: new Date(row.updated_at).toISOString()
  }));
}

async function addCompanyMember(companyId, userId, role) {
  const result = await queryDatabase(`
    INSERT INTO company_memberships (company_id, user_id, role)
    VALUES ($1, $2, $3)
    ON CONFLICT (company_id, user_id)
    DO UPDATE SET role = EXCLUDED.role, active = TRUE, updated_at = now()
    RETURNING company_id, user_id, role, active, updated_at
  `, [companyId, userId, role]);
  return result.rows[0];
}

async function countCompanyAdmins(companyId, excludeUserId = null) {
  const params = [companyId];
  let query = `
    SELECT COUNT(*)::int AS count
    FROM company_memberships
    WHERE company_id = $1 AND role = 'admin' AND active = TRUE
  `;
  if (excludeUserId !== null) {
    params.push(excludeUserId);
    query += " AND user_id <> $2";
  }
  const result = await queryDatabase(query, params);
  return result.rows[0].count;
}

function setSessionCompany(response, session, companyId) {
  const token = createSessionToken({
    csrfToken: session.csrfToken,
    role: session.role,
    userId: session.userId,
    companyId,
    expiresAt: session.expiresAt
  });
  response.setHeader("Set-Cookie", cookie(SESSION_COOKIE, token, { httpOnly: true }));
}

async function countActiveAdmins(excludeId = null) {
  const params = [];
  let query = "SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin' AND active = TRUE";
  if (excludeId !== null) {
    params.push(excludeId);
    query += " AND id <> $1";
  }
  const result = await queryDatabase(query, params);
  return result.rows[0].count;
}

function accountManagementUnavailable(response) {
  sendJson(response, 503, {
    error: "Gestion des comptes indisponible: configurez DATABASE_URL pour utiliser les comptes persistants."
  });
}

async function requireAdmin(request, response) {
  const session = await requireActiveSession(request, response);
  if (!session) return null;
  if (session.role !== "admin") {
    sendJson(response, 403, { error: "Gestion des comptes reservee a l'administrateur" });
    return null;
  }
  return session;
}

async function requireActiveSession(request, response) {
  const session = getSession(request);
  if (!session) {
    sendJson(response, 401, { error: "Non authentifie" });
    return null;
  }

  if (useDatabase() && session.userId) {
    const user = await findDatabaseUserById(session.userId);
    if (!user || !user.active) {
      sendJson(response, 401, { error: "Compte desactive ou introuvable" });
      return null;
    }
    const activeCompanyId = session.companyId || defaultCompanyId;
    if (!(await hasActiveCompanyMembership(session.userId, activeCompanyId))) {
      sendJson(response, 403, { error: "Accès à l'entreprise active refusé" });
      return null;
    }
    const membership = await getCompanyMembership(session.userId, activeCompanyId);
    if (!membership || !membership.active) {
      sendJson(response, 403, { error: "Accès à l'entreprise active refusé" });
      return null;
    }
    return {
      ...session,
      role: membership.role,
      companyId: activeCompanyId
    };
  }

  return session;
}

async function createUserInDatabase(payload, companyId = defaultCompanyId) {
  await ensureDatabase();
  const duplicate = await queryDatabase(
    "SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1",
    [payload.username]
  );
  if (duplicate.rowCount > 0) {
    const error = new Error("Cet identifiant est deja utilise.");
    error.code = "23505";
    throw error;
  }
  const result = await queryDatabase(`
    INSERT INTO users (username, role, password_hash)
    VALUES ($1, $2, $3)
    RETURNING id, username, role, active, created_at, updated_at
  `, [payload.username, payload.role, hashPassword(payload.password)]);
  await queryDatabase(`
    INSERT INTO company_memberships (company_id, user_id, role)
    VALUES ($1, $2, $3)
  `, [companyId, result.rows[0].id, payload.role]);
  return userFromRow(result.rows[0]);
}

async function updateUserInDatabase(id, payload, companyId = defaultCompanyId) {
  await ensureDatabase();
  if (payload.username !== undefined) {
    const duplicate = await queryDatabase(
      "SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) AND id <> $2 LIMIT 1",
      [payload.username, id]
    );
    if (duplicate.rowCount > 0) {
      const error = new Error("Cet identifiant est deja utilise.");
      error.code = "23505";
      throw error;
    }
  }
  const fields = [];
  const params = [];
  const addField = (sql, value) => {
    params.push(value);
    fields.push(`${sql} $${params.length}`);
  };

  if (payload.username !== undefined) addField("username =", payload.username);
  if (payload.role !== undefined) addField("role =", payload.role);
  if (payload.password !== undefined) addField("password_hash =", hashPassword(payload.password));
  if (payload.active !== undefined) addField("active =", payload.active);

  if (fields.length === 0) throw new Error("Aucune modification demandee");
  fields.push("updated_at = now()");
  params.push(id);
  const result = await queryDatabase(`
    UPDATE users
    SET ${fields.join(", ")}
    WHERE id = $${params.length}
    RETURNING id, username, role, active, created_at, updated_at
  `, params);
  if (payload.role !== undefined || payload.active !== undefined) {
    const membershipFields = [];
    const membershipParams = [];
    if (payload.role !== undefined) {
      membershipParams.push(payload.role);
      membershipFields.push(`role = $${membershipParams.length}`);
    }
    if (payload.active !== undefined) {
      membershipParams.push(payload.active);
      membershipFields.push(`active = $${membershipParams.length}`);
    }
    membershipParams.push(companyId, id);
    await queryDatabase(`
      UPDATE company_memberships
      SET ${membershipFields.join(", ")}, updated_at = now()
      WHERE company_id = $${membershipParams.length - 1} AND user_id = $${membershipParams.length}
    `, membershipParams);
  }
  return result.rows[0] ? userFromRow(result.rows[0]) : null;
}

async function deleteUserFromDatabase(id) {
  await ensureDatabase();
  const result = await queryDatabase("DELETE FROM users WHERE id = $1 RETURNING id, role, active", [id]);
  return result.rows[0] || null;
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";

    request.on("data", chunk => {
      body += chunk;
      if (body.length > 1_000_000) {
        request.destroy();
        reject(new Error("Payload trop volumineux"));
      }
    });

    request.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("JSON invalide"));
      }
    });
  });
}

function readStockFile() {
  ensureDataFile();
  const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

  return {
    products: data.products && typeof data.products === "object" ? data.products : {},
    history: Array.isArray(data.history) ? data.history : []
  };
}

function writeStockFile(data) {
  ensureDataFile();
  const payload = validateStockPayload(data);
  const tempFile = `${DATA_FILE}.tmp`;

  backupStockFile();
  fs.writeFileSync(tempFile, JSON.stringify(payload, null, 2));
  fs.renameSync(tempFile, DATA_FILE);
}

async function readStock(companyId = defaultCompanyId) {
  if (useDatabase()) return readStockFromDatabase(companyId);
  return readStockFile();
}

async function writeStock(data, companyId = defaultCompanyId) {
  if (useDatabase()) {
    await ensureDatabase();
    await writeStockToDatabase(data, companyId);
    return;
  }

  writeStockFile(data);
}

function requireSession(request, response) {
  if (getSession(request)) return true;

  sendJson(response, 401, { error: "Non authentifie" });
  return false;
}

function requireCsrf(request, response, session) {
  const token = request.headers[CSRF_HEADER];

  if (!session || !token || token !== session.csrfToken) {
    sendJson(response, 403, { error: "Jeton CSRF invalide" });
    return false;
  }

  return true;
}

function canWriteStock(role) {
  return ["admin", "magasinier"].includes(role);
}

function canDeleteProduct(role) {
  return role === "admin";
}

async function handleApi(request, response, pathname) {
  if (request.method === "GET" && pathname === "/api/session") {
    const session = getSession(request);
    const activeSession = session && useDatabase() && session.userId
      ? await findDatabaseUserById(session.userId)
      : null;
    const authenticated = Boolean(session && (!session.userId || (activeSession && activeSession.active)));
    const activeMembership = authenticated && activeSession && (session.companyId || defaultCompanyId)
      ? await getCompanyMembership(activeSession.id, session.companyId || defaultCompanyId)
      : null;
    sendJson(response, 200, {
      authenticated,
      role: authenticated ? (activeMembership?.role || activeSession?.role || session?.role || null) : null,
      companyId: authenticated
        ? (session.companyId || (useDatabase() ? defaultCompanyId : null))
        : null
    });
    return;
  }

  if (request.method === "POST" && pathname === "/api/login") {
    const { ip, state } = loginState(request);

    if (configuredUsers().length === 0 && !useDatabase()) {
      sendJson(response, 500, {
        error: "Configuration serveur incomplete: variables de mots de passe manquantes."
      });
      return;
    }

    if (state.lockedUntil > Date.now()) {
      const retryAfter = Math.ceil((state.lockedUntil - Date.now()) / 1000);
      sendJson(response, 429, {
        error: "Trop de tentatives. Reessaie plus tard.",
        retryAfter
      }, {
        "Retry-After": String(retryAfter)
      });
      return;
    }

    const body = await readBody(request);
    const password = String(body.password || "");
    const identifier = normalizeUsername(body.identifier || body.username || "");
    let user = null;
    let userId = null;

    if (useDatabase()) {
      await ensureDatabase();
      if (identifier) {
        const databaseUser = await findDatabaseUserByUsername(identifier);
        if (databaseUser && databaseUser.active && safePasswordHashMatch(password, databaseUser.password_hash)) {
          user = { role: databaseUser.role };
          userId = String(databaseUser.id);
        }
      }
    }

    if (!user && !identifier) {
      user = findUserByPassword(password);
    } else if (!user && identifier) {
      const fallbackUser = configuredUsers().find(candidate => candidate.role === identifier);
      if (fallbackUser && safePasswordHashMatch(password, fallbackUser.passwordHash)) {
        user = fallbackUser;
      }
    }

    if (!user) {
      recordLoginFailure(ip, state);
      sendJson(response, 401, {
        error: "Mot de passe incorrect",
        remainingAttempts: Math.max(LOGIN_MAX_ATTEMPTS - state.count - 1, 0)
      });
      return;
    }

    if (useDatabase() && !userId && user.passwordHash) {
      const databaseUser = await ensureFallbackUserInDatabase(user.role, user.passwordHash);
      userId = String(databaseUser.id);
    }

    clearLoginFailures(ip);
    const csrfToken = crypto.randomBytes(32).toString("hex");
    const token = createSessionToken({
      csrfToken,
      role: user.role,
      userId,
      companyId: useDatabase() ? defaultCompanyId : null,
      expiresAt: Date.now() + SESSION_TTL_MS
    });

    response.setHeader("Set-Cookie", [
      cookie(SESSION_COOKIE, token, { httpOnly: true }),
      cookie(CSRF_COOKIE, csrfToken, { httpOnly: false })
    ]);
    sendJson(response, 200, { ok: true, role: user.role });
    return;
  }

  if (request.method === "POST" && pathname === "/api/logout") {
    const session = getSession(request);
    if (!requireCsrf(request, response, session)) return;

    response.setHeader("Set-Cookie", [
      cookie(SESSION_COOKIE, "", { httpOnly: true, maxAge: 0 }),
      cookie(CSRF_COOKIE, "", { httpOnly: false, maxAge: 0 })
    ]);
    sendJson(response, 200, { ok: true });
    return;
  }

  if (pathname === "/api/audit" && request.method === "GET") {
    if (!useDatabase()) {
      sendJson(response, 503, { error: "Le journal d'audit nécessite DATABASE_URL." });
      return;
    }
    const session = await requireCompanyAdmin(request, response, getSession(request)?.companyId);
    if (!session) return;
    sendJson(response, 200, { logs: await readAuditLogs(session.companyId) });
    return;
  }

  if (pathname === "/api/billing" && (request.method === "GET" || request.method === "PUT")) {
    const session = await requireCompanyAdmin(request, response, getSession(request)?.companyId);
    if (!session) return;
    if (request.method === "GET") {
      sendJson(response, 200, { subscription: await readSubscription(session.companyId) });
      return;
    }
    if (!requireCsrf(request, response, session)) return;
    const body = await readBody(request);
    const plan = String(body.plan || "").trim().toLowerCase();
    if (!SUBSCRIPTION_PLANS.has(plan)) {
      sendJson(response, 400, { error: "Plan d'abonnement invalide." });
      return;
    }
    await queryDatabase(`
      UPDATE subscriptions
      SET plan = $1, status = 'active', updated_at = now()
      WHERE company_id = $2
    `, [plan, session.companyId]);
    await writeAuditLog({
      request,
      companyId: session.companyId,
      actorUserId: session.userId,
      action: "billing.plan.update",
      entityType: "subscription",
      entityId: session.companyId,
      metadata: { plan }
    });
    sendJson(response, 200, { subscription: await readSubscription(session.companyId) });
    return;
  }

  const invitationMatch = pathname.match(/^\/api\/companies\/([^/]+)\/invitations$/);
  if (invitationMatch) {
    if (!useDatabase()) {
      sendJson(response, 503, { error: "Les invitations nécessitent DATABASE_URL." });
      return;
    }
    let companyId;
    try {
      companyId = validateCompanyId(safeDecodeURIComponent(invitationMatch[1]));
    } catch (error) {
      sendJson(response, 400, { error: error.message });
      return;
    }
    const session = await requireCompanyAdmin(request, response, companyId);
    if (!session) return;
    if (request.method === "GET") {
      const result = await queryDatabase(`
        SELECT id, email, role, expires_at, accepted_at, created_at
        FROM invitations WHERE company_id = $1 ORDER BY created_at DESC LIMIT 50
      `, [companyId]);
      sendJson(response, 200, { invitations: result.rows });
      return;
    }
    if (request.method === "POST") {
      if (!requireCsrf(request, response, session)) return;
      try {
        const body = await readBody(request);
        const email = validateInvitationEmail(body.email);
        const role = validateUserRole(body.role);
        const token = createInvitationToken();
        await queryDatabase(`
          INSERT INTO invitations (company_id, email, role, token_hash, expires_at)
          VALUES ($1, $2, $3, $4, now() + interval '7 days')
        `, [companyId, email, role, hashInvitationToken(token)]);
        await writeAuditLog({
          request, companyId, actorUserId: session.userId,
          action: "invitation.create", entityType: "invitation",
          metadata: { email, role }
        });
        sendJson(response, 201, {
          invitation: { email, role, expiresInDays: 7 },
          token
        });
      } catch (error) {
        sendJson(response, 400, { error: error.message || "Invitation impossible." });
      }
      return;
    }
    sendJson(response, 405, { error: "Methode non autorisee" });
    return;
  }

  if (pathname === "/api/invitations/accept" && request.method === "POST") {
    if (!useDatabase()) {
      sendJson(response, 503, { error: "Les invitations nécessitent DATABASE_URL." });
      return;
    }
    try {
      const body = await readBody(request);
      const token = String(body.token || "").trim();
      if (!token) throw new Error("Jeton d'invitation manquant.");
      const invitation = await queryDatabase(`
        SELECT id, company_id, role, email
        FROM invitations
        WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()
      `, [hashInvitationToken(token)]);
      if (invitation.rowCount === 0) {
        sendJson(response, 400, { error: "Invitation invalide ou expiree." });
        return;
      }
      const payload = validateUserPayload({
        username: body.username,
        role: invitation.rows[0].role,
        password: body.password
      });
      const user = await createUserInDatabase(payload, invitation.rows[0].company_id);
      await queryDatabase("UPDATE invitations SET accepted_at = now() WHERE id = $1", [invitation.rows[0].id]);
      sendJson(response, 201, { ok: true, username: user.username });
    } catch (error) {
      sendJson(response, 400, { error: error.message || "Acceptation impossible." });
    }
    return;
  }

  if (pathname.startsWith("/api/reports/") && request.method === "GET") {
    const session = await requireActiveSession(request, response);
    if (!session) return;
    try {
      const reportType = safeDecodeURIComponent(pathname.split("/").pop());
      sendJson(response, 200, await readStockReport(session.companyId, reportType));
    } catch (error) {
      sendJson(response, 400, { error: error.message || "Rapport invalide" });
    }
    return;
  }

  if (pathname === "/api/companies" && request.method === "GET") {
    const session = await requireActiveSession(request, response);
    if (!session) return;

    if (!useDatabase() || !session.userId) {
      sendJson(response, 200, {
        companies: [{ id: null, name: DEFAULT_COMPANY_NAME, slug: DEFAULT_COMPANY_SLUG, active: true }],
        activeCompanyId: null
      });
      return;
    }

    sendJson(response, 200, {
      companies: await readCompaniesForUser(session.userId),
      activeCompanyId: session.companyId
    });
    return;
  }

  if (pathname === "/api/company/settings" && (request.method === "GET" || request.method === "PUT")) {
    if (!useDatabase()) {
      sendJson(response, 503, { error: "Les parametres d'entreprise necessitent DATABASE_URL." });
      return;
    }
    const session = await requireActiveSession(request, response);
    if (!session) return;
    const settings = await readCompanySettings(session.companyId);
    if (!settings) {
      sendJson(response, 404, { error: "Entreprise introuvable." });
      return;
    }
    if (request.method === "GET") {
      sendJson(response, 200, { company: settings });
      return;
    }
    if (!requireCsrf(request, response, session)) return;
    const membership = await getCompanyMembership(session.userId, session.companyId);
    if (!membership || membership.role !== "admin") {
      sendJson(response, 403, { error: "Modification reservee a l'administrateur de cette entreprise." });
      return;
    }
    try {
      const payload = validateCompanySettings(await readBody(request));
      const updated = await updateCompanySettings(session.companyId, payload);
      await writeAuditLog({
        request,
        companyId: session.companyId,
        actorUserId: session.userId,
        action: "company.settings.update",
        entityType: "company",
        entityId: session.companyId,
        metadata: {
          name: updated.name,
          currency: updated.currency,
          defaultThreshold: updated.defaultThreshold
        }
      });
      sendJson(response, 200, { company: updated });
    } catch (error) {
      sendJson(response, 400, { error: error.message || "Modification des parametres impossible." });
    }
    return;
  }

  if (request.method === "POST" && pathname === "/api/session/company") {
    if (!useDatabase()) {
      sendJson(response, 503, {
        error: "Le changement d'entreprise nécessite DATABASE_URL."
      });
      return;
    }

    const session = await requireActiveSession(request, response);
    if (!session) return;
    if (!requireCsrf(request, response, session)) return;

    try {
      const body = await readBody(request);
      const companyId = validateCompanyId(body.companyId);
      if (!session.userId || !(await hasActiveCompanyMembership(session.userId, companyId))) {
        sendJson(response, 403, { error: "Vous n'avez pas accès à cette entreprise." });
        return;
      }

      setSessionCompany(response, session, companyId);
      await writeAuditLog({
        request,
        companyId,
        actorUserId: session.userId,
        action: "company.switch",
        entityType: "company",
        entityId: companyId
      });
      sendJson(response, 200, { ok: true, companyId });
    } catch (error) {
      sendJson(response, 400, { error: error.message || "Entreprise invalide" });
    }
    return;
  }

  if (pathname === "/api/companies" && request.method === "POST") {
    if (!useDatabase()) {
      accountManagementUnavailable(response);
      return;
    }
    const session = await requireActiveSession(request, response);
    if (!session) return;
    const companyAdmin = session.companyId
      ? await getCompanyMembership(session.userId, session.companyId)
      : null;
    if (!companyAdmin || companyAdmin.role !== "admin") {
      sendJson(response, 403, { error: "Creation reservee a l'administrateur" });
      return;
    }
    if (!requireCsrf(request, response, session)) return;

    try {
      const body = await readBody(request);
      const name = validateCompanyName(body.name);
      const slug = validateCompanySlug(body.slug || productKey(name).replace(/\s+/g, "-"));
      const company = await createCompanyInDatabase(name, slug, session.userId);
      await writeAuditLog({
        request,
        companyId: session.companyId,
        actorUserId: session.userId,
        action: "company.create",
        entityType: "company",
        entityId: company.id,
        metadata: { name: company.name, slug: company.slug }
      });
      sendJson(response, 201, { company });
    } catch (error) {
      sendJson(response, error.code === "23505" ? 409 : 400, {
        error: error.code === "23505"
          ? "Cet identifiant d'entreprise est deja utilise."
          : error.message || "Creation de l'entreprise impossible"
      });
    }
    return;
  }

  const companyMembersMatch = pathname.match(/^\/api\/companies\/([^/]+)\/members(?:\/([^/]+))?$/);
  if (companyMembersMatch) {
    if (!useDatabase()) {
      accountManagementUnavailable(response);
      return;
    }
    let companyId;
    try {
      companyId = validateCompanyId(safeDecodeURIComponent(companyMembersMatch[1]));
    } catch (error) {
      sendJson(response, 400, { error: error.message });
      return;
    }
    const session = await requireCompanyAdmin(request, response, companyId);
    if (!session) return;

    if (request.method === "GET" && !companyMembersMatch[2]) {
      sendJson(response, 200, { members: await readCompanyMembers(companyId) });
      return;
    }

    if (request.method === "POST" && !companyMembersMatch[2]) {
      if (!requireCsrf(request, response, session)) return;
      try {
        const body = await readBody(request);
        const userId = validateUserId(body.userId);
        const role = validateUserRole(body.role);
        const user = await findDatabaseUserById(userId);
        if (!user || !user.active) {
          sendJson(response, 404, { error: "Utilisateur introuvable ou desactive" });
          return;
        }
        await addCompanyMember(companyId, userId, role);
        sendJson(response, 200, { members: await readCompanyMembers(companyId) });
      } catch (error) {
        sendJson(response, 400, { error: error.message || "Rattachement impossible" });
      }
      return;
    }

    if (companyMembersMatch[2]) {
      let userId;
      try {
        userId = validateUserId(safeDecodeURIComponent(companyMembersMatch[2]));
      } catch (error) {
        sendJson(response, 400, { error: error.message });
        return;
      }
      const membership = await getCompanyMembership(userId, companyId);
      if (!membership) {
        sendJson(response, 404, { error: "Membre introuvable" });
        return;
      }
      if (request.method === "PATCH") {
        if (!requireCsrf(request, response, session)) return;
        try {
          const body = await readBody(request);
          const role = body.role === undefined ? membership.role : validateUserRole(body.role);
          const active = body.active === undefined ? membership.active : body.active;
          if (typeof active !== "boolean") throw new Error("Etat du membre invalide");
          if (membership.role === "admin" && membership.active && (role !== "admin" || !active)
              && await countCompanyAdmins(companyId, userId) === 0) {
            sendJson(response, 400, { error: "Impossible de retirer le dernier administrateur." });
            return;
          }
          await queryDatabase(`
            UPDATE company_memberships
            SET role = $1, active = $2, updated_at = now()
            WHERE company_id = $3 AND user_id = $4
          `, [role, active, companyId, userId]);
          sendJson(response, 200, { members: await readCompanyMembers(companyId) });
        } catch (error) {
          sendJson(response, 400, { error: error.message || "Modification impossible" });
        }
        return;
      }
      if (request.method === "DELETE") {
        if (!requireCsrf(request, response, session)) return;
        if (membership.role === "admin" && membership.active
            && await countCompanyAdmins(companyId, userId) === 0) {
          sendJson(response, 400, { error: "Impossible de retirer le dernier administrateur." });
          return;
        }
        await queryDatabase(
          "DELETE FROM company_memberships WHERE company_id = $1 AND user_id = $2",
          [companyId, userId]
        );
        sendJson(response, 200, { ok: true });
        return;
      }
    }
    sendJson(response, 405, { error: "Methode non autorisee" });
    return;
  }

  if (pathname === "/api/users" || pathname.startsWith("/api/users/")) {
    if (!useDatabase()) {
      accountManagementUnavailable(response);
      return;
    }

    const session = await requireAdmin(request, response);
    if (!session) return;

    if (pathname === "/api/users" && request.method === "GET") {
      sendJson(response, 200, {
        users: await readUsersFromDatabase(session.companyId),
        directory: await readUsersFromDatabase()
      });
      return;
    }

    if (pathname === "/api/users" && request.method === "POST") {
      if (!requireCsrf(request, response, session)) return;

      try {
        const payload = validateUserPayload(await readBody(request));
        const user = await createUserInDatabase(payload, session.companyId);
        await writeAuditLog({
          request,
          companyId: session.companyId,
          actorUserId: session.userId,
          action: "user.create",
          entityType: "user",
          entityId: user.id,
          metadata: { username: user.username, role: user.role }
        });
        sendJson(response, 201, { user });
      } catch (error) {
        const status = error.code === "23505" ? 409 : 400;
        sendJson(response, status, {
          error: error.code === "23505"
            ? "Cet identifiant est deja utilise."
            : error.message || "Creation du compte impossible"
        });
      }
      return;
    }

    let id;
    try {
      id = validateUserId(safeDecodeURIComponent(pathname.slice("/api/users/".length)));
    } catch (error) {
      sendJson(response, 400, { error: error.message });
      return;
    }
    const existingUser = await findDatabaseUserById(id);
    const membership = await getCompanyMembership(id, session.companyId);
    if (!existingUser || !membership) {
      sendJson(response, 404, { error: "Compte introuvable" });
      return;
    }

    if ((request.method === "PUT" || request.method === "PATCH") && pathname.startsWith("/api/users/")) {
      if (!requireCsrf(request, response, session)) return;

      try {
        const payload = validateUserPayload(await readBody(request), { partial: true });
        const nextRole = payload.role || membership.role;
        const nextActive = payload.active === undefined ? membership.active : payload.active;
        if (membership.role === "admin" && membership.active && (nextRole !== "admin" || !nextActive)) {
          if (await countCompanyAdmins(session.companyId, id) === 0) {
            sendJson(response, 400, { error: "Impossible de desactiver ou retrograder le dernier administrateur." });
            return;
          }
        }

        const accountPayload = { ...payload };
        delete accountPayload.active;
        if (Object.keys(accountPayload).length > 0) {
          await updateUserInDatabase(id, accountPayload, session.companyId);
        }
        if (payload.active !== undefined) {
          await queryDatabase(`
            UPDATE company_memberships
            SET active = $1, updated_at = now()
            WHERE company_id = $2 AND user_id = $3
          `, [payload.active, session.companyId, id]);
        }
        const updatedUser = (await readUsersFromDatabase(session.companyId))
          .find(user => user.id === id);
        await writeAuditLog({
          request,
          companyId: session.companyId,
          actorUserId: session.userId,
          action: "user.update",
          entityType: "user",
          entityId: id,
          metadata: { role: updatedUser?.role, active: updatedUser?.active }
        });
        sendJson(response, 200, { user: updatedUser });
      } catch (error) {
        const status = error.code === "23505" ? 409 : 400;
        sendJson(response, status, {
          error: error.code === "23505"
            ? "Cet identifiant est deja utilise."
            : error.message || "Modification du compte impossible"
        });
      }
      return;
    }

    if (request.method === "DELETE") {
      if (!requireCsrf(request, response, session)) return;

      if (membership.role === "admin" && membership.active
          && await countCompanyAdmins(session.companyId, id) === 0) {
        sendJson(response, 400, { error: "Impossible de supprimer le dernier administrateur actif." });
        return;
      }

      await queryDatabase(
        "DELETE FROM company_memberships WHERE company_id = $1 AND user_id = $2",
        [session.companyId, id]
      );
      await writeAuditLog({
        request,
        companyId: session.companyId,
        actorUserId: session.userId,
        action: "user.delete",
        entityType: "user",
        entityId: id
      });
      sendJson(response, 200, { ok: true });
      return;
    }
  }

  if (pathname === "/api/stock") {
    const session = await requireActiveSession(request, response);
    if (!session) return;

    if (request.method === "GET") {
      sendJson(response, 200, await readStock(session.companyId));
      return;
    }

    if (request.method === "PUT") {
      if (!canWriteStock(session.role)) {
        sendJson(response, 403, { error: "Role insuffisant" });
        return;
      }

      if (!requireCsrf(request, response, session)) return;

      try {
        await writeStock(await readBody(request), session.companyId);
        await writeAuditLog({
          request,
          companyId: session.companyId,
          actorUserId: session.userId,
          action: "stock.update",
          entityType: "stock",
          metadata: { role: session.role }
        });
        sendJson(response, 200, { ok: true });
      } catch (error) {
        sendJson(response, 400, { error: error.message || "Donnees invalides" });
      }
      return;
    }
  }

  if (pathname.startsWith("/api/products/")) {
    const session = await requireActiveSession(request, response);
    if (!session) return;

    if (request.method === "DELETE") {
      if (!canDeleteProduct(session.role)) {
        sendJson(response, 403, { error: "Suppression reservee a l'administrateur" });
        return;
      }

      if (!requireCsrf(request, response, session)) return;

      const key = safeDecodeURIComponent(pathname.slice("/api/products/".length));
      if (useDatabase()) {
        try {
          const deleted = await deleteProductFromDatabase(key, session.companyId);
          if (!deleted) {
            sendJson(response, 404, { error: "Produit introuvable" });
            return;
          }

          await writeAuditLog({
            request,
            companyId: session.companyId,
            actorUserId: session.userId,
            action: "product.delete",
            entityType: "product",
            entityId: key
          });
          sendJson(response, 200, { ok: true });
        } catch (error) {
          sendJson(response, 500, { error: error.message || "Suppression impossible" });
        }
        return;
      }

      const data = await readStock(session.companyId);
      const product = data.products[key];

      if (!product) {
        sendJson(response, 404, { error: "Produit introuvable" });
        return;
      }

      delete data.products[key];
      data.history.push({
        date: new Date().toISOString(),
        product: product.name,
        type: "Sortie",
        quantity: 0,
        remaining: 0,
        note: "Produit supprime"
      });
      await writeStock(data, session.companyId);
      sendJson(response, 200, { ok: true });
      return;
    }
  }

  sendJson(response, 404, { error: "Route inconnue" });
}

function serveStatic(request, response, pathname) {
  const filePath = pathname === "/" ? "/index.html" : pathname;
  const safePath = safeDecodeURIComponent(filePath);
  const resolved = path.resolve(ROOT, `.${safePath}`);

  if (!resolved.startsWith(ROOT) || resolved.startsWith(DATA_DIR)) {
    response.writeHead(403);
    response.end("Acces refuse");
    return;
  }

  if (path.basename(resolved) === "stock.html" && !getSession(request)) {
    response.writeHead(302, { Location: "/connexion.html" });
    response.end();
    return;
  }

  fs.readFile(resolved, (error, content) => {
    if (error) {
      response.writeHead(404);
      response.end("Fichier introuvable");
      return;
    }

    response.writeHead(200, {
      "Content-Type": mimeTypes[path.extname(resolved)] || "application/octet-stream"
    });
    response.end(content);
  });
}

async function requestHandler(request, response) {
  try {
    applySecurityHeaders(response);
    const protocol = HTTPS_ENABLED ? "https" : "http";
    const { pathname } = new URL(request.url, `${protocol}://${request.headers.host}`);

    if (pathname.startsWith("/api/")) {
      await handleApi(request, response, pathname);
      return;
    }

    serveStatic(request, response, pathname);
  } catch (error) {
    sendJson(response, 500, { error: error.message || "Erreur serveur" });
  }
}

const server = http.createServer(requestHandler);

function createServer() {
  if (!HTTPS_ENABLED) return server;

  if (!fs.existsSync(HTTPS_PFX)) {
    console.error(`Certificat HTTPS introuvable: ${HTTPS_PFX}`);
    process.exit(1);
  }

  return https.createServer({
    pfx: fs.readFileSync(HTTPS_PFX),
    passphrase: HTTPS_PASSPHRASE
  }, async (request, response) => {
    try {
      applySecurityHeaders(response);
      const { pathname } = new URL(request.url, `https://${request.headers.host}`);

      if (pathname.startsWith("/api/")) {
        await handleApi(request, response, pathname);
        return;
      }

      serveStatic(request, response, pathname);
    } catch (error) {
      sendJson(response, 500, { error: error.message || "Erreur serveur" });
    }
  });
}

async function startServer() {
  if (useDatabase()) {
    await ensureDatabase();
  } else {
    ensureDataFile();
  }

  const activeServer = createServer();
  activeServer.on("error", error => {
    if (error.code === "EADDRINUSE") {
      console.error(`Le port ${PORT} est deja utilise.`);
      console.error("Ferme l'autre serveur ou lance avec une autre valeur PORT, par exemple: set PORT=3001");
      process.exit(1);
    }

    console.error("Erreur serveur:", error.message);
    process.exit(1);
  });

  activeServer.listen(PORT, () => {
    const protocol = HTTPS_ENABLED ? "https" : "http";
    console.log(`DD Service disponible sur ${protocol}://localhost:${PORT}`);
  });
}

if (require.main === module) {
  startServer().catch(error => {
    console.error("Demarrage impossible:", error.message);
    process.exit(1);
  });
}

module.exports = requestHandler;
