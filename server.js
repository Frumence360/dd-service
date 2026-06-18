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
const COOKIE_SECURE = HTTPS_ENABLED || process.env.COOKIE_SECURE === "true";
const sessions = new Map();
const loginAttempts = new Map();
const ALLOWED_CATEGORIES = new Set(["Materiaux", "Alimentation", "Equipement", "Autre"]);
const PRODUCT_FIELDS = new Set(["name", "category", "quantity", "threshold", "unitPrice", "updatedAt"]);
const HISTORY_FIELDS = new Set(["date", "product", "type", "quantity", "remaining", "note"]);

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
    "script-src 'self'",
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

function configuredUsers() {
  return USER_ENV_KEYS
    .map(user => ({ role: user.role, passwordHash: process.env[user.env] }))
    .filter(user => Boolean(user.passwordHash));
}

function findUserByPassword(password) {
  const passwordHash = hashPassword(password);

  return configuredUsers().find(user => user.passwordHash === passwordHash) || null;
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
        return [cookie.slice(0, index), decodeURIComponent(cookie.slice(index + 1))];
      })
  );
}

function getSession(request) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token) return null;

  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }

  session.expiresAt = Date.now() + SESSION_TTL_MS;
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

function readStock() {
  ensureDataFile();
  const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

  return {
    products: data.products && typeof data.products === "object" ? data.products : {},
    history: Array.isArray(data.history) ? data.history : []
  };
}

function writeStock(data) {
  ensureDataFile();
  const payload = validateStockPayload(data);
  const tempFile = `${DATA_FILE}.tmp`;

  backupStockFile();
  fs.writeFileSync(tempFile, JSON.stringify(payload, null, 2));
  fs.renameSync(tempFile, DATA_FILE);
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
    sendJson(response, 200, {
      authenticated: Boolean(session),
      role: session?.role || null
    });
    return;
  }

  if (request.method === "POST" && pathname === "/api/login") {
    const { ip, state } = loginState(request);

    if (configuredUsers().length === 0) {
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

    const user = findUserByPassword(String(body.password || ""));

    if (!user) {
      recordLoginFailure(ip, state);
      sendJson(response, 401, {
        error: "Mot de passe incorrect",
        remainingAttempts: Math.max(LOGIN_MAX_ATTEMPTS - state.count - 1, 0)
      });
      return;
    }

    clearLoginFailures(ip);
    const token = crypto.randomBytes(32).toString("hex");
    const csrfToken = crypto.randomBytes(32).toString("hex");
    sessions.set(token, { csrfToken, role: user.role, expiresAt: Date.now() + SESSION_TTL_MS });

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

    const token = parseCookies(request)[SESSION_COOKIE];
    if (token) sessions.delete(token);

    response.setHeader("Set-Cookie", [
      cookie(SESSION_COOKIE, "", { httpOnly: true, maxAge: 0 }),
      cookie(CSRF_COOKIE, "", { httpOnly: false, maxAge: 0 })
    ]);
    sendJson(response, 200, { ok: true });
    return;
  }

  if (pathname === "/api/stock") {
    const session = getSession(request);
    if (!session) {
      sendJson(response, 401, { error: "Non authentifie" });
      return;
    }

    if (request.method === "GET") {
      sendJson(response, 200, readStock());
      return;
    }

    if (request.method === "PUT") {
      if (!canWriteStock(session.role)) {
        sendJson(response, 403, { error: "Role insuffisant" });
        return;
      }

      if (!requireCsrf(request, response, session)) return;

      try {
        writeStock(await readBody(request));
        sendJson(response, 200, { ok: true });
      } catch (error) {
        sendJson(response, 400, { error: error.message || "Donnees invalides" });
      }
      return;
    }
  }

  if (pathname.startsWith("/api/products/")) {
    const session = getSession(request);
    if (!session) {
      sendJson(response, 401, { error: "Non authentifie" });
      return;
    }

    if (request.method === "DELETE") {
      if (!canDeleteProduct(session.role)) {
        sendJson(response, 403, { error: "Suppression reservee a l'administrateur" });
        return;
      }

      if (!requireCsrf(request, response, session)) return;

      const key = decodeURIComponent(pathname.slice("/api/products/".length));
      const data = readStock();
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
      writeStock(data);
      sendJson(response, 200, { ok: true });
      return;
    }
  }

  sendJson(response, 404, { error: "Route inconnue" });
}

function serveStatic(request, response, pathname) {
  const filePath = pathname === "/" ? "/index.html" : pathname;
  const resolved = path.resolve(ROOT, `.${decodeURIComponent(filePath)}`);

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

function startServer() {
  ensureDataFile();
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
  startServer();
}

module.exports = {
  requestHandler,
  startServer
};
