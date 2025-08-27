const { app, dialog, BrowserWindow, ipcMain, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const keytar = require("keytar");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const { authenticator } = require("otplib");
const protobuf = require("protobufjs");
const parser = require("otpauth-migration-parser");

const APP_NAME = "2DEX 1.0";
const BASE_DIR = path.join(process.env.HOME || process.env.USERPROFILE, ".vox", "apps", "2dex");
const DB_PATH = path.join(BASE_DIR, "2dex.db");
const dbPath = path.join(app.getPath("userData"), "vault.db");
// ========= crypto helpers =========
const getOrCreateMasterKey = async () => {
  let key = await keytar.getPassword("2dex", "master-key");
  if (!key) {
    key = crypto.randomBytes(32).toString("hex");
    await keytar.setPassword("2dex", "master-key", key);
    console.log("Generated master key");
  }
  return key;
};
// helper: derive AES key from PIN
function deriveKey(pin) {
  return crypto.pbkdf2Sync(pin, "2dex-salt", 100000, 32, "sha256");
}
function seal(plainText, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(key, "hex"), iv);
  const enc = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function openSealed(b64, key) {
  const raw = Buffer.from(b64, "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(key, "hex"), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

// ========= PIN hashing =========
function hashPin(pin, salt) {
  return crypto.scryptSync(pin, salt, 64).toString("hex");
}
function normalizeAccount(acc) {
  const type = (acc.type === "totp" || acc.type === "hotp") ? acc.type : "totp";
  const digits = acc.digits && acc.digits >= 6 ? acc.digits : 6;
  const period = type === "totp" ? (acc.period && acc.period > 0 ? acc.period : 30) : null;
  const algorithm = ["SHA1","SHA256","SHA512"].includes(acc.algorithm?.toUpperCase()) 
    ? acc.algorithm.toUpperCase() 
    : "SHA1";

  return {
    type,
    secret: acc.secret,
    issuer: acc.issuer || "",
    account: acc.account || "",
    algorithm,
    digits,
    period
  };
}

function toOtpauthURI(acc) {
  const label = encodeURIComponent(acc.issuer ? `${acc.issuer}:${acc.account}` : acc.account);
  const params = new URLSearchParams({
    secret: acc.secret,
    issuer: acc.issuer,
    algorithm: acc.algorithm,
    digits: acc.digits,
    ...(acc.type === "totp" ? { period: acc.period } : {})
  });
  return `otpauth://${acc.type}/${label}?${params.toString()}`;
}

// ========= DB init =========
let MASTER_KEY = null;

async function initDatabase() {
  if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });
  MASTER_KEY = await getOrCreateMasterKey();

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.prepare(`
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY,
      service TEXT NOT NULL,
      account TEXT NOT NULL,
      secret_enc TEXT NOT NULL,
      algorithm TEXT DEFAULT 'SHA1',
      digits INTEGER DEFAULT 6,
      period INTEGER DEFAULT 30
    );
  `).run();
  db.prepare(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `).run();
  db.close();
}

// ========= IPC: PIN =========
let failCount = 0;

ipcMain.handle("has-pin", () => {
  const db = new Database(DB_PATH);
  const row = db.prepare("SELECT value FROM settings WHERE key='pin'").get();
  db.close();
  return !!row;
});

ipcMain.handle("set-pin", (event, pin) => {
  if (!/^\d{4}$/.test(pin)) throw new Error("PIN must be 4 digits");
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = hashPin(pin, salt);
  const db = new Database(DB_PATH);
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('pin', ?)").run(`${salt}:${hash}`);
  db.close();
  return true;
});

ipcMain.handle("verify-pin", (event, pin) => {
  const db = new Database(DB_PATH);
  const row = db.prepare("SELECT value FROM settings WHERE key='pin'").get();
  db.close();
  if (!row) return false;

  const [salt, storedHash] = row.value.split(":");
  const entered = hashPin(pin, salt);

  if (entered === storedHash) {
    failCount = 0;
    return true;
  }
  failCount++;
  if (failCount >= 3) app.quit();
  return false;
});

ipcMain.on("quit", () => app.quit());

// === Backup (export + wipe + restart) ===
ipcMain.handle("exportVault", async (_, filePath) => {
  if (!filePath) {
    const { canceled, filePath: chosen } = await dialog.showSaveDialog({
      title: "Export Vault",
      defaultPath: "2dex-backup.db",
      filters: [{ name: "Database", extensions: ["db"] }],
    });
    if (canceled) return false;
    filePath = chosen;
  }

  // Step 1: copy DB to backup
  fs.copyFileSync(DB_PATH, filePath);

  // Step 2: wipe accounts (keep PIN/settings)
  const db = new Database(DB_PATH);
  db.prepare("DELETE FROM accounts").run();
  db.prepare("VACUUM").run(); // shrink file
  db.close();

  // Step 3: restart app
  app.relaunch();
  app.exit(0);

  return true;
});


// === Restore (import + optional delete backup + restart) ===
ipcMain.handle("importVault", async (_, filePath) => {
  if (!filePath) {
    const { canceled, filePaths } = await dialog.showOpenDialog({
      title: "Restore Vault",
      filters: [{ name: "Database", extensions: ["db", "sql"] }],
      properties: ["openFile"],
    });
    if (canceled || !filePaths.length) return false;
    filePath = filePaths[0];
  }

  // Step 1: restore DB
  fs.copyFileSync(filePath, DB_PATH);

  // Step 2: ask user if they want to delete the backup file
  const { response } = await dialog.showMessageBox({
    type: "question",
    buttons: ["Yes, delete", "No, keep"],
    defaultId: 1,
    title: "Delete Backup?",
    message: "Do you want to delete the backup file after restoring?",
    detail: filePath,
  });

  if (response === 0) {
    try {
      fs.unlinkSync(filePath);
    } catch (err) {
      console.error("Failed to delete backup file:", err);
    }
  }

  // Step 3: restart app so restored accounts load properly
  app.relaunch();
  app.exit(0);

  return true;
});

// === Self Destruct (Double Confirmation) ===
ipcMain.handle("selfDestruct", async () => {
  // First warning
  const { response: first } = await dialog.showMessageBox({
    type: "warning",
    buttons: ["Proceed", "Cancel"],
    defaultId: 1,
    cancelId: 1,
    title: "⚠️ Self Destruct",
    message: "This will permanently delete ALL your accounts.",
    detail: "⚠️ No backups will be made. You will lose everything.\n\nDo you really want to proceed?",
  });

  if (first !== 0) return false; // cancelled

  // Second confirmation
  const { response: second } = await dialog.showMessageBox({
    type: "error",
    buttons: ["🔥 Yes, I understand", "Cancel"],
    defaultId: 1,
    cancelId: 1,
    title: "💥 Final Warning",
    message: "There is NO going back after this.",
    detail: "Your vault will be wiped PERMANENTLY.\n\nAre you ABSOLUTELY sure?",
  });

  if (second !== 0) return false; // cancelled

  try {
    if (fs.existsSync(DB_PATH)) {
      fs.unlinkSync(DB_PATH);
    }
    // Optionally: wipe config folder as well
    // fs.rmSync(path.dirname(DB_PATH), { recursive: true, force: true });
  } catch (err) {
    console.error("Self Destruct failed:", err);
    return false;
  }

  app.exit(0); // 💥 quit immediately
  return true;
});


ipcMain.handle("surprise", async () => {
  const surpriseWin = new BrowserWindow({
    fullscreen: true,       // 🚀 fullscreen takeover
    frame: false,           // 🚫 no OS frame or close button
    resizable: false,
    minimizable: false,
    maximizable: false,
    closable: false,        // user can’t close it manually
    alwaysOnTop: true,      // stays above all other windows
    modal: true,
    parent: BrowserWindow.getFocusedWindow(),
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });

  const html = `
    <html>
      <head>
        <meta charset="UTF-8">
        <title>🎉 Surprise!</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
        <style>
          body { background-color: #0f172a; }
        </style>
      </head>
      <body class="flex flex-col items-center justify-center h-screen text-gray-200 font-sans select-none">
        
        <div class="text-center space-y-8">
          <h2 class="text-6xl font-extrabold text-indigo-400 drop-shadow-lg animate-pulse">
            🎁 You found a secret
          </h2>
          <p class="text-2xl text-gray-400">There’s only one way out...</p>

          <button onclick="openRickroll()" 
            class="flex items-center gap-3 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 transition px-10 py-5 rounded-3xl text-2xl font-semibold shadow-2xl">
            <i class="bi bi-music-note-beamed text-3xl"></i> 
            🎵 Click Me!
          </button>
        </div>

        <script>
          const { shell } = require("electron");
          function openRickroll() {
            shell.openExternal("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
            window.close();
          }
        </script>
      </body>
    </html>
  `;

  surpriseWin.loadURL("data:text/html;charset=UTF-8," + encodeURIComponent(html));
});


ipcMain.handle("open-user-data", async () => {
  const userDataPath = app.getPath("userData");
  await shell.openPath(userDataPath); // Opens folder in system file explorer
  return true;
});



// ========= IPC: Accounts =========
ipcMain.handle("add-account", (event, account) => {
  if (!account?.service || !account?.account || !account?.secret) {
    throw new Error("Missing fields");
  }
  const secret_enc = seal(account.secret, MASTER_KEY);
  const db = new Database(DB_PATH);
  db.prepare(`
    INSERT INTO accounts (service, account, secret_enc, algorithm, digits, period)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    account.service,
    account.account,
    secret_enc,
    account.algorithm || "SHA1",
    account.digits || 6,
    account.period || 30
  );
  db.close();
  return true;
});

ipcMain.handle("get-accounts", () => {
  const db = new Database(DB_PATH);
  const rows = db.prepare("SELECT * FROM accounts ORDER BY service, account").all();
  db.close();
  return rows.map(r => ({
    id: r.id,
    service: r.service,
    account: r.account,
    secret: (() => {
      try { return openSealed(r.secret_enc, MASTER_KEY); }
      catch { return null; }
    })(),
    algorithm: r.algorithm,
    digits: r.digits,
    period: r.period
  }));
});

// ========= IPC: OTP =========
ipcMain.handle("generate-otp", (event, secret, opts) => {
  try {
    authenticator.options = {
      digits: opts?.digits || 6,
      step: opts?.period || 30,
      algorithm: (opts?.algorithm || "SHA1").toLowerCase()
    };
    return authenticator.generate(secret);
  } catch (err) {
    console.error("OTP error:", err);
    return null;
  }
});

// ========= IPC: otpauth parser =========
function toBase32(buf) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, output = "";
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

// ========= IPC: otpauth parser =========

ipcMain.handle("parse-otpauth", async (event, uri) => {
  try {
    if (uri.startsWith("otpauth-migration://")) {
      // parser() accepts the *full URI*, not just the base64 data
      const parsedDataList = await parser(uri);

      const accounts = parsedDataList.map(acc => {
        const normalized = normalizeAccount({
          type: acc.type,
          secret: acc.secret,   // already base32
          issuer: acc.issuer || "",
          account: acc.name || "",
          algorithm: acc.algorithm.toUpperCase(),
          digits: acc.digits,
          period: acc.period || 30
        });
        return {
          ...normalized,
          uri: toOtpauthURI(normalized)
        };
      });

      return { migration: true, accounts };
    }

    if (uri.startsWith("otpauth://")) {
      const url = new URL(uri);
      const type = url.hostname;
      const secret = url.searchParams.get("secret");
      const issuerParam = url.searchParams.get("issuer") || "";
      const label = decodeURIComponent(url.pathname).replace(/^\//, "");

      let issuer = issuerParam;
      let account = label;
      if (label.includes(":")) {
        const [lhs, rhs] = label.split(":");
        if (!issuer) issuer = lhs;
        account = rhs;
      }

      return {
        migration: false,
        type,
        secret,
        issuer,
        account,
        algorithm: (url.searchParams.get("algorithm") || "SHA1").toUpperCase(),
        digits: parseInt(url.searchParams.get("digits") || "6", 10),
        period: parseInt(url.searchParams.get("period") || "30", 10)
      };
    }

    return null;
  } catch (err) {
    console.error("parse-otpauth error:", err);
    return null;
  }
});


function createWindow() {
  const win = new BrowserWindow({
    width: 760,
    height: 560,
    resizable: false,
    autoHideMenuBar: true,
    frame: true,
    maximizable: false,
    fullscreenable: false,
    icon: path.join(__dirname, "assets/logo.web"), 
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  win.loadFile("index.html");
}


app.whenReady().then(async () => {
  await initDatabase();
  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
