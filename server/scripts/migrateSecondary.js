// server/scripts/migrateSecondary.js
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database(path.join(__dirname, "..", "..", "rentchain.db"));

function hasColumn(table, col) {
  return new Promise((resolve, reject) => {
    db.all(`PRAGMA table_info(${table});`, (err, rows) => {
      if (err) return reject(err);
      resolve(rows.some(r => r.name === col));
    });
  });
}
function addColumn(table, ddl) {
  return new Promise((resolve, reject) => {
    db.run(`ALTER TABLE ${table} ADD COLUMN ${ddl};`, err => err ? reject(err) : resolve());
  });
}

(async () => {
  try {
    if (!(await hasColumn("users", "secondary_password_hash"))) await addColumn("users", "secondary_password_hash TEXT");
    if (!(await hasColumn("users", "secondary_password_salt"))) await addColumn("users", "secondary_password_salt TEXT");
    if (!(await hasColumn("users", "secondary_enabled"))) await addColumn("users", "secondary_enabled INTEGER DEFAULT 0");
    if (!(await hasColumn("users", "secondary_updated_at"))) await addColumn("users", "secondary_updated_at TEXT");
    console.log("OK: colonnes secondaires prêtes.");
  } catch (e) {
    console.error("Erreur migration:", e.message);
    process.exit(1);
  } finally {
    db.close();
  }
})();
