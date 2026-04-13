const { readDb, writeDb } = require("./store");

function corruptAuditLog() {
  const db = readDb();
  if (db.auditLogs.length === 0) {
    console.error("No audit logs found to corrupt.");
    return;
  }

  const indexToCorrupt = 0; // Corrupt the first entry
  const originalAction = db.auditLogs[indexToCorrupt].action;
  db.auditLogs[indexToCorrupt].action = "MALICIOUS_TAMPERED_ACTION";

  console.log(`Corrupting audit log at index ${indexToCorrupt}...`);
  console.log(`Original: ${originalAction} -> Tampered: ${db.auditLogs[indexToCorrupt].action}`);

  writeDb(db);
  console.log("Database updated with corrupted log entry.");
}

function restoreAuditLog() {
  const db = readDb();
  if (db.auditLogs.length === 0) {
    console.error("No audit logs found to restore.");
    return;
  }

  // Note: This is a simple mock. In a real scenario, we'd need to know what it was.
  // For the demo, we'll just run some actions to generate new valid logs.
  console.log("Restoration involves re-generating valid logs or clearing the chain.");
}

const command = process.argv[2];
if (command === "corrupt") {
  corruptAuditLog();
} else if (command === "restore") {
  restoreAuditLog();
} else {
  console.log("Usage: node security_demo_setup.js [corrupt|restore]");
}
