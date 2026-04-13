const { Redis } = require("@upstash/redis");
const {
  DATA_DIR,
  STORAGE_DIR,
  RESUME_DIR,
} = require("./config");
const fs = require("fs");

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const DB_KEY = "CAREERS_DB_V1";

const DEFAULT_DB = {
  users: [],
  companies: [],
  jobs: [],
  applications: [],
  conversations: [],
  auditLogs: [],
};

function normalizeDb(parsed) {
  return {
    users: Array.isArray(parsed?.users) ? parsed.users : [],
    companies: Array.isArray(parsed?.companies) ? parsed.companies : [],
    jobs: Array.isArray(parsed?.jobs) ? parsed.jobs : [],
    applications: Array.isArray(parsed?.applications) ? parsed.applications : [],
    conversations: Array.isArray(parsed?.conversations) ? parsed.conversations : [],
    auditLogs: Array.isArray(parsed?.auditLogs) ? parsed.auditLogs : [],
  };
}

// In a serverless environment, we still need these for temporary resume buffers
function ensureDirectories() {
  [DATA_DIR, STORAGE_DIR, RESUME_DIR].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
}

async function readDb() {
  try {
    const data = await redis.get(DB_KEY);
    if (!data) {
      await redis.set(DB_KEY, DEFAULT_DB);
      return normalizeDb(DEFAULT_DB);
    }
    return normalizeDb(data);
  } catch (error) {
    console.error("Redis Read Error:", error);
    return normalizeDb(DEFAULT_DB);
  }
}

async function writeDb(db) {
  try {
    await redis.set(DB_KEY, normalizeDb(db));
  } catch (error) {
    console.error("Redis Write Error:", error);
  }
}

module.exports = {
  ensureDirectories,
  readDb,
  writeDb,
};
