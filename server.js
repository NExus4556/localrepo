require("dotenv").config();

const express = require("express");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const hpp = require("hpp");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const { PORT, CORS_ORIGIN } = require("./src/config");
const { ensureDirectories } = require("./src/store");
const {
  ensureDefaultAdminAccount,
  migrateUsersAndCollectionsIfNeeded,
} = require("./src/portal-helpers");
const { registerAuthProfileRoutes } = require("./src/routes/auth-profile");
const { registerOpportunityRoutes } = require("./src/routes/opportunities");
const { registerMessagingRoutes } = require("./src/routes/messaging");
const { registerAdminRoutes } = require("./src/routes/admin");

const app = express();

const baseCorsOptions = {
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

if (CORS_ORIGIN === "*") {
  baseCorsOptions.origin = true;
} else {
  baseCorsOptions.origin = CORS_ORIGIN.split(",").map((item) => item.trim());
}

app.use(cors(baseCorsOptions));
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "img-src": ["'self'", "data:", "https://api.qrserver.com"],
      },
    },
  })
);
app.use(hpp());
app.use(express.json({ limit: "2mb" }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);
app.use("/api/auth", authLimiter);



registerAuthProfileRoutes(app);
registerOpportunityRoutes(app);
registerMessagingRoutes(app);
registerAdminRoutes(app);

async function bootstrap() {
  const publicDir = path.join(process.cwd(), "public");
  
  // Serve static files from the React app
  app.use(express.static(publicDir));

  // The "catchall" handler: for any request that doesn't
  // match one above, send back React's index.html file.
  app.get(/.*/, (req, res) => {
    res.sendFile(path.join(publicDir, "index.html"));
  });

  ensureDirectories();
  await ensureDefaultAdminAccount();
  await migrateUsersAndCollectionsIfNeeded();
  
  if (process.env.NODE_ENV !== "production") {
    app.listen(PORT, () => {
      console.log(`Backend running on port ${PORT}`);
    });
  }
}

bootstrap().catch(console.error);

module.exports = app;
