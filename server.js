const express = require("express");
const dotenv = require("dotenv");
const { MongoClient, ObjectId, ServerApiVersion } = require("mongodb");
const cookieParser = require("cookie-parser");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const MONGO_DB_URI = process.env.MONGO_DB_URI;
const AUTH_DB_NAME = process.env.AUTH_DB_NAME;
const APP_DB_NAME = process.env.APP_DB_NAME || AUTH_DB_NAME;

const ROLES = {
  CLIENT: "Client",
  FREELANCER: "Freelancer",
  ADMIN: "Admin",
};

let mongoClient;
let usersCollection;
let sessionCollection;
let tasksCollection;
let proposalsCollection;
let transactionsCollection;

const normalizeRole = (role) => {
  const value = String(role || "").trim().toLowerCase();

  if (value === "admin") {
    return ROLES.ADMIN;
  }

  if (value === "freelancer") {
    return ROLES.FREELANCER;
  }

  return ROLES.CLIENT;
};

const initDatabase = async () => {
  if (
    usersCollection &&
    sessionCollection &&
    tasksCollection &&
    proposalsCollection &&
    transactionsCollection
  ) {
    return;
  }

  if (!MONGO_DB_URI || !AUTH_DB_NAME || !APP_DB_NAME) {
    throw new Error("Missing database environment variables for auth verification");
  }

  mongoClient = new MongoClient(MONGO_DB_URI, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  });

  await mongoClient.connect();
  const authDb = mongoClient.db(AUTH_DB_NAME);
  const appDb = mongoClient.db(APP_DB_NAME);

  usersCollection = authDb.collection("user");
  sessionCollection = authDb.collection("session");
  tasksCollection = appDb.collection("tasks");
  proposalsCollection = appDb.collection("proposals");
  transactionsCollection = appDb.collection("transactions");
};

const toObjectId = (value) => {
  if (!ObjectId.isValid(value)) {
    return null;
  }

  return new ObjectId(value);
};

const verifyToken = async (req, res, next) => {
  try {
    await initDatabase();

    const cookies = req.cookies || {};
    let token = null;

    const candidateNames = [
      "taskhive_session",
      "better_auth_session",
      "better-auth-session",
      "session",
      "token",
    ];

    for (const name of candidateNames) {
      if (cookies[name]) {
        token = cookies[name];
        break;
      }
    }

    if (!token) {
      const authHeader = req.headers.authorization || "";
      const [scheme, hdrToken] = authHeader.split(" ");
      if (scheme === "Bearer" && hdrToken) {
        token = hdrToken;
      }
    }

    let session = null;
    if (token) {
      session = await sessionCollection.findOne({ token });
    }

    if (!session) {
      for (const v of Object.values(cookies)) {
        if (typeof v !== "string") continue;
        const s = await sessionCollection.findOne({ token: v });
        if (s) {
          session = s;
          token = v;
          break;
        }
      }
    }

    if (!session?.userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const userId = String(session.userId);
    const userFilter = ObjectId.isValid(userId)
      ? { $or: [{ _id: new ObjectId(userId) }, { _id: userId }] }
      : { _id: userId };

    const user = await usersCollection.findOne(userFilter);

    if (!user) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    req.user = {
      id: String(user._id),
      email: user.email,
      name: user.name,
      role: normalizeRole(user.role),
    };

    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    res.status(500).json({ success: false, message: "Authentication failed" });
  }
};

const verifyRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: "Forbidden" });
    }

    next();
  };
};

const verifyClient = verifyRole([ROLES.CLIENT]);
const verifyFreelancer = verifyRole([ROLES.FREELANCER]);
const verifyAdmin = verifyRole([ROLES.ADMIN]);