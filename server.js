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

    // Prefer cookie-based token (HTTPOnly cookie set by auth system)
    const cookies = req.cookies || {};
    let token = null;

    // Try common cookie names first
    const candidateNames = [
      "skillswap_session",
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

    // If no cookie token, try Authorization header
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

    // As a fallback, check if any cookie value matches a session token
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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", CLIENT_URL);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.get("/", (req, res) => {
  res.send("Skill-Swap API Server is running successfully");
});

app.get("/api/health", (req, res) => {
  res.status(200).json({ success: true, message: "Skill-Swap server is healthy" });
});

app.get("/api/roles", (req, res) => {
  res.status(200).json({
    success: true,
    roles: ["Client", "Freelancer", "Admin"],
  });
});

app.get("/api/auth/me", verifyToken, (req, res) => {
  res.status(200).json({ success: true, user: req.user });
});

app.get("/api/protected/client", verifyToken, verifyClient, (req, res) => {
  res.status(200).json({ success: true, message: "Client access granted", user: req.user });
});

app.get("/api/protected/freelancer", verifyToken, verifyFreelancer, (req, res) => {
  res.status(200).json({ success: true, message: "Freelancer access granted", user: req.user });
});

app.get("/api/protected/admin", verifyToken, verifyAdmin, (req, res) => {
  res.status(200).json({ success: true, message: "Admin access granted", user: req.user });
});

app.get("/api/tasks", async (req, res) => {
  try {
    await initDatabase();
    const filter = {};

    if (req.query.status) {
      filter.status = req.query.status;
    }

    const tasks = await tasksCollection.find(filter).sort({ createdAt: -1 }).toArray();
    res.status(200).json({ success: true, data: tasks });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to load tasks" });
  }
});

app.post("/api/tasks", verifyToken, verifyClient, async (req, res) => {
  try {
    await initDatabase();
    const payload = req.body || {};

    const task = {
      title: payload.title,
      description: payload.description,
      budget: payload.budget,
      status: payload.status || "open",
      clientId: req.user.id,
      clientEmail: req.user.email,
      createdAt: new Date(),
    };

    const result = await tasksCollection.insertOne(task);
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to create task" });
  }
});

app.get("/api/tasks/my", verifyToken, verifyClient, async (req, res) => {
  try {
    await initDatabase();
    const tasks = await tasksCollection
      .find({ clientId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({ success: true, data: tasks });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to load your tasks" });
  }
});

app.post("/api/proposals", verifyToken, verifyFreelancer, async (req, res) => {
  try {
    await initDatabase();
    const payload = req.body || {};
    const taskId = toObjectId(payload.taskId);

    if (!taskId) {
      return res.status(400).json({ success: false, message: "Invalid taskId" });
    }

    const task = await tasksCollection.findOne({ _id: taskId });

    if (!task) {
      return res.status(404).json({ success: false, message: "Task not found" });
    }

    const proposal = {
      taskId: task._id.toString(),
      coverLetter: payload.coverLetter,
      expectedAmount: payload.expectedAmount,
      status: "pending",
      freelancerId: req.user.id,
      freelancerEmail: req.user.email,
      createdAt: new Date(),
    };

    const result = await proposalsCollection.insertOne(proposal);
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to submit proposal" });
  }
});

app.get("/api/proposals/my", verifyToken, verifyFreelancer, async (req, res) => {
  try {
    await initDatabase();
    const proposals = await proposalsCollection
      .find({ freelancerId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({ success: true, data: proposals });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to load your proposals" });
  }
});

app.get("/api/proposals/task/:taskId", verifyToken, verifyClient, async (req, res) => {
  try {
    await initDatabase();
    const taskId = toObjectId(req.params.taskId);

    if (!taskId) {
      return res.status(400).json({ success: false, message: "Invalid taskId" });
    }

    const task = await tasksCollection.findOne({ _id: taskId });

    if (!task || task.clientId !== req.user.id) {
      return res.status(403).json({ success: false, message: "Forbidden" });
    }

    const proposals = await proposalsCollection
      .find({ taskId: req.params.taskId })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({ success: true, data: proposals });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to load task proposals" });
  }
});

app.post("/api/transactions", verifyToken, verifyClient, async (req, res) => {
  try {
    await initDatabase();
    const payload = req.body || {};
    const taskId = toObjectId(payload.taskId);

    if (!taskId) {
      return res.status(400).json({ success: false, message: "Invalid taskId" });
    }

    const task = await tasksCollection.findOne({ _id: taskId });

    if (!task || task.clientId !== req.user.id) {
      return res.status(403).json({ success: false, message: "Forbidden" });
    }

    const transaction = {
      taskId: task._id.toString(),
      proposalId: payload.proposalId,
      amount: payload.amount,
      clientId: req.user.id,
      freelancerId: payload.freelancerId,
      status: payload.status || "pending",
      createdAt: new Date(),
    };

    const result = await transactionsCollection.insertOne(transaction);
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to create transaction" });
  }
});

app.get("/api/transactions/my", verifyToken, async (req, res) => {
  try {
    await initDatabase();
    const filter = {};

    if (req.user.role === ROLES.CLIENT) {
      filter.clientId = req.user.id;
    } else if (req.user.role === ROLES.FREELANCER) {
      filter.freelancerId = req.user.id;
    }

    const transactions = await transactionsCollection.find(filter).sort({ createdAt: -1 }).toArray();
    res.status(200).json({ success: true, data: transactions });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to load transactions" });
  }
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    initDatabase()
      .then(() => console.log("Auth DB ready"))
      .catch((error) => console.error("Auth DB init failed:", error.message));
  });
}

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

const getTrustedUserFromHeaders = (req) => {
  const userId = req?.headers?.["x-user-id"] || req?.headers?.["X-User-Id"] || "";
  const email = req?.headers?.["x-user-email"] || req?.headers?.["X-User-Email"] || "";
  const role = req?.headers?.["x-user-role"] || req?.headers?.["X-User-Role"] || "";

  if (!userId && !email && !role) {
    return null;
  }

  return {
    id: String(userId || email || "guest"),
    email: String(email || ""),
    name: String(email || "Authenticated user"),
    role: normalizeRole(role),
  };
};

const extractAuthToken = (req) => {
  const signedCookies = req?.signedCookies || {};
  const cookies = req?.cookies || {};
  const header = req?.headers?.cookie || "";
  const authHeader = req?.headers?.authorization || "";
  const [scheme, hdrToken] = authHeader.split(" ");

  if (scheme === "Bearer" && hdrToken) {
    return hdrToken.trim();
  }

  const parsedCookies = Object.fromEntries(
    header
      .split(";")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => {
        const separatorIndex = entry.indexOf("=");
        if (separatorIndex === -1) {
          return [entry, ""];
        }

        const key = entry.slice(0, separatorIndex).trim();
        const value = decodeURIComponent(entry.slice(separatorIndex + 1).trim());
        return [key, value];
      })
  );

  const candidateNames = [
    "better-auth.session_token",
    "better-auth.session-token",
    "better_auth_session",
    "better-auth-session",
    "skillswap_session",
    "session_token",
    "session",
    "token",
  ];

  for (const name of candidateNames) {
    const value = signedCookies[name] || cookies[name] || parsedCookies[name];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }

  return null;
};

const verifyToken = async (req, res, next) => {
  try {
    const trustedUser = getTrustedUserFromHeaders(req);
    if (trustedUser) {
      req.user = trustedUser;
      return next();
    }

    await initDatabase();

    if (!usersCollection || !sessionCollection) {
      return res.status(503).json({ success: false, message: "Authentication service unavailable" });
    }

    let token = extractAuthToken(req);

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
      const cookies = req.cookies || {};
      for (const v of Object.values(cookies)) {
        if (typeof v !== "string") continue;
        const trimmed = v.trim();
        if (!trimmed) continue;
        const s = await sessionCollection.findOne({ token: trimmed });
        if (s) {
          session = s;
          token = trimmed;
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

app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  const isAllowedOrigin = origin && ALLOWED_ORIGINS.includes(origin);
  const responseOrigin = isAllowedOrigin ? origin : CLIENT_URL;

  res.header("Access-Control-Allow-Origin", responseOrigin);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Vary", "Origin");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User-Id, X-User-Email, X-User-Role");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const escapeRegex = (value) => String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const normalizeTaskDocument = (task) => {
  if (!task || typeof task !== "object") {
    return null;
  }

  const idValue = task._id ?? task.id ?? task.taskId ?? null;
  const clientEmail = task.clientEmail || task.client_email || task.client?.email || task.clientEmail || null;
  const clientName = task.clientName || task.client_name || task.client?.name || task.clientName || null;
  const category = task.category || task.type || "General";
  const budget = Number(task.budget ?? task.amount ?? 0);
  const status = String(task.status || "open").trim().toLowerCase();

  return {
    ...task,
    _id: idValue ? String(idValue) : "",
    id: idValue ? String(idValue) : "",
    title: task.title || task.name || "Untitled task",
    description: task.description || task.summary || "",
    category,
    budget,
    status,
    deadline: task.deadline || task.dueDate || null,
    clientEmail,
    clientName,
    client: {
      name: clientName || clientEmail || "Unknown client",
      email: clientEmail || null,
    },
  };
};

const toObjectId = (value) => {
  if (!value || typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  if (!trimmed || !ObjectId.isValid(trimmed)) {
    return null;
  }

  return new ObjectId(trimmed);
};

const buildTaskLookupQuery = (taskId) => {
  const normalizedTaskId = String(taskId || "").trim();
  const orFilters = [];
  const objectId = toObjectId(normalizedTaskId);

  if (objectId) {
    orFilters.push({ _id: objectId });
  }

  if (normalizedTaskId) {
    orFilters.push({ _id: normalizedTaskId });
    orFilters.push({ taskId: normalizedTaskId });
    orFilters.push({ id: normalizedTaskId });
  }

  return orFilters.length ? { $or: orFilters } : { _id: null };
};

app.get("/api/tasks/:taskId", async (req, res) => {
  try {
    await initDatabase();

    if (!tasksCollection) {
      return res.status(503).json({ success: false, message: "Task service unavailable" });
    }

    const taskId = req.params.taskId;
    const taskQuery = buildTaskLookupQuery(taskId);
    const task = await tasksCollection.findOne(taskQuery);

    if (!task) {
      return res.status(404).json({ success: false, message: "Task not found" });
    }

    return res.status(200).json({ success: true, data: normalizeTaskDocument(task) });
  } catch (error) {
    console.error("Failed to load task details:", error.stack || error);
    res.status(500).json({ success: false, message: "Failed to load task details", error: error.message });
  }
});

app.get("/api/tasks", async (req, res) => {
  try {
    await initDatabase();

    if (!tasksCollection) {
      return res.status(503).json({ success: false, message: "Task service unavailable" });
    }

    const page = Math.max(1, Number.parseInt(req.query.page || "1", 10) || 1);
    const limit = Math.min(9, Math.max(1, Number.parseInt(req.query.limit || "9", 10) || 9));
    const search = typeof req.query.search === "string" ? req.query.search.trim().toLowerCase() : "";
    const category = typeof req.query.category === "string" ? req.query.category.trim() : "";
    const requestedStatus = typeof req.query.status === "string" ? req.query.status.trim().toLowerCase() : "";
    const effectiveStatus = requestedStatus && requestedStatus !== "all" ? requestedStatus : "open";

    const query = {};
    const filters = [];

    if (effectiveStatus) {
      filters.push({ status: { $regex: `^${escapeRegex(effectiveStatus)}$`, $options: "i" } });
    }

    if (search) {
      filters.push({ title: { $regex: escapeRegex(search), $options: "i" } });
    }

    if (category) {
      filters.push({ category: { $regex: `^${escapeRegex(category)}$`, $options: "i" } });
    }

    if (filters.length === 1) {
      Object.assign(query, filters[0]);
    } else if (filters.length > 1) {
      query.$and = filters;
    }

    const totalTasks = await tasksCollection.countDocuments(query);
    const totalPages = Math.max(1, Math.ceil(totalTasks / limit));
    const currentPage = Math.min(page, totalPages);
    const skip = (currentPage - 1) * limit;
    const docs = await tasksCollection
      .find(query)
      .sort({ createdAt: -1, _id: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    const data = docs.map(normalizeTaskDocument).filter(Boolean);
    const categoryPipeline = [
      { $match: { status: { $regex: "^open$", $options: "i" } } },
      { $group: { _id: "$category" } },
      { $project: { _id: 0, category: "$_id" } },
    ];
    const categoryDocs = await tasksCollection.aggregate(categoryPipeline).toArray();
    const categories = categoryDocs.map((item) => item.category).filter(Boolean).sort();

    res.status(200).json({
      success: true,
      data,
      pagination: {
        page: currentPage,
        limit,
        totalTasks,
        totalPages,
      },
      categories,
    });
  } catch (error) {
    console.error("Failed to load tasks:", error.stack || error);
    res.status(500).json({ success: false, message: "Failed to load tasks", error: error.message });
  }
});

module.exports = app;