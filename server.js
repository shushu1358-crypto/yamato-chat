const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { WebSocketServer } = require("ws");
const { createClient } = require("@supabase/supabase-js");
const multer = require("multer");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const YAMATO_GATE_PASSWORD = process.env.YAMATO_GATE_PASSWORD;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY || !YAMATO_GATE_PASSWORD) {
  console.error("Missing SUPABASE_URL, SUPABASE_SECRET_KEY, or YAMATO_GATE_PASSWORD.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY);

const channels = {
  general: { name: "general", id: null },
  chat: { name: "雑談", id: null },
  game: { name: "ゲーム", id: null }
};

const clients = new Map();
const MAX_MESSAGES = 200;
const SESSION_DAYS = 30;
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
const MAX_AVATAR_BYTES = 5 * 1024 * 1024;
const STORAGE_BUCKET = "yamato-chat-files";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES }
});
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_AVATAR_BYTES }
});

app.use(express.json({ limit: "32kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "Yamato Chat",
    database: "supabase",
    auth: "accounts",
    online: clients.size
  });
});

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function newSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    out[key] = decodeURIComponent(value);
  }
  return out;
}

function setSessionCookie(res, token) {
  const forwarded = String(res.req?.headers?.["x-forwarded-proto"] || "");
  const secure = forwarded === "https" || process.env.NODE_ENV === "production";
  const parts = [
    `yamato_session=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "yamato_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
  );
}

async function getAccountBySessionToken(token) {
  if (!token) return null;

  const tokenHash = hashToken(token);
  const { data, error } = await supabase
    .from("sessions")
    .select(`
      id,
      account_id,
      expires_at,
      accounts (
        id,
        username,
        display_name,
        bio,
        avatar_url,
        created_at,
        last_login_at
      )
    `)
    .eq("token_hash", tokenHash)
    .gt("expires_at", new Date().toISOString())
    .limit(1)
    .maybeSingle();

  if (error) {
    console.error("Session lookup error:", error);
    return null;
  }

  return data?.accounts || null;
}

async function createSession(accountId) {
  // Keep multiple active sessions. Each browser tab has its own token.
  const raw = newSessionToken();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();

  const { error } = await supabase.from("sessions").insert({
    account_id: accountId,
    token_hash: hashToken(raw),
    expires_at: expires
  });

  if (error) throw error;
  return raw;
}

function getRequestSessionToken(req) {
  const auth = String(req.headers.authorization || "");
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return parseCookies(req).yamato_session || "";
}

async function requireAccount(req, res, next) {
  const token = getRequestSessionToken(req);
  const account = await getAccountBySessionToken(token);
  if (!account) {
    return res.status(401).json({ ok: false, error: "ログインが必要です" });
  }
  req.account = account;
  req.sessionToken = token;
  next();
}

function validUsername(username) {
  return /^[A-Za-z0-9_]{3,24}$/.test(username);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 4 && password.length <= 128;
}

function cleanDisplayName(value) {
  return String(value || "").trim().slice(0, 24);
}

function cleanBio(value) {
  return String(value || "").trim().slice(0, 500);
}

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const displayName = cleanDisplayName(req.body.displayName);
    const password = String(req.body.password || "");
    const gatePassword = String(req.body.gatePassword || "");
    const bio = cleanBio(req.body.bio);

    if (!validUsername(username)) {
      return res.status(400).json({
        ok: false,
        error: "ユーザー名は半角英数字と _ の3〜24文字にしてください"
      });
    }
    if (!displayName) {
      return res.status(400).json({ ok: false, error: "表示名を入力してください" });
    }
    if (!validPassword(password)) {
      return res.status(400).json({ ok: false, error: "パスワードは4〜128文字です" });
    }
    if (!verifyGatePassword(gatePassword)) {
      return res.status(401).json({ ok: false, error: "共通ゲートパスワードが違います" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data: account, error } = await supabase
      .from("accounts")
      .insert({
        username,
        display_name: displayName,
        password_hash: passwordHash,
        bio
      })
      .select("id, username, display_name, bio, avatar_url, created_at")
      .single();

    if (error) {
      if (error.code === "23505") {
        return res.status(409).json({ ok: false, error: "そのユーザー名はすでに使われています" });
      }
      throw error;
    }

    const token = await createSession(account.id);
    setSessionCookie(res, token);

    res.json({ ok: true, account, sessionToken: token });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ ok: false, error: "登録に失敗しました" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const gatePassword = String(req.body.gatePassword || "");

    if (!username || !password || !gatePassword) {
      return res.status(400).json({ ok: false, error: "すべて入力してください" });
    }

    const { data: account, error } = await supabase
      .from("accounts")
      .select(`
        id, username, display_name, bio, avatar_url, created_at, last_login_at,
        password_hash
      `)
      .eq("username", username)
      .limit(1)
      .maybeSingle();

    if (error) throw error;

    // Deliberately use one generic error so account existence is not revealed.
    if (!account) {
      return res.status(401).json({ ok: false, error: "ユーザー名またはパスワードが違います" });
    }

    const passwordOK = await bcrypt.compare(password, account.password_hash);
    const gateOK = verifyGatePassword(gatePassword);

    if (!passwordOK || !gateOK) {
      return res.status(401).json({ ok: false, error: "ユーザー名またはパスワードが違います" });
    }

    await supabase
      .from("accounts")
      .update({ last_login_at: new Date().toISOString() })
      .eq("id", account.id);

    const token = await createSession(account.id);
    setSessionCookie(res, token);

    delete account.password_hash;

    res.json({ ok: true, account, sessionToken: token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ ok: false, error: "ログインに失敗しました" });
  }
});

app.get("/api/me", requireAccount, async (req, res) => {
  res.json({ ok: true, account: req.account });
});

app.post("/api/logout", async (req, res) => {
  try {
    const token = getRequestSessionToken(req);
    if (token) {
      await supabase.from("sessions").delete().eq("token_hash", hashToken(token));
    }
  } catch (error) {
    console.error("Logout error:", error);
  }
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.patch("/api/profile", requireAccount, async (req, res) => {
  try {
    const displayName = cleanDisplayName(req.body.displayName);
    const bio = cleanBio(req.body.bio);

    if (!displayName) {
      return res.status(400).json({ ok: false, error: "表示名を入力してください" });
    }

    const { data, error } = await supabase
      .from("accounts")
      .update({ display_name: displayName, bio })
      .eq("id", req.account.id)
      .select("id, username, display_name, bio, avatar_url, created_at, last_login_at")
      .single();

    if (error) throw error;

    // Keep the chat identity in sync immediately after profile edits.
    await supabase
      .from("chat_users")
      .update({
        username: data.username,
        avatar_url: data.avatar_url || null
      })
      .eq("username", data.username);

    for (const [client, info] of clients) {
      if (info.username === data.username && client.readyState === 1) {
        info.name = data.display_name;
        info.avatarUrl = data.avatar_url || null;
        client.send(JSON.stringify({
          type: "profile_updated",
          account: {
            username: data.username,
            displayName: data.display_name,
            bio: data.bio,
            avatarUrl: data.avatar_url || null
          }
        }));
      }
    }

    res.json({ ok: true, account: data });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ ok: false, error: "プロフィールの更新に失敗しました" });
  }
});

function repairFileName(name) {
  let value = String(name || "file");

  // Repair common UTF-8 -> Latin-1/Windows-1252 mojibake.
  // Only apply when the text has characteristic mojibake markers and the
  // round-trip produces valid UTF-8 without replacement characters.
  if (/[ÃÂã€šåäæçèéêëìíîïðñòóôõöøùúûüýþ]/.test(value)) {
    try {
      const repaired = Buffer.from(value, "latin1").toString("utf8");
      if (repaired && !/\uFFFD/.test(repaired)) value = repaired;
    } catch {}
  }

  return value;
}

function safeFileName(name) {
  const cleaned = repairFileName(name)
    .replace(/[\\\\/<>:"|?*\x00-\x1F]/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
  return cleaned || "file";
}

function makeStoragePath(accountId, originalName, prefix) {
  const ext = path.extname(originalName).slice(0, 16);
  const base = path.basename(originalName, ext)
    .replace(/[^A-Za-z0-9_-]/g, "_")
    .slice(0, 60) || "file";
  return `${prefix}/${accountId}/${Date.now()}-${crypto.randomBytes(6).toString("hex")}-${base}${ext}`;
}

function publicStorageUrl(storagePath) {
  const encoded = storagePath.split("/").map(encodeURIComponent).join("/");
  return `${SUPABASE_URL}/storage/v1/object/public/${STORAGE_BUCKET}/${encoded}`;
}

async function ensureStorageBucket() {
  const { data, error } = await supabase.storage.listBuckets();
  if (error) throw error;

  if (!(data || []).some(bucket => bucket.name === STORAGE_BUCKET)) {
    const { error: createError } = await supabase.storage.createBucket(STORAGE_BUCKET, {
      public: true,
      fileSizeLimit: `${MAX_UPLOAD_BYTES}B`
    });

    if (createError && !String(createError.message || "").toLowerCase().includes("already")) {
      throw createError;
    }
  }
}

app.post("/api/profile/avatar", requireAccount, avatarUpload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "画像を選択してください" });
    }
    if (!String(req.file.mimetype || "").startsWith("image/")) {
      return res.status(400).json({ ok: false, error: "アイコンには画像ファイルを選択してください" });
    }

    const storagePath = makeStoragePath(req.account.id, safeFileName(req.file.originalname), "avatars");
    const { error: uploadError } = await supabase.storage
      .from(STORAGE_BUCKET)
      .upload(storagePath, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });

    if (uploadError) throw uploadError;

    const avatarUrl = publicStorageUrl(storagePath);

    const { data, error } = await supabase
      .from("accounts")
      .update({ avatar_url: avatarUrl })
      .eq("id", req.account.id)
      .select("id, username, display_name, bio, avatar_url, created_at, last_login_at")
      .single();

    if (error) throw error;

    await supabase
      .from("chat_users")
      .update({ avatar_url: avatarUrl })
      .eq("username", req.account.username);

    res.json({ ok: true, account: data });
  } catch (error) {
    console.error("Avatar upload error:", error);
    res.status(500).json({ ok: false, error: "アイコンのアップロードに失敗しました" });
  }
});

app.post("/api/upload", requireAccount, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "ファイルを選択してください" });
    }

    const storagePath = makeStoragePath(
      req.account.id,
      safeFileName(req.file.originalname),
      "uploads"
    );

    const { error: uploadError } = await supabase.storage
      .from(STORAGE_BUCKET)
      .upload(storagePath, req.file.buffer, {
        contentType: req.file.mimetype || "application/octet-stream",
        upsert: false
      });

    if (uploadError) throw uploadError;

    res.json({
      ok: true,
      file: {
        url: publicStorageUrl(storagePath),
        name: safeFileName(req.file.originalname),
        type: req.file.mimetype || "application/octet-stream",
        size: req.file.size
      }
    });
  } catch (error) {
    console.error("File upload error:", error);
    if (error?.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ ok: false, error: "ファイルは20MB以下にしてください" });
    }
    res.status(500).json({ ok: false, error: "ファイルのアップロードに失敗しました" });
  }
});

function broadcast(data) {
  const text = JSON.stringify(data);
  for (const ws of clients.keys()) {
    if (ws.readyState === 1) ws.send(text);
  }
}

function sendUserList() {
  broadcast({
    type: "users",
    users: [...clients.values()].map(u => ({
      id: u.id,
      username: u.username,
      name: u.name,
      avatarUrl: u.avatarUrl || null,
      channel: u.channel
    }))
  });
}

async function ensureDefaultData() {
  const { data: existingServer, error: serverSelectError } = await supabase
    .from("servers")
    .select("id")
    .eq("name", "Yamato Chat")
    .limit(1)
    .maybeSingle();

  if (serverSelectError) throw serverSelectError;

  let serverId = existingServer?.id;

  if (!serverId) {
    const { data: createdServer, error } = await supabase
      .from("servers")
      .insert({ name: "Yamato Chat" })
      .select("id")
      .single();

    if (error) throw error;
    serverId = createdServer.id;
  }

  for (const key of Object.keys(channels)) {
    const channelName = channels[key].name;

    const { data: existingChannel, error: channelSelectError } = await supabase
      .from("channels")
      .select("id")
      .eq("server_id", serverId)
      .eq("name", channelName)
      .limit(1)
      .maybeSingle();

    if (channelSelectError) throw channelSelectError;

    let channelId = existingChannel?.id;

    if (!channelId) {
      const { data: createdChannel, error } = await supabase
        .from("channels")
        .insert({ server_id: serverId, name: channelName })
        .select("id")
        .single();

      if (error) throw error;
      channelId = createdChannel.id;
    }

    channels[key].id = channelId;
  }

  console.log("Supabase initialized:", Object.fromEntries(
    Object.entries(channels).map(([key, value]) => [key, value.id])
  ));
}

async function getHistory(channelKey, reactionUserId = null) {
  const channelId = channels[channelKey]?.id;
  if (!channelId) return [];

  const baseSelect = `
    id, content, created_at, edited_at, user_id,
    attachment_url, attachment_name, attachment_type, attachment_size
  `;

  let { data: rows, error } = await supabase
    .from("messages")
    .select(`${baseSelect}, attachments`)
    .eq("channel_id", channelId)
    .order("created_at", { ascending: false })
    .limit(MAX_MESSAGES);

  if (error && /attachments|column/i.test(String(error.message || ""))) {
    ({ data: rows, error } = await supabase
      .from("messages")
      .select(baseSelect)
      .eq("channel_id", channelId)
      .order("created_at", { ascending: false })
      .limit(MAX_MESSAGES));
  }

  if (error) {
    console.error("History load error:", error);
    return [];
  }

  rows = (rows || []).reverse();

  const userIds = [...new Set(rows.map(r => r.user_id).filter(Boolean))];
  let userRows = [];
  if (userIds.length) {
    const result = await supabase
      .from("chat_users")
      .select("id,username,display_name,avatar_url")
      .in("id", userIds);
    if (!result.error) userRows = result.data || [];
    else console.error("Chat user history load error:", result.error);
  }
  const usersById = Object.fromEntries(userRows.map(u => [u.id, u]));

  return rows.map(row => {
    const u = usersById[row.user_id] || {};
    return {
      id: row.id,
      userId: row.user_id,
      user: u.display_name || u.username || "Unknown",
      username: u.username || "",
      avatarUrl: u.avatar_url || null,
      text: row.content,
      time: row.created_at,
      editedAt: row.edited_at || null,
      attachments: Array.isArray(row.attachments) ? row.attachments : (
        row.attachment_url ? [{
          url: row.attachment_url,
          name: row.attachment_name || "file",
          type: row.attachment_type || "application/octet-stream",
          size: row.attachment_size || 0
        }] : []
      ),
      attachment: row.attachment_url ? {
        url: row.attachment_url,
        name: row.attachment_name || "file",
        type: row.attachment_type || "application/octet-stream",
        size: row.attachment_size || 0
      } : null,
      reactions: []
    };
  });
}

async function ensureChatUser(account) {
  // Keep the existing messages schema working while accounts become
  // the canonical identity for login/profile.
  const { data, error } = await supabase
    .from("chat_users")
    .upsert(
      { username: account.username, display_name: account.display_name || account.username, avatar_url: account.avatar_url || null },
      { onConflict: "username" }
    )
    .select("id, username, display_name, avatar_url")
    .single();

  if (error) throw error;
  return data;
}


function verifyGatePassword(input) {
  return typeof input === "string" &&
    typeof YAMATO_GATE_PASSWORD === "string" &&
    input === YAMATO_GATE_PASSWORD;
}


function canonicalPair(a, b) {
  return String(a) < String(b) ? [a, b] : [b, a];
}

async function getFriendshipForAccounts(a, b) {
  const [userA, userB] = canonicalPair(a, b);
  const { data, error } = await supabase
    .from("friendships")
    .select("*")
    .eq("user_a_id", userA)
    .eq("user_b_id", userB)
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function isAcceptedFriend(a, b) {
  const row = await getFriendshipForAccounts(a, b);
  return !!row && row.status === "accepted";
}

async function getOrCreateDmConversation(a, b) {
  const [userA, userB] = canonicalPair(a, b);
  let { data, error } = await supabase
    .from("dm_conversations")
    .select("id,user_a_id,user_b_id,created_at")
    .eq("user_a_id", userA)
    .eq("user_b_id", userB)
    .maybeSingle();
  if (error) throw error;
  if (data) return data;

  const result = await supabase
    .from("dm_conversations")
    .insert({ user_a_id: userA, user_b_id: userB })
    .select("id,user_a_id,user_b_id,created_at")
    .single();

  if (result.error) {
    // Another request may have created it concurrently.
    if (result.error.code === "23505") {
      const retry = await supabase
        .from("dm_conversations")
        .select("id,user_a_id,user_b_id,created_at")
        .eq("user_a_id", userA)
        .eq("user_b_id", userB)
        .single();
      if (retry.error) throw retry.error;
      return retry.data;
    }
    throw result.error;
  }
  return result.data;
}

async function getDmParticipants(conversationId) {
  const { data, error } = await supabase
    .from("dm_conversations")
    .select("id,user_a_id,user_b_id")
    .eq("id", conversationId)
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function getReactionsForTargets(targetType, ids) {
  if (!ids.length) return {};
  let query = supabase.from("reactions")
    .select("id,message_id,dm_message_id,user_id,emoji,chat_users(username,display_name)")
    .in(targetType === "channel" ? "message_id" : "dm_message_id", ids);
  const { data, error } = await query;
  if (error) {
    console.error("Reaction load error:", error);
    return {};
  }

  const out = {};
  for (const row of data || []) {
    const targetId = targetType === "channel" ? row.message_id : row.dm_message_id;
    if (!out[targetId]) out[targetId] = [];
    const existing = out[targetId].find(x => x.emoji === row.emoji);
    if (existing) {
      existing.count += 1;
      if (row.user_id === currentReactionUserId) existing.mine = true;
    } else {
      out[targetId].push({
        emoji: row.emoji,
        count: 1,
        mine: row.user_id === currentReactionUserId
      });
    }
  }
  return out;
}

async function getReactionSummary(targetType, targetId, userId) {
  const column = targetType === "channel" ? "message_id" : "dm_message_id";
  const { data, error } = await supabase
    .from("reactions")
    .select("user_id,emoji")
    .eq(column, targetId);
  if (error) throw error;

  const grouped = [];
  for (const row of data || []) {
    let item = grouped.find(x => x.emoji === row.emoji);
    if (!item) {
      item = { emoji: row.emoji, count: 0, mine: false };
      grouped.push(item);
    }
    item.count += 1;
    if (row.user_id === userId) item.mine = true;
  }
  return grouped;
}

async function getFriendData(accountId) {
  const { data: rows, error } = await supabase
    .from("friendships")
    .select("id,user_a_id,user_b_id,requester_id,status,created_at,updated_at")
    .or(`user_a_id.eq.${accountId},user_b_id.eq.${accountId}`)
    .order("created_at", { ascending: false });
  if (error) throw error;

  const otherIds = [...new Set((rows || []).map(r => r.user_a_id === accountId ? r.user_b_id : r.user_a_id))];
  let accounts = [];
  if (otherIds.length) {
    const result = await supabase
      .from("accounts")
      .select("id,username,display_name,bio,avatar_url")
      .in("id", otherIds);
    if (result.error) throw result.error;
    accounts = result.data || [];
  }
  const byId = Object.fromEntries(accounts.map(a => [a.id, a]));

  const friends = [], incoming = [], outgoing = [];
  for (const row of rows || []) {
    const otherId = row.user_a_id === accountId ? row.user_b_id : row.user_a_id;
    const other = byId[otherId];
    if (!other) continue;
    const item = { ...row, other };
    if (row.status === "accepted") friends.push(item);
    else if (row.status === "pending" && row.requester_id !== accountId) incoming.push(item);
    else if (row.status === "pending" && row.requester_id === accountId) outgoing.push(item);
  }
  return { friends, incoming, outgoing };
}

async function sendSocialUpdate(accountId) {
  const data = await getFriendData(accountId);
  for (const [client, info] of clients) {
    if (info.accountId === accountId && client.readyState === 1) {
      client.send(JSON.stringify({ type: "friends_updated", data }));
    }
  }
}

async function sendToAccount(accountId, payload) {
  const text = JSON.stringify(payload);
  for (const [client, info] of clients) {
    if (info.accountId === accountId && client.readyState === 1) client.send(text);
  }
}

async function getDmHistory(conversationId, accountId) {
  const participant = await getDmParticipants(conversationId);
  if (!participant || ![participant.user_a_id, participant.user_b_id].includes(accountId)) return [];

  const { data, error } = await supabase
    .from("dm_messages")
    .select("id,conversation_id,sender_id,content,created_at,edited_at,accounts(username,display_name,avatar_url)")
    .eq("conversation_id", conversationId)
    .order("created_at", { ascending: true })
    .limit(MAX_MESSAGES);
  if (error) throw error;

  const ids = (data || []).map(x => x.id);
  const { data: reactions, error: reactionError } = ids.length
    ? await supabase.from("reactions").select("dm_message_id,user_id,emoji").in("dm_message_id", ids)
    : { data: [], error: null };
  if (reactionError) throw reactionError;

  const reactionMap = {};
  for (const r of reactions || []) {
    if (!reactionMap[r.dm_message_id]) reactionMap[r.dm_message_id] = [];
    let item = reactionMap[r.dm_message_id].find(x => x.emoji === r.emoji);
    if (!item) {
      item = { emoji:r.emoji, count:0, mine:false };
      reactionMap[r.dm_message_id].push(item);
    }
    item.count++;
    if (r.user_id === (await getChatUserIdByAccount(accountId))) item.mine = true;
  }

  return (data || []).map(row => ({
    id: row.id,
    dmConversationId: row.conversation_id,
    userId: row.sender_id,
    username: row.accounts?.username || "",
    user: row.accounts?.display_name || row.accounts?.username || "Unknown",
    avatarUrl: row.accounts?.avatar_url || null,
    text: row.content,
    time: row.created_at,
    editedAt: row.edited_at || null,
    reactions: reactionMap[row.id] || []
  }));
}

async function getChatUserIdByAccount(accountId) {
  const { data, error } = await supabase
    .from("chat_users")
    .select("id")
    .eq("username", (
      await supabase.from("accounts").select("username").eq("id", accountId).single()
    ).data?.username || "")
    .maybeSingle();
  if (error) return null;
  return data?.id || null;
}


app.get("/api/friends", requireAccount, async (req, res) => {
  try {
    res.json({ ok: true, data: await getFriendData(req.account.id) });
  } catch (error) {
    console.error("Friends load error:", error);
    res.status(500).json({ ok:false, error:"フレンド情報の取得に失敗しました" });
  }
});

app.post("/api/friends/request", requireAccount, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    if (!validUsername(username)) return res.status(400).json({ok:false,error:"ユーザー名が正しくありません"});
    const { data: target, error: targetError } = await supabase
      .from("accounts").select("id,username,display_name,bio,avatar_url").eq("username", username).maybeSingle();
    if (targetError) throw targetError;
    if (!target) return res.status(404).json({ok:false,error:"そのユーザーは見つかりません"});
    if (target.id === req.account.id) return res.status(400).json({ok:false,error:"自分自身は追加できません"});

    const [a,b] = canonicalPair(req.account.id,target.id);
    const existing = await getFriendshipForAccounts(req.account.id,target.id);
    if (existing?.status === "accepted") return res.status(400).json({ok:false,error:"すでにフレンドです"});
    if (existing?.status === "pending") {
      if (existing.requester_id === req.account.id) return res.status(400).json({ok:false,error:"すでに申請済みです"});
      return res.status(400).json({ok:false,error:"相手からフレンド申請が届いています。承認してください"});
    }

    const { data: friendship, error } = await supabase.from("friendships").upsert({
      user_a_id:a,user_b_id:b,requester_id:req.account.id,status:"pending",updated_at:new Date().toISOString()
    },{onConflict:"user_a_id,user_b_id"}).select().single();
    if (error) throw error;

    await sendSocialUpdate(req.account.id);
    await sendSocialUpdate(target.id);
    await sendToAccount(target.id,{type:"friend_request",friendshipId:friendship.id,from:{
      id:req.account.id,username:req.account.username,displayName:req.account.display_name,avatarUrl:req.account.avatar_url
    }});
    res.json({ok:true});
  } catch(error) {
    console.error("Friend request error:",error);
    res.status(500).json({ok:false,error:"フレンド申請に失敗しました"});
  }
});

app.post("/api/friends/:id/accept", requireAccount, async (req,res)=>{
  try {
    const {data: row,error} = await supabase.from("friendships").select("*").eq("id",req.params.id).maybeSingle();
    if(error) throw error;
    if(!row || row.status!=="pending" || row.requester_id===req.account.id ||
       ![row.user_a_id,row.user_b_id].includes(req.account.id)) {
      return res.status(404).json({ok:false,error:"申請が見つかりません"});
    }
    const {data: updated,error:updateError}=await supabase.from("friendships")
      .update({status:"accepted",updated_at:new Date().toISOString()}).eq("id",row.id)
      .select().single();
    if(updateError) throw updateError;

    // Accepted friends automatically get a DM entry. The user does not
    // need a separate "new DM" action.
    await getOrCreateDmConversation(row.user_a_id, row.user_b_id);

    await sendSocialUpdate(row.user_a_id);
    await sendSocialUpdate(row.user_b_id);
    await sendToAccount(row.requester_id,{type:"friend_accepted",friendshipId:row.id});
    res.json({ok:true,friendship:updated});
  }catch(error){
    console.error("Friend accept error:",error);
    res.status(500).json({ok:false,error:"承認に失敗しました"});
  }
});

app.post("/api/friends/:id/reject", requireAccount, async (req,res)=>{
  try {
    const {data: row,error}=await supabase.from("friendships").select("*").eq("id",req.params.id).maybeSingle();
    if(error) throw error;
    if(!row || row.status!=="pending" || ![row.user_a_id,row.user_b_id].includes(req.account.id)) {
      return res.status(404).json({ok:false,error:"申請が見つかりません"});
    }
    await supabase.from("friendships").delete().eq("id",row.id);
    await sendSocialUpdate(row.user_a_id);
    await sendSocialUpdate(row.user_b_id);
    res.json({ok:true});
  }catch(error){
    console.error("Friend reject error:",error);
    res.status(500).json({ok:false,error:"申請の処理に失敗しました"});
  }
});

app.delete("/api/friends/:id", requireAccount, async (req,res)=>{
  try {
    const {data: row,error}=await supabase.from("friendships").select("*").eq("id",req.params.id).maybeSingle();
    if(error) throw error;
    if(!row || ![row.user_a_id,row.user_b_id].includes(req.account.id)) return res.status(404).json({ok:false,error:"フレンドが見つかりません"});
    await supabase.from("friendships").delete().eq("id",row.id);
    await sendSocialUpdate(row.user_a_id);
    await sendSocialUpdate(row.user_b_id);
    res.json({ok:true});
  }catch(error){
    console.error("Friend delete error:",error);
    res.status(500).json({ok:false,error:"フレンド解除に失敗しました"});
  }
});

app.get("/api/dms", requireAccount, async (req,res)=>{
  try {
    const id=req.account.id;
    const {data: rows,error}=await supabase.from("dm_conversations")
      .select("id,user_a_id,user_b_id,created_at")
      .or(`user_a_id.eq.${id},user_b_id.eq.${id}`)
      .order("created_at",{ascending:false});
    if(error) throw error;
    const otherIds=(rows||[]).map(r=>r.user_a_id===id?r.user_b_id:r.user_a_id);
    const accounts=otherIds.length ? (await supabase.from("accounts")
      .select("id,username,display_name,avatar_url").in("id",otherIds)).data||[] : [];
    const byId=Object.fromEntries(accounts.map(a=>[a.id,a]));
    const result=[];
    for(const row of rows||[]){
      const otherId=row.user_a_id===id?row.user_b_id:row.user_a_id;
      const {data:last}=await supabase.from("dm_messages").select("content,created_at")
        .eq("conversation_id",row.id).order("created_at",{ascending:false}).limit(1).maybeSingle();
      result.push({id:row.id,other:byId[otherId]||null,lastMessage:last||null});
    }
    res.json({ok:true,dms:result});
  }catch(error){
    console.error("DM list error:",error);
    res.status(500).json({ok:false,error:"DM一覧の取得に失敗しました"});
  }
});

app.post("/api/dms/open", requireAccount, async (req,res)=>{
  try {
    const username=String(req.body.username||"").trim();
    const {data: target,error}=await supabase.from("accounts")
      .select("id,username,display_name,bio,avatar_url").eq("username",username).maybeSingle();
    if(error) throw error;
    if(!target) return res.status(404).json({ok:false,error:"ユーザーが見つかりません"});
    if(target.id===req.account.id) return res.status(400).json({ok:false,error:"自分自身にはDMできません"});
    if(!await isAcceptedFriend(req.account.id,target.id)) {
      return res.status(403).json({ok:false,error:"DMするには先にフレンドになる必要があります"});
    }
    const conversation=await getOrCreateDmConversation(req.account.id,target.id);
    res.json({ok:true,conversation,other:target});
  }catch(error){
    console.error("DM open error:",error);
    res.status(500).json({ok:false,error:"DMを開けませんでした"});
  }
});

wss.on("connection", async (ws, req) => {
  let token = parseCookies(req).yamato_session;
  try {
    const url = new URL(req.url || "/", "http://localhost");
    const tabToken = url.searchParams.get("session");
    if (tabToken) token = tabToken;
  } catch {}
  const account = await getAccountBySessionToken(token);

  if (!account) {
    ws.send(JSON.stringify({ type: "auth_required" }));
    ws.close(1008, "Authentication required");
    return;
  }

  const id = crypto.randomBytes(8).toString("hex");

  let dbUser;
  try {
    dbUser = await ensureChatUser(account);
  } catch (error) {
    console.error("Chat user sync error:", error);
    ws.close(1011, "User sync failed");
    return;
  }

  const user = {
    id,
    dbUserId: dbUser.id,
    accountId: account.id,
    username: account.username,
    name: account.display_name,
    avatarUrl: account.avatar_url || null,
    channel: "general",
    view: "channel",
    dmConversationId: null
  };

  clients.set(ws, user);

  try {
    const history = await getHistory("general", dbUser.id);

    ws.send(JSON.stringify({
      type: "welcome",
      id,
      account: {
        username: account.username,
        displayName: account.display_name,
        bio: account.bio,
        chatUserId: dbUser.id,
        avatarUrl: account.avatar_url
      },
      channels: Object.entries(channels).map(([key, c]) => ({
        id: key,
        name: c.name
      })),
      currentChannel: "general",
      messages: history
    }));

    sendUserList();
  } catch (error) {
    console.error("Connection initialization error:", error);
    ws.close();
    return;
  }

  ws.on("message", async raw => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!data || typeof data !== "object") return;

    if (data.type === "join_channel") {
      const channel = String(data.channel || "");
      if (!channels[channel]) return;

      user.channel = channel;
      user.view = "channel";
      user.dmConversationId = null;
      const history = await getHistory(channel, user.dbUserId);

      ws.send(JSON.stringify({
        type: "channel_history",
        channel,
        messages: history
      }));

      sendUserList();
      return;
    }

    if (data.type === "open_dm") {
      const conversationId = String(data.conversationId || "");
      if (!conversationId) return;
      const participant = await getDmParticipants(conversationId);
      if (!participant || ![participant.user_a_id,participant.user_b_id].includes(user.accountId)) return;
      user.view = "dm";
      user.dmConversationId = conversationId;
      const history = await getDmHistory(conversationId, user.accountId);
      ws.send(JSON.stringify({type:"dm_history",conversationId,messages:history}));
      return;
    }

    if (data.type === "dm_message") {
      const conversationId = String(data.conversationId || "");
      const text = String(data.text || "").trim().slice(0,2000);
      if (!conversationId || !text) return;
      const participant = await getDmParticipants(conversationId);
      if (!participant || ![participant.user_a_id,participant.user_b_id].includes(user.accountId)) return;

      const {data:saved,error}=await supabase.from("dm_messages").insert({
        conversation_id:conversationId,sender_id:user.accountId,content:text
      }).select("id,conversation_id,sender_id,content,created_at,edited_at").single();
      if(error){console.error("DM message save error:",error);return;}

      const message={
        id:saved.id,dmConversationId:conversationId,userId:saved.sender_id,
        username:user.username,user:user.name,avatarUrl:user.avatarUrl||null,
        text:saved.content,time:saved.created_at,editedAt:saved.edited_at||null,reactions:[]
      };
      const recipients=[participant.user_a_id,participant.user_b_id];
      for(const [client,info] of clients){
        if(recipients.includes(info.accountId) && info.view==="dm" && info.dmConversationId===conversationId && client.readyState===1){
          client.send(JSON.stringify({type:"dm_message",conversationId,message}));
        } else if(recipients.includes(info.accountId) && info.accountId!==user.accountId && client.readyState===1){
          client.send(JSON.stringify({type:"dm_notification",conversationId,message}));
        }
      }
      return;
    }

    if (data.type === "dm_edit_message") {
      const messageId = String(data.messageId || "").trim();
      const conversationId = String(data.conversationId || "").trim();
      const newText = String(data.text || "").trim().slice(0, 2000);
      if (!messageId || !conversationId || !newText) return;

      const participant = await getDmParticipants(conversationId);
      if (!participant || ![participant.user_a_id,participant.user_b_id].includes(user.accountId)) return;

      const {data:target,error:findError}=await supabase.from("dm_messages")
        .select("id,conversation_id,sender_id").eq("id",messageId).maybeSingle();
      if(findError || !target || target.conversation_id!==conversationId || target.sender_id!==user.accountId) return;

      const {data:updated,error:updateError}=await supabase.from("dm_messages")
        .update({content:newText,edited_at:new Date().toISOString()})
        .eq("id",messageId).eq("sender_id",user.accountId).select("id,content,edited_at").single();
      if(updateError || !updated){console.error("DM edit error:",updateError);return;}

      for(const [client,info] of clients){
        if([participant.user_a_id,participant.user_b_id].includes(info.accountId) &&
           info.view==="dm" && info.dmConversationId===conversationId && client.readyState===1){
          client.send(JSON.stringify({type:"dm_message_edited",conversationId,messageId:updated.id,text:updated.content,editedAt:updated.edited_at}));
        }
      }
      return;
    }

    if (data.type === "dm_delete_message") {
      const messageId=String(data.messageId||"").trim();
      const conversationId=String(data.conversationId||"").trim();
      if(!messageId || !conversationId) return;

      const participant=await getDmParticipants(conversationId);
      if(!participant || ![participant.user_a_id,participant.user_b_id].includes(user.accountId)) return;

      const {data:target,error:findError}=await supabase.from("dm_messages")
        .select("id,conversation_id,sender_id").eq("id",messageId).maybeSingle();
      if(findError || !target || target.conversation_id!==conversationId || target.sender_id!==user.accountId) return;

      const {error:deleteError}=await supabase.from("dm_messages").delete()
        .eq("id",messageId).eq("sender_id",user.accountId);
      if(deleteError){console.error("DM delete error:",deleteError);return;}

      for(const [client,info] of clients){
        if([participant.user_a_id,participant.user_b_id].includes(info.accountId) &&
           info.view==="dm" && info.dmConversationId===conversationId && client.readyState===1){
          client.send(JSON.stringify({type:"dm_message_deleted",conversationId,messageId}));
        }
      }
      return;
    }

    if (data.type === "message") {
      const text = String(data.text || "").trim().slice(0, 2000);
      const channel = user.channel;
      const channelId = channels[channel]?.id;
      const rawAttachments = Array.isArray(data.attachments)
        ? data.attachments.slice(0, 10)
        : (data.attachment && typeof data.attachment === "object" ? [data.attachment] : []);

      const attachments = rawAttachments
        .filter(a => a && a.url)
        .map(a => ({
          url: String(a.url).slice(0, 2000),
          name: safeFileName(a.name).slice(0, 120),
          type: String(a.type || "application/octet-stream").slice(0, 150),
          size: Math.max(0, Number(a.size) || 0)
        }));

      if ((!text && attachments.length === 0) || !channelId) return;

      const insertRow = {
        channel_id: channelId,
        user_id: user.dbUserId,
        content: text,
        attachments
      };

      if (attachments[0]) {
        insertRow.attachment_url = attachments[0].url;
        insertRow.attachment_name = attachments[0].name;
        insertRow.attachment_type = attachments[0].type;
        insertRow.attachment_size = attachments[0].size;
      }

      let { data: saved, error } = await supabase
        .from("messages")
        .insert(insertRow)
        .select("id, content, created_at, edited_at, user_id, attachment_url, attachment_name, attachment_type, attachment_size, attachments")
        .single();

      if (error && /attachments|column/i.test(String(error.message || ""))) {
        // Migration not applied yet: save text and the first attachment using
        // the schema that existed before V2.4.5.
        const legacyRow = {
          channel_id: channelId,
          user_id: user.dbUserId,
          content: text
        };
        if (attachments[0]) {
          legacyRow.attachment_url = attachments[0].url;
          legacyRow.attachment_name = attachments[0].name;
          legacyRow.attachment_type = attachments[0].type;
          legacyRow.attachment_size = attachments[0].size;
        }
        ({ data: saved, error } = await supabase
          .from("messages")
          .insert(legacyRow)
          .select("id, content, created_at, edited_at, user_id, attachment_url, attachment_name, attachment_type, attachment_size")
          .single());

        if (!error && attachments.length > 1) {
          console.warn("attachments migration is missing; only the first attachment was saved.");
        }
      }

      if (error) {
        console.error("Message save error:", error);
        return;
      }

      const message = {
        id: saved.id,
        userId: saved.user_id,
        username: user.username,
        user: user.name,
        avatarUrl: user.avatarUrl || null,
        text: saved.content,
        time: saved.created_at,
        editedAt: saved.edited_at || null,
        attachments: Array.isArray(saved.attachments) ? saved.attachments : (
          saved.attachment_url ? [{
            url: saved.attachment_url,
            name: saved.attachment_name || "file",
            type: saved.attachment_type || "application/octet-stream",
            size: saved.attachment_size || 0
          }] : []
        ),
        attachment: saved.attachment_url ? {
          url: saved.attachment_url,
          name: saved.attachment_name || "file",
          type: saved.attachment_type || "application/octet-stream",
          size: saved.attachment_size || 0
        } : null
      };

      for (const [client, info] of clients) {
        if (info.view === "channel" && info.channel === channel && client.readyState === 1) {
          client.send(JSON.stringify({
            type: "message",
            channel,
            message
          }));
        }

      }

    }

    if (data.type === "edit_message") {
      const messageId = String(data.messageId || "").trim();
      const newText = String(data.text || "").trim().slice(0, 2000);
      if (!messageId || !newText) return;

      const channelId = channels[user.channel]?.id;
      if (!channelId || !user.dbUserId) return;

      const { data: target, error: findError } = await supabase
      .from("messages")
      .select("id, channel_id, user_id")
      .eq("id", messageId)
      .maybeSingle();

      if (findError || !target) return;
      if (target.user_id !== user.dbUserId || target.channel_id !== channelId) return;

      const { data: updated, error: updateError } = await supabase
      .from("messages")
      .update({
        content: newText,
        edited_at: new Date().toISOString()
      })
      .eq("id", messageId)
      .eq("user_id", user.dbUserId)
      .eq("channel_id", channelId)
      .select("id, content, edited_at")
      .single();

      if (updateError || !updated) {
      console.error("Message edit error:", updateError);
      return;
      }

      for (const [client, info] of clients) {
      if (info.channel === user.channel && client.readyState === 1) {
        client.send(JSON.stringify({
        type: "message_edited",
        channel: user.channel,
        messageId: updated.id,
        text: updated.content,
        editedAt: updated.edited_at
        }));
      }
      }
      return;
    }

    if (data.type === "delete_message") {
      const messageId = String(data.messageId || "").trim();
      if (!messageId) return;

      const channelId = channels[user.channel]?.id;
      if (!channelId || !user.dbUserId) return;

      const { data: target, error: findError } = await supabase
      .from("messages")
      .select("id, channel_id, user_id")
      .eq("id", messageId)
      .maybeSingle();

      if (findError || !target) return;
      if (target.user_id !== user.dbUserId || target.channel_id !== channelId) return;

      const { error: deleteError } = await supabase
      .from("messages")
      .delete()
      .eq("id", messageId)
      .eq("user_id", user.dbUserId)
      .eq("channel_id", channelId);

      if (deleteError) {
      console.error("Message delete error:", deleteError);
      return;
      }

      for (const [client, info] of clients) {
      if (info.channel === user.channel && client.readyState === 1) {
        client.send(JSON.stringify({
        type: "message_deleted",
        channel: user.channel,
        messageId
        }));
      }
      }
      return;
    }
  });

  ws.on("close", () => {
    const oldName = user.name;
    clients.delete(ws);

    broadcast({ type: "system", text: `${oldName} が退出しました` });
    sendUserList();
  });
});

app.get(/.*/, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

Promise.all([ensureDefaultData(), ensureStorageBucket()])
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Yamato Chat running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Supabase initialization failed:", error);
    process.exit(1);
  });
