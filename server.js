const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { WebSocketServer } = require("ws");
const { createClient } = require("@supabase/supabase-js");

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
  // Remove old sessions for this account when creating a fresh login.
  await supabase.from("sessions").delete().eq("account_id", accountId);

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

async function requireAccount(req, res, next) {
  const token = parseCookies(req).yamato_session;
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

    res.json({ ok: true, account });
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

    res.json({ ok: true, account });
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
    const token = parseCookies(req).yamato_session;
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
    res.json({ ok: true, account: data });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ ok: false, error: "プロフィールの更新に失敗しました" });
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

async function getHistory(channelKey) {
  const channelId = channels[channelKey]?.id;
  if (!channelId) return [];

  const { data, error } = await supabase
    .from("messages")
    .select(`
      id,
      content,
      created_at,
      user_id,
      chat_users(username)
    `)
    .eq("channel_id", channelId)
    .order("created_at", { ascending: false })
    .limit(MAX_MESSAGES);

  if (error) {
    console.error("History load error:", error);
    return [];
  }

  return (data || []).reverse().map(row => ({
    id: row.id,
    userId: row.user_id,
    user: row.chat_users?.username || "Unknown",
    text: row.content,
    time: row.created_at
  }));
}

async function ensureChatUser(account) {
  // Keep the existing messages schema working while accounts become
  // the canonical identity for login/profile.
  const { data, error } = await supabase
    .from("chat_users")
    .upsert(
      { username: account.username },
      { onConflict: "username" }
    )
    .select("id, username")
    .single();

  if (error) throw error;
  return data;
}


function verifyGatePassword(input) {
  return typeof input === "string" &&
    typeof YAMATO_GATE_PASSWORD === "string" &&
    input === YAMATO_GATE_PASSWORD;
}

wss.on("connection", async (ws, req) => {
  const token = parseCookies(req).yamato_session;
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
    channel: "general"
  };

  clients.set(ws, user);

  try {
    const history = await getHistory("general");

    ws.send(JSON.stringify({
      type: "welcome",
      id,
      account: {
        username: account.username,
        displayName: account.display_name,
        bio: account.bio,
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

    if (data.type === "join_channel") {
      const channel = String(data.channel || "");
      if (!channels[channel]) return;

      user.channel = channel;
      const history = await getHistory(channel);

      ws.send(JSON.stringify({
        type: "channel_history",
        channel,
        messages: history
      }));

      sendUserList();
      return;
    }

    if (data.type === "message") {
      const text = String(data.text || "").trim().slice(0, 2000);
      const channel = user.channel;
      const channelId = channels[channel]?.id;

      if (!text || !channelId) return;

      const { data: saved, error } = await supabase
        .from("messages")
        .insert({
          channel_id: channelId,
          user_id: user.dbUserId,
          content: text
        })
        .select("id, content, created_at, user_id")
        .single();

      if (error) {
        console.error("Message save error:", error);
        return;
      }

      const message = {
        id: saved.id,
        userId: saved.user_id,
        username: user.username,
        user: user.name,
        text: saved.content,
        time: saved.created_at
      };

      for (const [client, info] of clients) {
        if (info.channel === channel && client.readyState === 1) {
          client.send(JSON.stringify({
            type: "message",
            channel,
            message
          }));
        }
      }
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

ensureDefaultData()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Yamato Chat running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Supabase initialization failed:", error);
    process.exit(1);
  });
