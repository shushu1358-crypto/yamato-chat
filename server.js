const express = require("express");
const http = require("http");
const path = require("path");
const { WebSocketServer } = require("ws");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SECRET_KEY.");
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

app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "Yamato Chat",
    database: "supabase",
    online: clients.size
  });
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

async function ensureUser(name) {
  const { data, error } = await supabase
    .from("chat_users")
    .upsert(
      { username: name },
      { onConflict: "username" }
    )
    .select("id, username")
    .single();

  if (error) throw error;
  return data;
}

wss.on("connection", async (ws) => {
  const id = Math.random().toString(36).slice(2, 10);
  const user = {
    id,
    dbUserId: null,
    name: "Guest",
    channel: "general"
  };
  clients.set(ws, user);

  try {
    const history = await getHistory("general");

    ws.send(JSON.stringify({
      type: "welcome",
      id,
      channels: Object.values(channels).map(c => ({
        id: Object.keys(channels).find(key => channels[key] === c),
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

  ws.on("message", async (raw) => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (data.type === "set_name") {
      const name = String(data.name || "").trim().slice(0, 24);
      if (!name) return;

      try {
        const dbUser = await ensureUser(name);
        user.dbUserId = dbUser.id;
        user.name = dbUser.username;

        broadcast({
          type: "system",
          text: `${user.name} が参加しました`
        });
        sendUserList();
      } catch (error) {
        console.error("User save error:", error);
      }
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

      if (!text || !channelId || !user.dbUserId) return;

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

    if (oldName !== "Guest") {
      broadcast({ type: "system", text: `${oldName} が退出しました` });
    }

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
