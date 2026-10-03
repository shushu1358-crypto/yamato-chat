const express = require("express");
const http = require("http");
const path = require("path");
const { WebSocketServer } = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;

// V1: 軽量なインメモリ履歴。
// 後でSupabase等に差し替えられる構造にしています。
const channels = {
  general: { name: "general", messages: [] },
  chat: { name: "雑談", messages: [] },
  game: { name: "ゲーム", messages: [] }
};

const clients = new Map();
const MAX_MESSAGES = 200;

app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "Yamato Chat", online: clients.size });
});

function broadcast(data) {
  const text = JSON.stringify(data);
  for (const ws of clients.keys()) {
    if (ws.readyState === 1) ws.send(text);
  }
}

function channelMessages(channel) {
  return channels[channel]?.messages || [];
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

wss.on("connection", (ws) => {
  const id = Math.random().toString(36).slice(2, 10);
  const user = { id, name: "Guest", channel: "general" };
  clients.set(ws, user);

  ws.send(JSON.stringify({
    type: "welcome",
    id,
    channels: Object.values(channels).map(c => ({ id: c.name, name: c.name })),
    currentChannel: "general",
    messages: channelMessages("general")
  }));

  sendUserList();

  ws.on("message", (raw) => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (data.type === "set_name") {
      const name = String(data.name || "").trim().slice(0, 24);
      if (!name) return;
      user.name = name;
      broadcast({
        type: "system",
        text: `${user.name} が参加しました`
      });
      sendUserList();
      return;
    }

    if (data.type === "join_channel") {
      const channel = String(data.channel || "");
      if (!channels[channel]) return;
      user.channel = channel;
      ws.send(JSON.stringify({
        type: "channel_history",
        channel,
        messages: channelMessages(channel)
      }));
      sendUserList();
      return;
    }

    if (data.type === "message") {
      const text = String(data.text || "").trim().slice(0, 2000);
      const channel = user.channel;
      if (!text || !channels[channel]) return;

      const message = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        userId: user.id,
        user: user.name,
        text,
        time: new Date().toISOString()
      };

      channels[channel].messages.push(message);
      if (channels[channel].messages.length > MAX_MESSAGES) {
        channels[channel].messages.shift();
      }

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

server.listen(PORT, () => {
  console.log(`Yamato Chat running on port ${PORT}`);
});
