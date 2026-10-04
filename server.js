const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { WebSocketServer } = require("ws");
const { createClient } = require("@supabase/supabase-js");
const multer = require("multer");
const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectsCommand } = require("@aws-sdk/client-s3");

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

let serverCache = [];
let channelCache = [];

const clients = new Map();
const MAX_MESSAGES = 200;
const SESSION_DAYS = 30;
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
const MAX_AVATAR_BYTES = 5 * 1024 * 1024;
const STORAGE_BUCKET = process.env.B2_BUCKET || "yamato-chat-files";
const B2_ENDPOINT = process.env.B2_ENDPOINT;
const B2_KEY_ID = process.env.B2_KEY_ID;
const B2_APPLICATION_KEY = process.env.B2_APPLICATION_KEY;
const B2_REGION = process.env.B2_REGION || "us-west-004";
const FILE_URL_SECRET = process.env.SUPABASE_SECRET_KEY;
const ATTACHMENT_CAP_BYTES = 9 * 1024 * 1024 * 1024;
const ATTACHMENT_TARGET_BYTES = Math.floor(8.5 * 1024 * 1024 * 1024);
if (!B2_ENDPOINT || !B2_KEY_ID || !B2_APPLICATION_KEY) {
  console.error("Missing B2_ENDPOINT, B2_KEY_ID, or B2_APPLICATION_KEY.");
  process.exit(1);
}
const b2 = new S3Client({ region: B2_REGION, endpoint: B2_ENDPOINT, credentials: { accessKeyId: B2_KEY_ID, secretAccessKey: B2_APPLICATION_KEY } });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES }
});
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_AVATAR_BYTES }
});

app.use(express.json({ limit: "32kb" }));

// CORS: allow the client HTML to be opened directly from file://.
// Authentication is carried in the tab-specific Authorization header.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
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
        last_login_at,
        is_global_admin
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
        is_global_admin, password_hash
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

// Public profile lookup for the Discord-style user card.
// Only non-sensitive profile fields are returned.
app.get("/api/users/:username", requireAccount, async (req, res) => {
  try {
    const username = String(req.params.username || "").trim();
    const { data: profile, error } = await supabase
      .from("accounts")
      .select("id, username, display_name, bio, avatar_url, created_at")
      .eq("username", username)
      .maybeSingle();
    if (error) throw error;
    if (!profile) return res.status(404).json({ ok:false, error:"ユーザーが見つかりません" });

    const online = [...clients.values()].some(u => u.accountId === profile.id);
    res.json({
      ok: true,
      user: {
        id: profile.id,
        username: profile.username,
        displayName: profile.display_name,
        bio: profile.bio || "",
        avatarUrl: profile.avatar_url || null,
        createdAt: profile.created_at,
        online
      }
    });
  } catch (error) {
    console.error("User profile lookup error:", error);
    res.status(500).json({ ok:false, error:"ユーザープロフィールの取得に失敗しました" });
  }
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
      .select("id, username, display_name, bio, avatar_url, created_at, last_login_at, is_global_admin")
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

function fileToken(storagePath) {
  return crypto.createHmac("sha256", FILE_URL_SECRET).update(storagePath).digest("hex");
}

function publicStorageUrl(storagePath, req, download = false) {
  const base = `${req.protocol}://${req.get("host")}`;
  const params = new URLSearchParams({ key: storagePath, token: fileToken(storagePath) });
  if (download) params.set("download", "1");
  return `${base}/api/file?${params.toString()}`;
}

async function putB2Object(storagePath, buffer, contentType) {
  await b2.send(new PutObjectCommand({ Bucket: STORAGE_BUCKET, Key: storagePath, Body: buffer, ContentType: contentType || "application/octet-stream" }));
}

async function enforceAttachmentCap() {
  try {
    let continuationToken; const objects = [];
    do {
      const page = await b2.send(new ListObjectsV2Command({ Bucket: STORAGE_BUCKET, Prefix: "uploads/", ContinuationToken: continuationToken }));
      objects.push(...(page.Contents || []));
      continuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (continuationToken);
    let total = objects.reduce((sum, o) => sum + (Number(o.Size) || 0), 0);
    if (total <= ATTACHMENT_CAP_BYTES) return;
    objects.sort((a,b) => new Date(a.LastModified || 0) - new Date(b.LastModified || 0));
    let batch=[];
    for (const obj of objects) {
      if (total <= ATTACHMENT_TARGET_BYTES) break;
      if (!obj.Key) continue;
      batch.push({Key:obj.Key}); total -= Number(obj.Size)||0;
      if (batch.length===1000) { await b2.send(new DeleteObjectsCommand({Bucket:STORAGE_BUCKET,Delete:{Objects:batch,Quiet:true}})); batch=[]; }
    }
    if (batch.length) await b2.send(new DeleteObjectsCommand({Bucket:STORAGE_BUCKET,Delete:{Objects:batch,Quiet:true}}));
    console.log(`B2 attachment cleanup completed. Remaining estimated size: ${total} bytes`);
  } catch (error) { console.error("B2 attachment cleanup error:", error); }
}

app.get("/api/file", async (req,res) => {
  try {
    const key=String(req.query.key||""); const token=String(req.query.token||""); const expected=fileToken(key);
    if (!key || !token || token.length!==expected.length || !crypto.timingSafeEqual(Buffer.from(token),Buffer.from(expected))) return res.status(403).send("Forbidden");
    if (key.includes("\\") || key.includes("..") || key.startsWith("/")) return res.status(400).send("Invalid key");
    const obj=await b2.send(new GetObjectCommand({Bucket:STORAGE_BUCKET,Key:key}));
    if (obj.ContentType) res.setHeader("Content-Type",obj.ContentType);
    res.setHeader("Cache-Control","private, max-age=3600");
    const filename=path.basename(key).replace(/"/g,"");
    res.setHeader("Content-Disposition",`${String(req.query.download||"")==="1"?"attachment":"inline"}; filename="${filename}"`);
    if (obj.ContentLength!=null) res.setHeader("Content-Length",String(obj.ContentLength));
    obj.Body.pipe(res);
  } catch(error) { console.error("B2 file read error:",error); if(error?.name==="NoSuchKey") return res.status(404).send("Not found"); res.status(500).send("File read failed"); }
});

app.post("/api/profile/avatar", requireAccount, avatarUpload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "画像を選択してください" });
    }
    if (!String(req.file.mimetype || "").startsWith("image/")) {
      return res.status(400).json({ ok: false, error: "アイコンには画像ファイルを選択してください" });
    }

    const storagePath = makeStoragePath(req.account.id, safeFileName(req.file.originalname), "avatars");
    await putB2Object(storagePath, req.file.buffer, req.file.mimetype);
    const avatarUrl = publicStorageUrl(storagePath, req);

    const { data, error } = await supabase
      .from("accounts")
      .update({ avatar_url: avatarUrl })
      .eq("id", req.account.id)
      .select("id, username, display_name, bio, avatar_url, created_at, last_login_at, is_global_admin")
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

app.get("/api/servers", requireAccount, async (req, res) => {
  try {
    await refreshServerCache();
    const servers = await Promise.all(serverCache.map(async server => ({
      ...server,
      canManage: await canManageServer(req.account, server),
      role: await getServerRole(req.account.id, server.id) || (isGlobalAdmin(req.account) ? "admin" : null),
      channels: channelCache.filter(c => String(c.server_id) === String(server.id))
    })));
    res.json({ok:true, servers});
  } catch (error) {
    console.error("Server list error:", error);
    res.status(500).json({ ok:false, error:"サーバー一覧を取得できませんでした" });
  }
});

app.post("/api/servers", requireAccount, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim().slice(0, 40);
    if (!name) return res.status(400).json({ok:false,error:"サーバー名を入力してください"});
    const { data: server, error } = await supabase
      .from("servers")
      .insert({ name, owner_account_id: req.account.id })
      .select("id,name,description,icon_url,owner_account_id")
      .single();
    if (error) throw error;
    await ensureServerMember(req.account.id, server.id, "admin");
    const { data: channel, error: ce } = await supabase
      .from("channels")
      .insert({ server_id: server.id, name: "general" })
      .select("id,server_id,name")
      .single();
    if (ce) throw ce;
    await refreshServerCache();
    res.json({ok:true,server:{...server,canManage:true,channels:[channel]}});
  } catch(error) {
    console.error("Server create error:",error);
    res.status(500).json({ok:false,error:"サーバーを作成できませんでした"});
  }
});

app.patch("/api/servers/:id", requireAccount, async (req,res)=>{
  try {
    const server=getServer(req.params.id);
    if(!server) return res.status(404).json({ok:false,error:"サーバーが見つかりません"});
    if(!(await canManageServer(req.account,server))) return res.status(403).json({ok:false,error:"サーバーを変更する権限がありません"});
    const name=String(req.body.name ?? server.name).trim().slice(0,40);
    const description=String(req.body.description ?? server.description ?? "").trim().slice(0,300);
    if(!name) return res.status(400).json({ok:false,error:"サーバー名を入力してください"});
    const {data:updated,error}=await supabase.from("servers").update({name,description}).eq("id",server.id).select("id,name,description,icon_url,owner_account_id").single();
    if(error) throw error;
    await refreshServerCache();
    res.json({ok:true,server:{...updated,canManage:true}});
  } catch(error) {
    console.error("Server update error:",error);
    res.status(500).json({ok:false,error:"サーバー情報を変更できませんでした"});
  }
});

app.post("/api/servers/:id/icon", requireAccount, avatarUpload.single("file"), async (req,res)=>{
  try {
    const server=getServer(req.params.id);
    if(!server) return res.status(404).json({ok:false,error:"サーバーが見つかりません"});
    if(!(await canManageServer(req.account,server))) return res.status(403).json({ok:false,error:"サーバーを変更する権限がありません"});
    if(!req.file || !String(req.file.mimetype||"").startsWith("image/")) return res.status(400).json({ok:false,error:"サーバーアイコンには画像を選択してください"});
    const storagePath=makeStoragePath(req.account.id,safeFileName(req.file.originalname),"server-icons");
    await putB2Object(storagePath,req.file.buffer,req.file.mimetype);
    const iconUrl=publicStorageUrl(storagePath,req);
    const {data:updated,error}=await supabase.from("servers").update({icon_url:iconUrl}).eq("id",server.id).select("id,name,description,icon_url,owner_account_id").single();
    if(error) throw error;
    await refreshServerCache();
    res.json({ok:true,server:{...updated,canManage:true}});
  } catch(error) {
    console.error("Server icon upload error:",error);
    res.status(500).json({ok:false,error:"サーバーアイコンの変更に失敗しました"});
  }
});

app.delete("/api/servers/:id", requireAccount, async (req,res) => {
  try {
    const server=getServer(req.params.id);
    if(!server) return res.status(404).json({ok:false,error:"サーバーが見つかりません"});
    if(!(await canManageServer(req.account,server))) return res.status(403).json({ok:false,error:"このサーバーを削除する権限がありません"});
    const channelsForServer=channelCache.filter(c=>String(c.server_id)===String(server.id));
    // Server deletion is destructive by design: remove messages first, then channels.
    // The old UI forced users to manually empty every channel, which was confusing.
    for(const ch of channelsForServer){
      const {error:me}=await supabase.from("messages").delete().eq("channel_id",ch.id);
      if(me) throw me;
    }
    const {error:cm}=await supabase.from("server_members").delete().eq("server_id",server.id);
    if(cm && cm.code !== "42P01") throw cm;
    const {error}=await supabase.from("channels").delete().eq("server_id",server.id);
    if(error) throw error;
    const {error:se}=await supabase.from("servers").delete().eq("id",server.id);
    if(se) throw se;
    await refreshServerCache();
    res.json({ok:true});
  }catch(error){
    console.error("Server delete error:",error);
    res.status(500).json({ok:false,error:"サーバーを削除できませんでした"});
  }
});

app.post("/api/servers/:serverId/channels", requireAccount, async (req,res)=>{
  try{
    const server=getServer(req.params.serverId);
    if(!server) return res.status(404).json({ok:false,error:"サーバーが見つかりません"});
    if(!(await canManageServer(req.account,server))) return res.status(403).json({ok:false,error:"チャンネルを管理する権限がありません"});
    const name=String(req.body.name||"").trim().replace(/^#+/,"").slice(0,40);
    if(!name) return res.status(400).json({ok:false,error:"チャンネル名を入力してください"});
    const {data:channel,error}=await supabase.from("channels").insert({server_id:server.id,name}).select("id,server_id,name").single();
    if(error) throw error;
    await refreshServerCache();
    res.json({ok:true,channel});
  }catch(error){
    console.error("Channel create error:",error);
    res.status(500).json({ok:false,error:"チャンネルを作成できませんでした"});
  }
});

app.delete("/api/channels/:id", requireAccount, async (req,res)=>{
  try{
    const channel=getChannel(req.params.id);
    if(!channel) return res.status(404).json({ok:false,error:"チャンネルが見つかりません"});
    const server=getServer(channel.server_id);
    if(!(await canManageServer(req.account,server))) return res.status(403).json({ok:false,error:"チャンネルを削除する権限がありません"});
    const channelCount=channelCache.filter(c=>String(c.server_id)===String(server.id)).length;
    if(channelCount<=1) return res.status(400).json({ok:false,error:"サーバーには最低1つのチャンネルが必要です"});
    // Deleting a channel also deletes its messages. No manual cleanup step.
    const {error:messageDeleteError}=await supabase.from("messages").delete().eq("channel_id",channel.id);
    if(messageDeleteError) throw messageDeleteError;
    const {error}=await supabase.from("channels").delete().eq("id",channel.id);
    if(error) throw error;
    await refreshServerCache();
    res.json({ok:true});
  }catch(error){
    console.error("Channel delete error:",error);
    res.status(500).json({ok:false,error:"チャンネルを削除できませんでした"});
  }
});

// Server member/admin role management.
app.get("/api/servers/:id/members", requireAccount, async (req,res)=>{
  try{
    const server=getServer(req.params.id);
    if(!server) return res.status(404).json({ok:false,error:"サーバーが見つかりません"});
    await ensureServerMember(req.account.id, server.id, (server.owner_account_id===req.account.id || isGlobalAdmin(req.account)) ? "admin" : "member");
    const {data,error}=await supabase.from("server_members")
      .select("server_id,user_id,role,accounts(id,username,display_name,bio,avatar_url)")
      .eq("server_id",server.id).order("role",{ascending:true});
    if(error) throw error;
    res.json({ok:true,members:(data||[]).map(x=>({serverId:x.server_id,accountId:x.user_id,role:x.role,user:x.accounts}))});
  }catch(error){ console.error("Server members error:",error); res.status(500).json({ok:false,error:"メンバー一覧を取得できませんでした"}); }
});

app.patch("/api/servers/:serverId/members/:accountId", requireAccount, async (req,res)=>{
  try{
    const server=getServer(req.params.serverId);
    if(!server) return res.status(404).json({ok:false,error:"サーバーが見つかりません"});
    if(!(await canManageServer(req.account,server))) return res.status(403).json({ok:false,error:"管理者権限が必要です"});
    const targetId=String(req.params.accountId);
    const role=String(req.body.role||"").toLowerCase()==="admin" ? "admin" : "member";
    if(String(server.owner_account_id)===targetId && role!=="admin") return res.status(400).json({ok:false,error:"サーバー所有者はメンバーに変更できません"});
    const {data:target,error:te}=await supabase.from("accounts").select("id,username,display_name").eq("id",targetId).maybeSingle();
    if(te) throw te; if(!target) return res.status(404).json({ok:false,error:"ユーザーが見つかりません"});
    await ensureServerMember(targetId,server.id,role);
    res.json({ok:true,accountId:targetId,role});
  }catch(error){ console.error("Role update error:",error); res.status(500).json({ok:false,error:"権限を変更できませんでした"}); }
});

app.get("/api/notifications", requireAccount, async (req,res)=>{
  try{
    const {data,error}=await supabase.from("notifications").select("id,type,message,server_id,channel_id,actor_id,is_read,created_at").eq("recipient_id",req.account.id).order("created_at",{ascending:false}).limit(50);
    if(error) throw error;
    const notifications=(data||[]).map(n=>({id:n.id,type:n.type,title:n.type==="mention"?"メンション":"通知",body:n.message||"",server_id:n.server_id,channel_id:n.channel_id,read_at:n.is_read?new Date(n.created_at).toISOString():null,created_at:n.created_at}));
    res.json({ok:true,notifications,unread:notifications.filter(n=>!n.read_at).length});
  }catch(error){ console.error("Notification load error:",error); res.status(500).json({ok:false,error:"通知を取得できませんでした"}); }
});
app.post("/api/notifications/read", requireAccount, async (req,res)=>{
  try{
    const {error}=await supabase.from("notifications").update({is_read:true}).eq("recipient_id",req.account.id).eq("is_read",false);
    if(error) throw error;
    res.json({ok:true});
  }catch(error){ console.error("Notification read error:",error); res.status(500).json({ok:false,error:"通知を既読にできませんでした"}); }
});

async function createMentionNotifications(text, message, serverId, channelId){
  const names=[...String(text||"").matchAll(/@([A-Za-z0-9_]{3,24})/g)].map(m=>m[1].toLowerCase());
  if(!names.length) return;
  const unique=[...new Set(names)];
  const {data:targets,error}=await supabase.from("accounts").select("id,username").in("username",unique);
  if(error) { console.error("Mention lookup error:",error); return; }
  const rows=(targets||[]).filter(t=>String(t.id)!==String(message.accountId)).map(t=>({
    recipient_id:t.id,type:"mention",message:`${message.user} さんがあなたをメンションしました: ${String(text).slice(0,450)}`,server_id:serverId,channel_id:channelId,actor_id:message.accountId
  }));
  if(rows.length){ const {error:ne}=await supabase.from("notifications").insert(rows); if(ne) console.error("Mention notification error:",ne); }
  for(const t of targets||[]){ if(String(t.id)!==String(message.accountId)) await sendToAccount(t.id,{type:"notification",notification:{title:`${message.user} さんがあなたをメンションしました`,body:String(text).slice(0,500),serverId,channelId,messageId:message.id}}); }
}

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

    await putB2Object(storagePath, req.file.buffer, req.file.mimetype || "application/octet-stream");
    void enforceAttachmentCap();

    res.json({
      ok: true,
      file: {
        url: publicStorageUrl(storagePath, req),
        key: storagePath,
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

async function refreshServerCache() {
  const { data: servers, error: se } = await supabase
    .from("servers")
    .select("id,name,description,icon_url,owner_account_id")
    .order("id", { ascending: true });
  if (se) throw se;
  const { data: channels, error: ce } = await supabase
    .from("channels")
    .select("id,server_id,name")
    .order("id", { ascending: true });
  if (ce) throw ce;
  serverCache = servers || [];
  channelCache = channels || [];
  return { servers: serverCache, channels: channelCache };
}

function getServer(serverId) {
  return serverCache.find(s => String(s.id) === String(serverId)) || null;
}
function getChannel(channelId) {
  return channelCache.find(c => String(c.id) === String(channelId)) || null;
}

function isGlobalAdmin(account) {
  return !!account?.is_global_admin;
}

async function getServerRole(accountId, serverId) {
  if (!accountId || !serverId) return null;
  const { data, error } = await supabase
    .from("server_members")
    .select("role")
    .eq("user_id", accountId)
    .eq("server_id", serverId)
    .maybeSingle();
  if (error) {
    if (error.code === "42P01") return null;
    throw error;
  }
  return data?.role || null;
}

async function ensureServerMember(accountId, serverId, role="member") {
  const {data:existing,error:findError}=await supabase.from("server_members")
    .select("server_id,user_id,role").eq("server_id",serverId).eq("user_id",accountId).maybeSingle();
  if(findError) throw findError;
  if(existing) return existing;
  const {data,error}=await supabase.from("server_members")
    .insert({server_id:serverId,user_id:accountId,role})
    .select("server_id,user_id,role").single();
  if(error) throw error;
  return data;
}

async function canManageServer(account, server) {
  if (!server) return false;
  if (isGlobalAdmin(account)) return true;
  if (server.owner_account_id && String(server.owner_account_id) === String(account.id)) return true;
  return (await getServerRole(account.id, server.id)) === "admin";
}

async function ensureDefaultData() {
  let { data: existingServer, error: serverSelectError } = await supabase
    .from("servers")
    .select("id,name,description,icon_url,owner_account_id")
    .eq("name", "Yamato Chat")
    .limit(1)
    .maybeSingle();
  if (serverSelectError) throw serverSelectError;

  let serverId = existingServer?.id;
  if (!serverId) {
    const { data: createdServer, error } = await supabase
      .from("servers")
      .insert({ name: "Yamato Chat", description: "Yamato Chatの公式サーバー" })
      .select("id,name,description,icon_url,owner_account_id")
      .single();
    if (error) throw error;
    existingServer = createdServer;
    serverId = createdServer.id;
  }

  // Legacy Yamato Chat servers created before ownership support had no owner.
  // Claim only the default Yamato Chat server for the first existing account.
  if (existingServer && !existingServer.owner_account_id && existingServer.name === "Yamato Chat") {
    const { data: firstAccount } = await supabase
      .from("accounts")
      .select("id")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();
    if (firstAccount) {
      const { data: claimed } = await supabase
        .from("servers")
        .update({ owner_account_id: firstAccount.id })
        .eq("id", existingServer.id)
        .is("owner_account_id", null)
        .select("id,name,description,icon_url,owner_account_id")
        .maybeSingle();
      if (claimed) existingServer = claimed;
    }
  }

  const defaults = ["general", "雑談", "ゲーム"];
  for (const channelName of defaults) {
    const { data: existingChannel, error: channelSelectError } = await supabase
      .from("channels")
      .select("id")
      .eq("server_id", serverId)
      .eq("name", channelName)
      .limit(1)
      .maybeSingle();
    if (channelSelectError) throw channelSelectError;
    if (!existingChannel) {
      const { error } = await supabase
        .from("channels")
        .insert({ server_id: serverId, name: channelName });
      if (error) throw error;
    }
  }
  await refreshServerCache();
  console.log("Supabase initialized:", serverCache.map(s => ({id:s.id,name:s.name})));
}

async function getHistory(channelId, reactionUserId = null) {
  if (!getChannel(channelId)) return [];
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
    if (row.status === "accepted") {
      // A friend automatically gets a DM entry. Recreate it if an older
      // database state is missing the conversation.
      try {
        await getOrCreateDmConversation(accountId, otherId);
      } catch (dmError) {
        console.error("DM conversation sync error:", dmError);
      }
      friends.push(item);
    } else if (row.status === "pending" && row.requester_id !== accountId) incoming.push(item);
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

    // DM entries belong to the friendship. Remove the conversation as well
    // so an old DM cannot reappear after a restart.
    const [dmA, dmB] = canonicalPair(row.user_a_id, row.user_b_id);
    const { error: dmDeleteError } = await supabase
      .from("dm_conversations")
      .delete()
      .eq("user_a_id", dmA)
      .eq("user_b_id", dmB);
    if (dmDeleteError) console.error("DM conversation cleanup error:", dmDeleteError);

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

    // DM list = accepted friends only. This prevents stale conversations
    // from appearing after a restart or after a friendship was removed.
    const friendData = await getFriendData(id);
    const acceptedIds = new Set(friendData.friends.map(f => f.other.id));

    const {data: rows,error}=await supabase.from("dm_conversations")
      .select("id,user_a_id,user_b_id,created_at")
      .or(`user_a_id.eq.${id},user_b_id.eq.${id}`)
      .order("created_at",{ascending:false});
    if(error) throw error;

    const validRows = (rows || []).filter(r => {
      const otherId = r.user_a_id === id ? r.user_b_id : r.user_a_id;
      return acceptedIds.has(otherId);
    });

    const otherIds=validRows.map(r=>r.user_a_id===id?r.user_b_id:r.user_a_id);
    const accounts=otherIds.length ? (await supabase.from("accounts")
      .select("id,username,display_name,avatar_url").in("id",otherIds)).data||[] : [];
    const byId=Object.fromEntries(accounts.map(a=>[a.id,a]));
    const result=[];
    for(const row of validRows){
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

wss.on("connection", (ws, req) => {
  (async () => {
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
    const defaultChannel = channelCache.find(c => c.name === "general") || channelCache[0];
    if (!defaultChannel) throw new Error("No channels available");
    user.channel = String(defaultChannel.id);
    const history = await getHistory(defaultChannel.id, dbUser.id);

    ws.send(JSON.stringify({
      type: "welcome",
      id,
      account: {
        username: account.username,
        displayName: account.display_name,
        bio: account.bio,
        chatUserId: dbUser.id,
        avatarUrl: account.avatar_url,
        isGlobalAdmin: !!account.is_global_admin
      },
      servers: await Promise.all(serverCache.map(async server => ({
        id: server.id,
        name: server.name,
        description: server.description || "",
        iconUrl: server.icon_url || null,
        ownerAccountId: server.owner_account_id,
        canManage: await canManageServer(account, server),
        role: await getServerRole(account.id, server.id) || (isGlobalAdmin(account) ? "admin" : null),
        channels: channelCache.filter(c => String(c.server_id) === String(server.id)).map(c => ({id:c.id,name:c.name}))
      }))),
      channels: channelCache.map(c => ({ id: c.id, serverId: c.server_id, name: c.name })),
      currentChannel: String(defaultChannel.id),
      messages: history
    }));

    sendUserList();
  } catch (error) {
    console.error("Connection initialization error:", error);
    ws.close();
    return;
  }

  ws.on("message", raw => {
    (async () => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!data || typeof data !== "object") return;

    if (data.type === "join_channel") {
      const channel = String(data.channel || "");
      const channelInfo = getChannel(channel);
      if (!channelInfo) return;
      const serverInfo = getServer(channelInfo.server_id);
      if (!serverInfo) return;
      await ensureServerMember(user.accountId, serverInfo.id, (String(serverInfo.owner_account_id)===String(user.accountId) || isGlobalAdmin(account)) ? "admin" : "member");

      user.channel = channel;
      user.server = String(channelInfo.server_id);
      user.view = "channel";
      user.dmConversationId = null;
      const history = await getHistory(channel, user.dbUserId);

      ws.send(JSON.stringify({
        type: "channel_history",
        channel,
        serverId: channelInfo.server_id,
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
      const channelInfo = getChannel(channel);
      const channelId = channel;
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
      await createMentionNotifications(text, {...message,accountId:user.accountId}, channelInfo?.server_id || user.server, channel);

    }

    if (data.type === "edit_message") {
      const messageId = String(data.messageId || "").trim();
      const newText = String(data.text || "").trim().slice(0, 2000);
      if (!messageId || !newText) return;

      const channelId = user.channel;
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

      const channelId = user.channel;
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
    })().catch(error => {
      console.error("WebSocket message handler error:", error);
    });
  });

  ws.on("close", () => {
    clients.delete(ws);
    // Leave silently. The member list reflects the offline state.
    sendUserList();
  });
  })().catch(error => {
    console.error("WebSocket connection handler error:", error);
    try { ws.close(1011, "Internal server error"); } catch {}
  });
});

app.get(/.*/, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

process.on("unhandledRejection", reason => {
  console.error("Unhandled promise rejection:", reason);
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
