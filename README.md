# Yamato Chat v2 - Supabase版

Render + Supabaseでメッセージを永続保存するYamato Chat。

## RenderのEnvironment Variables

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY`

Secret KeyはGitHubやブラウザ側のコードに書かないでください。

## 起動

```bash
npm install
npm start
```

## V2で追加されたもの

- Supabaseへのメッセージ保存
- Render再起動後も過去メッセージを復元
- 初回起動時にYamato Chatサーバーと3チャンネルを自動作成
- `/health` にSupabase接続構成を表示

UIはV1と同じです。
