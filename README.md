# Yamato Chat v1

Discord風の軽量リアルタイムチャット。

## ローカル起動

```bash
npm install
npm start
```

ブラウザで http://localhost:3000

## Render

- GitHubへこのフォルダをpush
- Renderで New → Web Service
- リポジトリを選択
- Build Command: `npm install`
- Start Command: `npm start`
- Environment: Node
- Freeプランでも試作可能

## 現在のV1

- 表示名
- リアルタイムWebSocketチャット
- 3チャンネル
- オンラインユーザー表示
- 直近200件のメッセージをサーバー内に保持
- RenderのHTTPS環境では自動的にWSSを利用

## 注意

V1はDBをまだ使っていません。Renderの無料サービスが再起動・停止すると履歴は消えます。
次の段階でSupabase/PostgreSQLを追加して永続化します。
