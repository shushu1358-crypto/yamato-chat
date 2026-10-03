# Yamato Chat V2.2 - Account Edition

Yamato Chatにアカウント機能を追加した版。

## 追加されたもの

- YDMログイン画面
- 新規登録画面
- 表示名
- ユーザー名（半角英数字 + `_`）
- パスワード
- ゲートパスワード
- 自己紹介
- 30日間のサーバー側セッション
- ログアウト
- プロフィール表示
- WebSocket接続をログイン済みアカウントに限定
- パスワードはbcryptでハッシュ化して保存
- 既存チャット履歴との互換性を維持

## 重要: 初回セットアップ

GitHubを更新する前後どちらでも構いませんが、Supabase SQL Editorで
`account_migration.sql` を1回実行してください。

RenderのEnvironment Variablesは既存の
`SUPABASE_URL`
`SUPABASE_SECRET_KEY`
をそのまま使います。

Secret KeyをGitHubやブラウザコードに入れないでください。

## 注意

ゲートパスワードは現在「YDMへのログイン時に必要な追加パスワード」として実装しています。
将来、作品ごとのゲートパスワードを別テーブルで追加できます。

## V2.2.1

- ログイン/新規登録画面のブランド表記を「Yamato Chat」に統一
- 登録・ログイン時にサーバーから返された具体的なエラーを画面に表示

## V2.2.2

- ゲートパスワードをアカウントごとのパスワードではなく、Yamato Chat全体で共通の1つに統一
- `YAMATO_GATE_PASSWORD` をRenderのEnvironment Variablesに設定して管理
- アカウントパスワードとは分離

### 共通ゲートパスワードの設定

Render の Environment Variables に次を追加してください。

- `YAMATO_GATE_PASSWORD` = 全員共通で使うゲートパスワード

これはアカウントごとには保存せず、Yamato Chat全体で1つだけ使います。
