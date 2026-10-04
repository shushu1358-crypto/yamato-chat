# Yamato Chat v2.6.0-b2

- Backblaze B2 is used for avatar and attachment storage.
- Supabase remains the database.
- B2 attachment cleanup starts at 9 GiB and removes oldest `uploads/` objects until about 8.5 GiB.
- `Enter` sends; `Shift+Enter` inserts a newline.

Required Render environment variables:
- SUPABASE_URL
- SUPABASE_SECRET_KEY
- YAMATO_GATE_PASSWORD
- B2_KEY_ID
- B2_APPLICATION_KEY
- B2_BUCKET
- B2_ENDPOINT

No SQL migration is required for this B2/Shift+Enter change.

## Multi-server / channel management (V2.7 base)

Run `server_channel_migration.sql` once in Supabase SQL Editor.

This adds server ownership and enables:
- multiple servers
- server creation
- server switching
- channel creation
- channel deletion (only empty channels)
- server deletion (only when its channels contain no messages)

Existing servers, channels, accounts, and messages are preserved.
