#!/bin/bash

set -euo pipefail

# Verify link
npx supabase projects list | grep gvbtfolcizkzihforqte || npx supabase link --project-ref gvbtfolcizkzihforqte

# Ensure directories exist
mkdir -p supabase/migrations supabase/seeds supabase/functions supabase/types supabase/storage supabase/secrets

# Run schema diff
ts=$(date +%Y%m%d%H%M%S)
file="supabase/migrations/${ts}_remote_delta.sql"
npx supabase db diff --linked \
  --schema public,auth,storage,realtime,graphql_public,cron,vault \
  --file "$file" || true

# If diff produced nothing, create a no-op migration so we can mark applied
if [ ! -f "$file" ] || [ ! -s "$file" ]; then
  echo "-- No schema changes detected at ${ts}" > "$file"
fi

# Call sanitizer (best-effort)
node scripts/sanitize-migration.js "$file" || true

# Dump data-only seeds
npx supabase db dump --linked --data-only --schema storage -x storage.objects -x storage.s3_multipart_uploads -f "supabase/seeds/${ts}_storage_buckets.sql" || true
npx supabase db dump --linked --data-only --schema cron -f "supabase/seeds/${ts}_cron.sql" || true

# Custom roles (may not be permitted on hosted; ignore failure)
npx supabase db dump --linked --role-only -f supabase/roles.sql || true

# Edge Functions export
npx supabase functions list -o json > /tmp/functions.json || echo '[]' > /tmp/functions.json
for name in $(jq -r '.[]? | .name // .slug // empty' /tmp/functions.json); do
  # Download into a clean folder per function
  rm -rf "supabase/functions/$name"
  npx supabase functions download "$name" -f "supabase/functions/$name" || true
done

# Secrets (names only)
npx supabase secrets list -o json | jq -r '[ .[]? | .name ]' > supabase/secrets/SECRETS.json || echo '[]' > supabase/secrets/SECRETS.json

# Generate .env.example (overwrite, names only, no values)
rm -f .env.example
jq -r '.[]' supabase/secrets/SECRETS.json | while read -r key; do
  echo "$key=" >> .env.example
done

# Config-as-code: CLI does not support config pull reliably; ensure config exists
if [ ! -f supabase/config.toml ]; then
  npx supabase init || true
fi

# Type generation (TS defs)
npx supabase gen types typescript --linked --schema public,auth,storage,realtime,graphql_public,cron,vault > supabase/types/database.types.ts

# Validate migrations locally (optional)
npx supabase db reset || echo "db reset failed, please review the latest migration order/dependencies"

# Git commit & push
git add -A
git commit -m "chore(db): sync remote -> git (${ts}), export seeds/functions/secrets/config/types" || echo "Nothing to commit"
git push origin main || true

# Mark the new migration as applied on prod (avoid re-apply)
npx supabase migration repair --status applied "${ts}" || true

# Echo success summary
echo "Sync completed. Generated migration: $file"
echo "Seeds: supabase/seeds/${ts}_storage_buckets.sql, supabase/seeds/${ts}_cron.sql"
echo "Types: supabase/types/database.types.ts"
echo "Secrets listed in: supabase/secrets/SECRETS.json and placeholders in .env.example"
