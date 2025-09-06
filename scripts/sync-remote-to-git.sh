#!/bin/bash

# Verify link
npx supabase projects list | grep gvbtfolcizkzihforqte || npx supabase link --project-ref gvbtfolcizkzihforqte

# Run schema diff
ts=$(date +%Y%m%d%H%M%S)
file="supabase/migrations/${ts}_remote_delta.sql"
npx supabase db diff --linked --schema public,auth,storage,realtime,graphql_public,cron,vault --file "$file"

# Call sanitizer
node scripts/sanitize-migration.js "$file"

# Dump data-only seeds
npx supabase db dump --linked --data-only --schema storage -x storage.objects -x storage.s3_multipart_uploads -f "supabase/seeds/${ts}_storage_buckets.sql"
npx supabase db dump --linked --data-only --schema cron -f "supabase/seeds/${ts}_cron.sql"

# Custom roles
npx supabase db dump --linked --role-only -f supabase/roles.sql

# Edge Functions
npx supabase functions list -o json > /tmp/functions.json || true
for name in $(jq -r '.[]?.name' /tmp/functions.json); do
  npx supabase functions download "$name" -f "supabase/functions/$name"
done

# Secrets
npx supabase secrets list -o json > supabase/secrets/SECRETS.json || true

# Generate .env.example
jq -r '.[]?.name' supabase/secrets/SECRETS.json | while read key; do
  echo "$key=" >> .env.example
done

# Config-as-code
npx supabase config pull --linked -o supabase/config.toml || true

# Type generation
npx supabase gen types typescript --linked --schema public,auth,storage,realtime,graphql_public,cron,vault > supabase/types/database.types.ts

# Validate migrations locally
npx supabase db reset || echo "db reset failed, please fix the migration"

# Git commit & push
git add -A
git commit -m "chore(db): sync remote -> git (${ts}), export seeds/functions/secrets/config/types"
git push origin main

# Mark migration as applied
npx supabase migration repair --status applied "${ts}"

# Echo success
echo "Sync completed. Generated migration: $file"
