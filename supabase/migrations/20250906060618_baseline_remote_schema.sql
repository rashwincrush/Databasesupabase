

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE SCHEMA IF NOT EXISTS "backup_exports";


ALTER SCHEMA "backup_exports" OWNER TO "postgres";


CREATE EXTENSION IF NOT EXISTS "pg_cron" WITH SCHEMA "pg_catalog";






CREATE EXTENSION IF NOT EXISTS "pg_net" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgsodium";






COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "http" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "moddatetime" WITH SCHEMA "public";






CREATE EXTENSION IF NOT EXISTS "pg_graphql" WITH SCHEMA "graphql";






CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgjwt" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE TYPE "public"."approval_status" AS ENUM (
    'pending',
    'approved',
    'rejected'
);


ALTER TYPE "public"."approval_status" OWNER TO "postgres";


CREATE TYPE "public"."employment_type" AS ENUM (
    'full-time',
    'part-time',
    'contract',
    'internship'
);


ALTER TYPE "public"."employment_type" OWNER TO "postgres";


CREATE TYPE "public"."profile_approval_status" AS ENUM (
    'pending',
    'approved',
    'rejected'
);


ALTER TYPE "public"."profile_approval_status" OWNER TO "postgres";


CREATE TYPE "public"."rsvp_status" AS ENUM (
    'going',
    'not_going',
    'interested'
);


ALTER TYPE "public"."rsvp_status" OWNER TO "postgres";


CREATE TYPE "public"."social_type" AS ENUM (
    'linkedin',
    'github',
    'website',
    'instagram',
    'facebook',
    'x'
);


ALTER TYPE "public"."social_type" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."_http_request_compat"("_method" "text", "_url" "text", "_headers" "extensions"."http_header"[] DEFAULT NULL::"extensions"."http_header"[], "_content" "text" DEFAULT NULL::"text") RETURNS "extensions"."http_response"
    LANGUAGE "plpgsql" STABLE
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare resp extensions.http_response; _m text := upper(coalesce(_method,'GET'));
begin
  begin resp := extensions.http_request(method:=_m, uri:=_url, headers:=_headers, content:=_content); return resp; exception when undefined_function then null; end;
  begin resp := extensions.http_request(_m, _url, _content, _headers); return resp; exception when undefined_function then null; end;

  if _m='DELETE' then begin resp := extensions.http_delete(_url, _headers); return resp; exception when undefined_function then null; end; end if;
  if _m='POST' then
    begin resp := extensions.http_post(_url, _content, 'application/json', _headers); return resp; exception when undefined_function then null; end;
    begin resp := extensions.http_post(_url, _content, _headers); return resp; exception when undefined_function then null; end;
  end if;
  if _m='GET' then begin resp := extensions.http_get(_url, _headers); return resp; exception when undefined_function then null; end; end if;

  raise exception 'No compatible HTTP function found' using errcode='42883';
end;
$$;


ALTER FUNCTION "public"."_http_request_compat"("_method" "text", "_url" "text", "_headers" "extensions"."http_header"[], "_content" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."_is_admin"("uid" "uuid") RETURNS boolean
    LANGUAGE "plpgsql" STABLE
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  col text;
  sql text;
  result boolean;
BEGIN
  -- Find a plausible "label" column on roles
  SELECT c.column_name INTO col
  FROM information_schema.columns c
  WHERE c.table_schema='public' AND c.table_name='roles'
    AND c.column_name = ANY (ARRAY['name','slug','code','key','title','role','label'])
  ORDER BY array_position(ARRAY['name','slug','code','key','title','role','label'], c.column_name)
  LIMIT 1;

  IF col IS NULL THEN
    -- Fallback 1: roles.is_admin boolean
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='roles' AND column_name='is_admin'
    ) THEN
      sql := $q$
        SELECT EXISTS (
          SELECT 1
          FROM public.user_roles ur
          JOIN public.roles r ON r.id = ur.role_id
          WHERE ur.profile_id = $1
            AND r.is_admin = true
        )
      $q$;
      EXECUTE sql INTO result USING uid;
      RETURN COALESCE(result, false);
    ELSE
      -- Fallback 2: profiles.is_admin boolean
      RETURN COALESCE((SELECT p.is_admin FROM public.profiles p WHERE p.id = uid), false);
    END IF;
  END IF;

  -- Primary path: compare the detected label column to admin names
  sql := format($fmt$
    SELECT EXISTS (
      SELECT 1
      FROM public.user_roles ur
      JOIN public.roles r ON r.id = ur.role_id
      WHERE ur.profile_id = $1
        AND lower(r.%I) IN ('admin','super_admin','super admin')
    )
  $fmt$, col);

  EXECUTE sql INTO result USING uid;
  RETURN COALESCE(result, false);
END;
$_$;


ALTER FUNCTION "public"."_is_admin"("uid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."add_creator_as_group_admin"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  -- Add creator as admin member; ignore on conflict
  IF NEW.created_by IS NOT NULL THEN
    INSERT INTO public.group_members (group_id, user_id, role)
    VALUES (NEW.id, NEW.created_by, 'admin')
    ON CONFLICT DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."add_creator_as_group_admin"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."add_creator_to_group_members"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM group_members
    WHERE group_id = NEW.id AND user_id = auth.uid()
  ) THEN
    INSERT INTO group_members (group_id, user_id)
    VALUES (NEW.id, auth.uid());
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."add_creator_to_group_members"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_delete_job"("p_job_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = auth.uid()
      AND (p.is_admin = true OR p.role IN ('admin','super_admin'))
  ) THEN
    RAISE EXCEPTION 'not authorized' USING ERRCODE='42501';
  END IF;

  DELETE FROM public.jobs WHERE id = p_job_id;

  INSERT INTO public.admin_actions (admin_id, action_type, target_type, target_id, description)
  VALUES (auth.uid(), 'delete', 'job', p_job_id, 'Admin deleted job');
END;
$$;


ALTER FUNCTION "public"."admin_delete_job"("p_job_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_delete_user_fallback"("target_user_id" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  caller_id UUID;
  caller_role TEXT;
  target_role TEXT;
  result JSONB;
BEGIN
  -- Get caller's ID from current session
  caller_id := auth.uid();
  
  -- Check if caller is authenticated
  IF caller_id IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'Authentication required');
  END IF;
  
  -- Get caller's role
  SELECT role INTO caller_role FROM profiles WHERE id = caller_id;
  
  -- Only admin or super_admin can delete users
  IF caller_role NOT IN ('admin', 'super_admin') THEN
    RETURN jsonb_build_object('success', false, 'error', 'Insufficient permissions');
  END IF;
  
  -- Get target user's role
  SELECT role INTO target_role FROM profiles WHERE id = target_user_id;
  
  -- Check if user exists
  IF target_role IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'User not found');
  END IF;
  
  -- Only super_admin can delete admin/super_admin users
  IF target_role IN ('admin', 'super_admin') AND caller_role <> 'super_admin' THEN
    RETURN jsonb_build_object('success', false, 'error', 'Only super_admin can delete admin/super_admin users');
  END IF;
  
  -- Cannot delete yourself
  IF caller_id = target_user_id THEN
    RETURN jsonb_build_object('success', false, 'error', 'Cannot delete your own account');
  END IF;
  
  -- We'll skip purge_user_data and just do direct cleanup
  
  -- Delete all user's content (add specific tables based on your schema)
  -- This is simplified and should be expanded based on your specific database schema
  BEGIN
    -- Posts (if such table exists)
    DELETE FROM posts WHERE author_id = target_user_id;
    EXCEPTION WHEN undefined_table THEN NULL; -- Ignore if table doesn't exist
  END;
  
  BEGIN
    -- Comments (if such table exists)
    DELETE FROM comments WHERE user_id = target_user_id;
    EXCEPTION WHEN undefined_table THEN NULL; -- Ignore if table doesn't exist
  END;
  
  BEGIN
    -- Group memberships
    DELETE FROM group_members WHERE user_id = target_user_id;
    EXCEPTION WHEN undefined_table THEN NULL; -- Ignore if table doesn't exist
  END;
  
  -- Mark as deleted in profiles
  -- This is NOT a complete deletion! Auth.users record remains, but data is anonymized
  UPDATE profiles 
  SET 
    email = 'deleted_' || id || '@deleted.user',
    full_name = 'Deleted User',
    updated_at = NOW(),
    is_deleted = TRUE
  WHERE id = target_user_id;
  
  -- Log action to admin_actions
  INSERT INTO admin_actions (
    admin_id,
    action_type,
    target_type,
    target_id,
    description
  ) VALUES (
    caller_id,
    'delete_user_fallback',
    'user',
    target_user_id,
    'User data cleanup via fallback RPC (auth record remains)'
  );
  
  -- Return success with warnings
  RETURN jsonb_build_object(
    'success', true,
    'warning', 'This is a partial deletion. The auth.users record may remain as RPC cannot access the Auth Admin API.',
    'details', jsonb_build_object('user_id', target_user_id, 'deleted_by', caller_id)
  );
END;
$$;


ALTER FUNCTION "public"."admin_delete_user_fallback"("target_user_id" "uuid") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."admin_delete_user_fallback"("target_user_id" "uuid") IS 'Fallback admin user deletion. Only cleans up application data. Cannot delete auth records - Edge Function required for complete deletion.';



CREATE OR REPLACE FUNCTION "public"."admin_delete_user_rpc"("target" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'net', 'vault', 'extensions'
    AS $$
declare
  requester uuid := auth.uid();
  srv_key   text := (select decrypted_secret from vault.decrypted_secrets where name='service_role');
  base_url  text := (select decrypted_secret from vault.decrypted_secrets where name='project_url');

  req_id    bigint;
  v_status  int;
  v_body    text;

  target_role text;
  super_admins_left int;

  -- OPTIONAL: gather storage object paths if you use them
  avatar_path text;
  resume_paths text[];
begin
  -- AuthZ
  if requester is null then return jsonb_build_object('error','unauthorized'); end if;
  if not exists (select 1 from public.profiles p where p.id=requester and p.role in ('admin','super_admin'))
     then return jsonb_build_object('error','forbidden'); end if;
  if target = requester then return jsonb_build_object('error','cannot_delete_self'); end if;

  select role into target_role from public.profiles where id=target;
  if target_role in ('admin','super_admin') and not exists
     (select 1 from public.profiles p where p.id=requester and p.role='super_admin')
  then return jsonb_build_object('error','only_super_admin_can_delete_admins'); end if;

  if target_role='super_admin' then
    select count(*) into super_admins_left from public.profiles where role='super_admin' and id<>target;
    if coalesce(super_admins_left,0)=0 then
      return jsonb_build_object('error','cannot_delete_last_super_admin');
    end if;
  end if;

  -- OPTIONAL storage cleanup (ignore if columns/tables don’t exist)
  begin
    select p.avatar_path into avatar_path from public.profiles p where p.id=target;
  exception when undefined_column then null; end;

  begin
    select array_agg(file_path) into resume_paths from public.user_resumes where user_id=target;
  exception when undefined_table or undefined_column then null; end;

  if avatar_path is not null then
    perform net.http_post(
      url     := base_url || '/storage/v1/object/avatars/remove',
      headers := jsonb_build_object('apikey',srv_key,'authorization','Bearer '||srv_key,'Content-Type','application/json'),
      body    := jsonb_build_array(jsonb_build_object('bucket','avatars','name',avatar_path))
    );
  end if;

  if resume_paths is not null then
    perform net.http_post(
      url     := base_url || '/storage/v1/object/resumes/remove',
      headers := jsonb_build_object('apikey',srv_key,'authorization','Bearer '||srv_key,'Content-Type','application/json'),
      body    := (select jsonb_agg(jsonb_build_object('bucket','resumes','name',p)) from unnest(resume_paths) as p)
    );
  end if;

  -- Purge app data
  perform public.purge_user_data(target);

  -- Delete Auth user via GoTrue Admin API (async)
  req_id := net.http_delete(
    url     := base_url || '/auth/v1/admin/users/' || target::text,
    headers := jsonb_build_object('apikey',srv_key,'authorization','Bearer '||srv_key,'Content-Type','application/json')
  );

  -- Block for up to ~5s waiting for the response to land
  perform pg_sleep(0.2);
  for i in 1..25 loop
    select status_code, content into v_status, v_body from net._http_response where id=req_id;
    exit when v_status is not null;
    perform pg_sleep(0.2);
  end loop;

  if v_status between 200 and 299 then
    return jsonb_build_object('ok',true,'status',v_status);
  else
    return jsonb_build_object('error','auth_delete_failed','status',v_status,'body',v_body);
  end if;
end;
$$;


ALTER FUNCTION "public"."admin_delete_user_rpc"("target" "uuid") OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."profiles" (
    "id" "uuid" NOT NULL,
    "email" "text" NOT NULL,
    "first_name" "text",
    "last_name" "text",
    "full_name" "text" GENERATED ALWAYS AS ((("first_name" || ' '::"text") || "last_name")) STORED,
    "avatar_url" "text",
    "graduation_year" integer,
    "degree" "text",
    "major" "text",
    "current_company" "text",
    "current_position" "text",
    "location" "text",
    "bio" "text",
    "linkedin_url" "text",
    "twitter_url" "text",
    "website_url" "text",
    "is_verified" boolean DEFAULT false,
    "is_mentor" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "mentor_availability" "text",
    "mentor_topics" "text"[],
    "mentor_status" "text" DEFAULT 'pending'::"text",
    "mentee_status" "text" DEFAULT 'pending'::"text",
    "alumni_verification_status" "text" DEFAULT 'pending'::"text",
    "verification_document_url" "text",
    "verification_notes" "text",
    "verification_reviewed_by" "uuid",
    "verification_reviewed_at" timestamp with time zone,
    "department" "text",
    "phone" "text",
    "github_url" "text",
    "skills" "jsonb" DEFAULT '[]'::"jsonb",
    "account_type" "text",
    "student_id" "text",
    "is_employer" boolean DEFAULT false,
    "company_name" "text",
    "company_website" "text",
    "industry" "text",
    "phone_number" "text",
    "is_admin" boolean DEFAULT false,
    "role" "text" DEFAULT 'alumni'::"text",
    "job_title" "text",
    "years_experience" integer,
    "current_location" "text",
    "degree_program" "text",
    "current_job_title" "text",
    "major_specialization" "text",
    "biography" "text",
    "privacy_level" "text" DEFAULT 'public'::"text",
    "is_online" boolean DEFAULT false,
    "last_seen" timestamp with time zone,
    "username" "text",
    "about" "text",
    "headline" "text",
    "company" "text",
    "experience" "text",
    "specialization" "text",
    "achievements" "jsonb" DEFAULT '[]'::"jsonb",
    "interests" "jsonb" DEFAULT '[]'::"jsonb",
    "languages" "text"[] DEFAULT '{}'::"text"[],
    "social_links" "jsonb" DEFAULT '{}'::"jsonb",
    "verified" boolean DEFAULT false NOT NULL,
    "batch_year" integer,
    "resume_url" "text",
    "wants_job_alerts" boolean DEFAULT false,
    "website" "text",
    "is_available_for_mentorship" boolean DEFAULT false,
    "mentorship_topics" "text"[],
    "date_of_birth" "date",
    "company_location" "text",
    "primary_role" "text",
    "batch" "text",
    "is_profile_complete" boolean GENERATED ALWAYS AS ((("email" IS NOT NULL) AND ("first_name" IS NOT NULL) AND ("last_name" IS NOT NULL) AND ("graduation_year" IS NOT NULL) AND ("degree_program" IS NOT NULL) AND ("current_job_title" IS NOT NULL) AND ("company_name" IS NOT NULL) AND ("avatar_url" IS NOT NULL))) STORED,
    "show_in_directory" boolean DEFAULT true,
    "privacy_settings" "jsonb" DEFAULT '{}'::"jsonb",
    "rejection_comment" "text",
    "rejected_by" "uuid",
    "rejection_date" timestamp with time zone,
    "admin_notes" "text",
    "clarification_comment" "text",
    "rejection_reason" "text",
    "is_deleted" boolean DEFAULT false NOT NULL,
    "deleted_at" timestamp with time zone,
    "deleted_by" "uuid",
    "is_approved" boolean DEFAULT false NOT NULL,
    "verified_at" timestamp with time zone,
    "degree_code" "text",
    "education" "jsonb" DEFAULT '[]'::"jsonb",
    "work_experience" "jsonb" DEFAULT '[]'::"jsonb",
    "positions" "jsonb" DEFAULT '[]'::"jsonb",
    "profession" "text",
    "location_city" "text",
    "location_country" "text",
    "company_size" "text",
    "approval_status" "public"."profile_approval_status" DEFAULT 'pending'::"public"."profile_approval_status" NOT NULL,
    "is_hidden" boolean DEFAULT false NOT NULL,
    CONSTRAINT "chk_email_lower" CHECK (("email" = "lower"("email"))),
    CONSTRAINT "chk_email_lower_no_co" CHECK ((("email" = "lower"("email")) AND ("email" !~* '\.co$'::"text"))),
    CONSTRAINT "chk_email_not_co" CHECK (("email" !~* '\.co$'::"text")),
    CONSTRAINT "chk_first_name_fmt" CHECK ((("first_name" IS NULL) OR (("length"("btrim"("first_name")) >= 1) AND ("length"("btrim"("first_name")) <= 100)))),
    CONSTRAINT "chk_last_name_fmt" CHECK ((("last_name" IS NULL) OR (("length"("btrim"("last_name")) >= 1) AND ("length"("btrim"("last_name")) <= 100)))),
    CONSTRAINT "chk_linkedin_url" CHECK ((("linkedin_url" IS NULL) OR ("linkedin_url" ~* '^(https?://)?(www\.)?linkedin\.com/.*$'::"text"))),
    CONSTRAINT "chk_phone_e164" CHECK (("phone" ~ '^\+?[0-9]{7,15}$'::"text")),
    CONSTRAINT "ck_profiles_achievements_array" CHECK ((("achievements" IS NULL) OR ("jsonb_typeof"("achievements") = 'array'::"text"))),
    CONSTRAINT "ck_profiles_degree_program_allowed" CHECK ((("degree_program" IS NULL) OR ("degree_program" = ANY (ARRAY['HND Marine'::"text", 'HND Nautical Science'::"text", 'B.E. Petroleum Engineering'::"text", 'B.E. Mining Engineering'::"text", 'B.Sc. Nautical Science'::"text", 'B.E. Marine Engineering'::"text", 'B.E. Marine Technology'::"text", 'B.E. Naval Architecture and Offshore Engineering'::"text", 'B.E. Mechanical Engineering'::"text", 'B.E. Electrical and Electronics Engineering – Marine'::"text", 'B.Com'::"text", 'B.B.A. Shipping & Logistics'::"text", 'Electro Technical Officers (ETO)'::"text", 'Graduate Marine Engineering (GME)'::"text", 'GP Rating'::"text", 'M.B.A. Shipping & Logistics Management'::"text", 'M.E. Naval Architecture and Offshore Engineering'::"text", 'M.E. Petroleum Engineering'::"text", 'M.E. Power Systems'::"text", 'M.E. Marine Engineering'::"text", 'HND Marine Engineering'::"text", 'MBA – Shipping and Logistics Management'::"text", 'B.E. Harbour Engineer'::"text"])))),
    CONSTRAINT "ck_profiles_interests_array" CHECK ((("interests" IS NULL) OR ("jsonb_typeof"("interests") = 'array'::"text"))),
    CONSTRAINT "ck_profiles_is_approved_consistent" CHECK (("is_approved" = ("approval_status" = 'approved'::"public"."profile_approval_status"))),
    CONSTRAINT "ck_profiles_linkedin_url_pattern" CHECK ((("linkedin_url" IS NULL) OR ("linkedin_url" ~* '^https://(www\\.)?linkedin\\.com/(in|pub|company|school)/.+'::"text"))),
    CONSTRAINT "ck_profiles_skills_array" CHECK ((("skills" IS NULL) OR ("jsonb_typeof"("skills") = 'array'::"text"))),
    CONSTRAINT "ck_profiles_social_links_object" CHECK ((("social_links" IS NULL) OR ("jsonb_typeof"("social_links") = 'object'::"text"))),
    CONSTRAINT "profiles_alumni_verification_status_check" CHECK (("alumni_verification_status" = ANY (ARRAY['pending'::"text", 'approved'::"text", 'rejected'::"text"]))),
    CONSTRAINT "profiles_mentee_status_check" CHECK (("mentee_status" = ANY (ARRAY['pending'::"text", 'approved'::"text", 'rejected'::"text"]))),
    CONSTRAINT "profiles_mentor_status_check" CHECK (("mentor_status" = ANY (ARRAY['pending'::"text", 'approved'::"text", 'rejected'::"text"])))
);


ALTER TABLE "public"."profiles" OWNER TO "postgres";


COMMENT ON COLUMN "public"."profiles"."mentor_status" IS 'Status of mentor role verification';



COMMENT ON COLUMN "public"."profiles"."mentee_status" IS 'Status of mentee role verification';



COMMENT ON COLUMN "public"."profiles"."alumni_verification_status" IS 'Status of alumni verification';



COMMENT ON COLUMN "public"."profiles"."verification_document_url" IS 'URL to verification document uploaded by user';



COMMENT ON COLUMN "public"."profiles"."verification_notes" IS 'Notes from admin regarding verification';



COMMENT ON COLUMN "public"."profiles"."verification_reviewed_by" IS 'Admin who reviewed the verification';



COMMENT ON COLUMN "public"."profiles"."verification_reviewed_at" IS 'When the verification was reviewed';



CREATE OR REPLACE VIEW "public"."admin_user_logins" AS
 SELECT "p"."id",
    "p"."first_name",
    "p"."last_name",
    "u"."last_sign_in_at"
   FROM ("auth"."users" "u"
     JOIN "public"."profiles" "p" ON (("p"."id" = "u"."id")));


ALTER TABLE "public"."admin_user_logins" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_list_user_logins"() RETURNS SETOF "public"."admin_user_logins"
    LANGUAGE "sql" SECURITY DEFINER
    AS $$ select * from admin_user_logins $$;


ALTER FUNCTION "public"."admin_list_user_logins"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_list_users_with_last_login"("p_search" "text" DEFAULT NULL::"text", "p_limit" integer DEFAULT 50, "p_offset" integer DEFAULT 0) RETURNS TABLE("id" "uuid", "email" "text", "full_name" "text", "role" "text", "last_sign_in_at" timestamp with time zone, "created_at" timestamp with time zone)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'auth'
    AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = auth.uid()
      AND (p.is_admin = true OR p.role IN ('admin','super_admin'))
  ) THEN
    RAISE EXCEPTION 'not authorized' USING ERRCODE='42501';
  END IF;

  RETURN QUERY
  WITH base AS (
    SELECT
      p.id,
      p.email,
      p.full_name,
      COALESCE(p.role, CASE WHEN p.is_admin THEN 'admin' ELSE 'alumni' END) AS role,
      u.last_sign_in_at,
      u.created_at
    FROM public.profiles p
    JOIN auth.users u ON u.id = p.id
    WHERE
      p_search IS NULL
      OR p.email ILIKE '%' || p_search || '%'
      OR p.full_name ILIKE '%' || p_search || '%'
  )
  SELECT *
  FROM base
  ORDER BY COALESCE(last_sign_in_at, created_at) DESC
  LIMIT p_limit OFFSET p_offset;
END;
$$;


ALTER FUNCTION "public"."admin_list_users_with_last_login"("p_search" "text", "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_purge_user_data"("target" "uuid") RETURNS "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  actor uuid := auth.uid();
begin
  if not is_admin() then
    return json_build_object('error','Forbidden','status',403);
  end if;

  -- Networking & Mentorship / Messaging
  delete from public.conversation_participants where user_id = target;
  delete from public.messages                     where sender_id = target or recipient_id = target;

  -- Networking Groups
  delete from public.group_members                where user_id = target;

  -- Event Management
  delete from public.event_attendees              where user_id = target;
  delete from public.event_feedback               where user_id = target;

  -- Job Portal
  delete from public.job_applications             where applicant_id = target;
  delete from public.resumes                      where user_id = target;
  delete from public.user_resumes                 where user_id = target;

  -- Notifications / Connections (if present)
  delete from public.notifications                where profile_id = target;
  delete from public.connections                  where requester_id = target or recipient_id = target;

  -- Finally (your app table)
  delete from public.profiles                     where id = target;

  insert into public.admin_actions (admin_id, action_type, target_type, target_id, description, metadata)
  values (actor, 'purge_user_data', 'user', target, 'Hard-purged user-related rows in app DB', json_build_object('phase','purge'));

  return json_build_object('ok', true);
end;
$$;


ALTER FUNCTION "public"."admin_purge_user_data"("target" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_request_user_delete"("target" "uuid") RETURNS "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  is_admin boolean;
begin
  -- allow only admins / super_admins (your schema uses these roles)
  select (role in ('admin','super_admin')) into is_admin
  from public.profiles
  where id = auth.uid();

  if not coalesce(is_admin, false) then
    return json_build_object('error','Forbidden','status',403);
  end if;

  -- Log the action (admins are allowed to insert/select in admin_actions)
  insert into public.admin_actions (admin_id, action_type, target_type, target_id, description, metadata)
  values (auth.uid(), 'delete_user', 'user', target, 'Requested hard delete of user via Admin API', json_build_object('requested_at', now()));

  -- Your frontend/server will now call /api/admin/delete-user to actually delete
  return json_build_object('ok', true);
end;
$$;


ALTER FUNCTION "public"."admin_request_user_delete"("target" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_revoke_super_admin"("target_user_id" "uuid", "new_role" "text" DEFAULT 'admin'::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  caller_id uuid := auth.uid();
  caller_is_super bool;
  target_role text;
BEGIN
  SELECT (p.role = 'super_admin') INTO caller_is_super
  FROM public.profiles p
  WHERE p.id = caller_id;

  IF NOT caller_is_super THEN
    RAISE EXCEPTION 'Only super_admin can revoke super_admin' USING ERRCODE='42501';
  END IF;

  IF target_user_id = caller_id THEN
    RAISE EXCEPTION 'You cannot revoke your own super_admin' USING ERRCODE='42501';
  END IF;

  SELECT role INTO target_role FROM public.profiles WHERE id = target_user_id;

  IF target_role IS NULL THEN
    RAISE EXCEPTION 'Target user not found';
  END IF;

  IF target_role <> 'super_admin' THEN
    RETURN jsonb_build_object('success', false, 'message', 'Target user is not super_admin');
  END IF;

  UPDATE public.profiles
  SET role = new_role, is_admin = (new_role IN ('admin','super_admin'))
  WHERE id = target_user_id;

  INSERT INTO public.admin_actions (admin_id, action_type, target_type, target_id, description)
  VALUES (caller_id, 'revoke_super_admin', 'user', target_user_id, 'Role changed to ' || new_role);

  -- Note for UI: refresh the target user's session via client to pick up the new role
  RETURN jsonb_build_object('success', true, 'new_role', new_role);
END;
$$;


ALTER FUNCTION "public"."admin_revoke_super_admin"("target_user_id" "uuid", "new_role" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_set_approval"("tname" "text", "row_id" "uuid", "new_status" "public"."approval_status", "note" "text" DEFAULT NULL::"text") RETURNS "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
declare
  actor uuid := auth.uid();
  sql text;
begin
  if not is_admin() then
    return json_build_object('error','Forbidden','status',403);
  end if;

  -- Whitelist only these three tables
  if tname not in ('events','jobs','groups') then
    return json_build_object('error','Unsupported table');
  end if;

  sql := format('update public.%I set approval_status = $1, reviewed_by = $2, reviewed_at = now() where id = $3', tname);
  execute sql using new_status, actor, row_id;

  insert into public.admin_actions (admin_id, action_type, target_type, target_id, description, metadata)
  values (actor, 'set_approval', tname, row_id,
          coalesce(note, concat('Set to ', new_status::text)),
          json_build_object('status', new_status));

  return json_build_object('ok', true);
end;
$_$;


ALTER FUNCTION "public"."admin_set_approval"("tname" "text", "row_id" "uuid", "new_status" "public"."approval_status", "note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_set_profile_approval"("target" "uuid", "new_status" "public"."profile_approval_status", "reason" "text" DEFAULT NULL::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Authorization: only admin/super_admin can use
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND (is_admin = true OR role IN ('admin','super_admin'))
  ) THEN
    RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
  END IF;

  -- Update status
  UPDATE public.profiles
  SET approval_status = new_status,
      -- Keep legacy column (if exists) in sync
      alumni_verification_status = CASE new_status
        WHEN 'approved' THEN 'approved'
        WHEN 'rejected' THEN 'rejected'
        ELSE 'pending'
      END,
      updated_at = now()
  WHERE id = target;

  -- Audit
  INSERT INTO public.admin_actions (id, action_type, admin_id, target_id, target_type, description, metadata, created_at)
  VALUES (uuid_generate_v4(), 'profile_approval', auth.uid(), target, 'profile',
          CONCAT('Set approval to ', new_status::text),
          jsonb_build_object('reason', reason),
          now());
END;
$$;


ALTER FUNCTION "public"."admin_set_profile_approval"("target" "uuid", "new_status" "public"."profile_approval_status", "reason" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_set_role"("p_user" "uuid", "p_role" "text") RETURNS "void"
    LANGUAGE "sql" SECURITY DEFINER
    AS $$
  insert into public.user_roles(profile_id, role_id)
  select p_user, r.id from public.roles r where r.name = p_role
  on conflict (profile_id, role_id) do nothing;
$$;


ALTER FUNCTION "public"."admin_set_role"("p_user" "uuid", "p_role" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_set_user_role"("target" "uuid", "new_role" "text", "make_admin" boolean DEFAULT false) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  old_role text;
BEGIN
  -- Authorization: only admin/super_admin can use
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND (is_admin = true OR role IN ('admin','super_admin'))
  ) THEN
    RAISE EXCEPTION 'not authorized' USING ERRCODE = '42501';
  END IF;

  -- Lock target row, get previous role
  SELECT role INTO old_role
  FROM public.profiles
  WHERE id = target
  FOR UPDATE;

  -- Update role and is_admin flag atomically
  UPDATE public.profiles
  SET role = new_role,
      is_admin = make_admin,
      updated_at = now()
  WHERE id = target;

  -- Audit
  INSERT INTO public.admin_actions (id, action_type, admin_id, target_id, target_type, description, metadata, created_at)
  VALUES (
    uuid_generate_v4(),
    'set_role',
    auth.uid(),
    target,
    'profile',
    CONCAT('Set role to ', COALESCE(new_role, 'NULL')),
    jsonb_build_object('old_role', old_role, 'new_role', new_role, 'is_admin', make_admin),
    now()
  );
END;
$$;


ALTER FUNCTION "public"."admin_set_user_role"("target" "uuid", "new_role" "text", "make_admin" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_soft_delete_user"("target" "uuid") RETURNS "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  actor uuid := auth.uid();
begin
  if not is_admin() then
    return json_build_object('error','Forbidden','status',403);
  end if;

  -- Mark profile deleted
  update public.profiles
     set is_deleted = true,
         deleted_at = now(),
         deleted_by = actor
   where id = target;

  -- (Optional) Example anonymization in your own table (comment out if not desired)
  -- update public.profiles
  --    set phone = null,
  --        full_name = concat('Deleted User ', substring(id::text,1,8))
  --  where id = target;

  insert into public.admin_actions (admin_id, action_type, target_type, target_id, description, metadata)
  values (actor, 'delete_user', 'user', target, 'Soft-deleted user in app DB', json_build_object('phase','soft'));

  return json_build_object('ok', true);
end;
$$;


ALTER FUNCTION "public"."admin_soft_delete_user"("target" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_soft_delete_user"("target_user_id" "uuid", "reason" "text" DEFAULT NULL::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  caller_id uuid := auth.uid();
  caller_is_admin bool;
  target_role text;
BEGIN
  SELECT (p.is_admin = true OR p.role IN ('admin','super_admin')) INTO caller_is_admin
  FROM public.profiles p
  WHERE p.id = caller_id;

  IF NOT caller_is_admin THEN
    RAISE EXCEPTION 'not authorized' USING ERRCODE='42501';
  END IF;

  SELECT role INTO target_role FROM public.profiles WHERE id = target_user_id;
  IF target_role IS NULL THEN
    RAISE EXCEPTION 'User not found';
  END IF;

  -- Prevent non-super admin from soft-deleting admins
  IF target_role IN ('admin','super_admin') AND NOT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = caller_id AND p.role = 'super_admin'
  ) THEN
    RAISE EXCEPTION 'Only super_admin can delete admin/super_admin' USING ERRCODE='42501';
  END IF;

  -- Application data purge hook (if you have it)
  -- BEGIN
  --   PERFORM purge_user_data(target_user_id);
  -- EXCEPTION WHEN OTHERS THEN
  --   -- Ignore purge errors in soft delete
  -- END;

  UPDATE public.profiles
  SET
    email = 'deleted_' || id || '@deleted.user',
    full_name = 'Deleted User',
    is_deleted = true,
    deleted_at = now(),
    role = 'alumni',
    is_admin = false
  WHERE id = target_user_id;

  INSERT INTO public.admin_actions (admin_id, action_type, target_type, target_id, description)
  VALUES (caller_id, 'soft_delete_user', 'user', target_user_id, COALESCE(reason, 'Soft delete'));

  RETURN jsonb_build_object('success', true);
END;
$$;


ALTER FUNCTION "public"."admin_soft_delete_user"("target_user_id" "uuid", "reason" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."assign_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  role_id_val UUID;
BEGIN
  -- Get role ID with fully qualified column names
  SELECT roles.id INTO role_id_val FROM roles WHERE roles.name = role_name;
  
  -- Check if role exists
  IF role_id_val IS NULL THEN
    RETURN FALSE;
  END IF;
  
  -- Assign role to user with fully qualified column names
  INSERT INTO user_roles (profile_id, role_id)
  VALUES (profile_uuid, role_id_val)
  ON CONFLICT (profile_id, role_id) DO NOTHING;
  
  RETURN TRUE;
END;
$$;


ALTER FUNCTION "public"."assign_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."assign_user_role"("profile_uuid" "uuid", "role_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  role_id UUID;
BEGIN
  -- Get role ID
  SELECT id INTO role_id FROM roles WHERE name = role_name;
  
  -- Check if role exists
  IF role_id IS NULL THEN
    RETURN FALSE;
  END IF;
  
  -- Assign role to user
  INSERT INTO user_roles (profile_id, role_id)
  VALUES (profile_uuid, role_id)
  ON CONFLICT (profile_id, role_id) DO NOTHING;
  
  RETURN TRUE;
END;
$$;


ALTER FUNCTION "public"."assign_user_role"("profile_uuid" "uuid", "role_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."attach_user_to_batch_group"("p_user_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_year int;
  v_dept text;
  v_group_name text;
  v_group_id uuid;
BEGIN
  SELECT graduation_year, department INTO v_year, v_dept
  FROM public.profiles
  WHERE id = p_user_id;

  IF v_year IS NULL OR v_dept IS NULL THEN
    RETURN;
  END IF;

  v_group_name := 'Batch ' || v_year::text || ' - ' || v_dept;

  -- Single upsert using normalized unique constraint (handles races & near-duplicates)
  INSERT INTO public.groups (name, description, is_private, created_by)
  VALUES (v_group_name, 'Auto-created batch group', false, p_user_id)
  ON CONFLICT ON CONSTRAINT uq_groups_name_norm
  DO UPDATE SET name = EXCLUDED.name
  RETURNING id INTO v_group_id;

  INSERT INTO public.group_members (group_id, user_id, role)
  VALUES (v_group_id, p_user_id, 'member')
  ON CONFLICT (group_id, user_id) DO NOTHING;
END
$$;


ALTER FUNCTION "public"."attach_user_to_batch_group"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."auto_confirm_email"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  -- Set the email_confirmed_at timestamp to now for new users
  UPDATE auth.users 
  SET email_confirmed_at = NOW() 
  WHERE id = NEW.id AND email_confirmed_at IS NULL;
  
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."auto_confirm_email"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."auto_conversation_on_match"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  PERFORM public.create_conversation_for_mentorship(NEW.mentor_id, NEW.mentee_id);
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."auto_conversation_on_match"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_bookmark_limit"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF (
    SELECT COUNT(*) FROM job_bookmarks WHERE user_id = NEW.user_id
  ) >= 3 THEN
    RAISE EXCEPTION 'You can only bookmark up to 3 jobs';
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."check_bookmark_limit"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_event_completed"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  event_end_at timestamptz;
BEGIN
  -- Build an end timestamp from date + (end_time or time)
  SELECT
    CASE
      WHEN e.date IS NOT NULL AND (e.end_time IS NOT NULL OR e.time IS NOT NULL)
        THEN (e.date::timestamp + COALESCE(e.end_time, e.time)) AT TIME ZONE current_setting('TimeZone')
      WHEN e.date IS NOT NULL
        THEN (e.date::timestamp + time '23:59:59') AT TIME ZONE current_setting('TimeZone')  -- last-resort fallback
      ELSE NULL
    END
  INTO event_end_at
  FROM public.events e
  WHERE e.id = NEW.event_id;

  IF event_end_at IS NULL THEN
    RAISE EXCEPTION 'Cannot submit feedback: event % has no end date/time set', NEW.event_id;
  END IF;

  IF event_end_at > now() THEN
    RAISE EXCEPTION 'Cannot submit feedback: event % has not completed yet (ends at %)', NEW.event_id, event_end_at;
  END IF;

  RETURN NEW;
END$$;


ALTER FUNCTION "public"."check_event_completed"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_user_permission_bypass_rls"("profile_uuid" "uuid", "permission_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  has_permission BOOLEAN;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM permissions p
    JOIN role_permissions rp ON p.id = rp.permission_id
    JOIN user_roles ur ON rp.role_id = ur.role_id
    WHERE ur.profile_id = profile_uuid AND p.name = permission_name
  ) INTO has_permission;
  
  RETURN has_permission;
END;
$$;


ALTER FUNCTION "public"."check_user_permission_bypass_rls"("profile_uuid" "uuid", "permission_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_user_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  has_role BOOLEAN;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM user_roles ur
    JOIN roles r ON ur.role_id = r.id
    WHERE ur.profile_id = profile_uuid AND r.name = role_name
  ) INTO has_role;
  
  RETURN has_role;
END;
$$;


ALTER FUNCTION "public"."check_user_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_conversation_for_mentorship"("mentor_uuid" "uuid", "mentee_uuid" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
  conv_id UUID;
BEGIN
  -- Check if a conversation already exists between them
  SELECT c.id INTO conv_id
  FROM public.conversations c
  JOIN public.conversation_participants cp1 ON cp1.conversation_id = c.id AND cp1.user_id = mentor_uuid
  JOIN public.conversation_participants cp2 ON cp2.conversation_id = c.id AND cp2.user_id = mentee_uuid
  LIMIT 1;

  -- If no conversation exists, create one
  IF conv_id IS NULL THEN
    INSERT INTO public.conversations DEFAULT VALUES RETURNING id INTO conv_id;

    INSERT INTO public.conversation_participants (conversation_id, user_id)
    VALUES
      (conv_id, mentor_uuid),
      (conv_id, mentee_uuid);
  END IF;

  RETURN conv_id;
END;
$$;


ALTER FUNCTION "public"."create_conversation_for_mentorship"("mentor_uuid" "uuid", "mentee_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_event_with_agenda"("event_data" "jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    new_event_id UUID;
    result JSONB;
BEGIN
    -- First insert the event without the agenda
    INSERT INTO public.events (
        title,
        description,
        start_date,
        end_date,
        location,
        is_virtual,
        creator_id,
        organizer_id,
        is_published,
        created_at,
        updated_at
    ) VALUES (
        event_data->>'title',
        event_data->>'description',
        (event_data->>'start_date')::TIMESTAMP WITH TIME ZONE,
        (event_data->>'end_date')::TIMESTAMP WITH TIME ZONE,
        event_data->>'location',
        (event_data->>'is_virtual')::BOOLEAN,
        (event_data->>'creator_id')::UUID,
        (event_data->>'creator_id')::UUID,
        (event_data->>'is_published')::BOOLEAN,
        COALESCE((event_data->>'created_at')::TIMESTAMP WITH TIME ZONE, now()),
        now()
    ) RETURNING id INTO new_event_id;
    
    -- Then update the agenda separately
    IF event_data->>'agenda' IS NOT NULL THEN
        UPDATE public.events 
        SET agenda = event_data->>'agenda'
        WHERE id = new_event_id;
    END IF;
    
    -- Add other optional fields if present
    IF event_data->>'cost' IS NOT NULL THEN
        UPDATE public.events 
        SET cost = event_data->>'cost'
        WHERE id = new_event_id;
    END IF;
    
    IF event_data->>'sponsors' IS NOT NULL THEN
        UPDATE public.events 
        SET sponsors = event_data->>'sponsors'
        WHERE id = new_event_id;
    END IF;
    
    IF event_data->>'virtual_meeting_link' IS NOT NULL THEN
        UPDATE public.events 
        SET virtual_meeting_link = event_data->>'virtual_meeting_link'
        WHERE id = new_event_id;
    END IF;
    
    IF event_data->>'event_type' IS NOT NULL THEN
        UPDATE public.events 
        SET event_type = event_data->>'event_type'
        WHERE id = new_event_id;
    END IF;
    
    IF event_data->>'max_attendees' IS NOT NULL THEN
        UPDATE public.events 
        SET max_attendees = (event_data->>'max_attendees')::INTEGER
        WHERE id = new_event_id;
    END IF;
    
    IF event_data->>'registration_deadline' IS NOT NULL THEN
        UPDATE public.events 
        SET registration_deadline = (event_data->>'registration_deadline')::TIMESTAMP WITH TIME ZONE
        WHERE id = new_event_id;
    END IF;
    
    IF event_data->>'image_url' IS NOT NULL THEN
        UPDATE public.events 
        SET featured_image_url = event_data->>'image_url'
        WHERE id = new_event_id;
    END IF;
    
    -- Return the created event
    SELECT row_to_json(e)::jsonb INTO result
    FROM public.events e
    WHERE id = new_event_id;
    
    RETURN result;
END;
$$;


ALTER FUNCTION "public"."create_event_with_agenda"("event_data" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_group_and_add_admin"("group_name" "text", "group_description" "text", "group_is_private" boolean, "group_tags" "text"[]) RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    new_group_id UUID;
    creator_id UUID := auth.uid();
BEGIN
    -- Insert the new group and get its ID
    INSERT INTO public.groups (name, description, is_private, tags, created_by)
    VALUES (group_name, group_description, group_is_private, group_tags, creator_id)
    RETURNING id INTO new_group_id;

    -- Add the creator as the first member with an 'admin' role
    INSERT INTO public.group_members (group_id, user_id, role)
    VALUES (new_group_id, creator_id, 'admin');

    RETURN new_group_id;
END;
$$;


ALTER FUNCTION "public"."create_group_and_add_admin"("group_name" "text", "group_description" "text", "group_is_private" boolean, "group_tags" "text"[]) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_new_event"("event_data" "jsonb") RETURNS "jsonb"
    LANGUAGE "sql"
    AS $$
    SELECT public.create_event_with_agenda(event_data);
$$;


ALTER FUNCTION "public"."create_new_event"("event_data" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_notification"("user_id" "uuid", "notification_title" "text", "notification_message" "text", "notification_link" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  RETURN public.create_notification(user_id, notification_title, notification_message, notification_link, 'system');
END
$$;


ALTER FUNCTION "public"."create_notification"("user_id" "uuid", "notification_title" "text", "notification_message" "text", "notification_link" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_notification"("target_profile_id" "uuid", "notif_title" "text", "notif_message" "text", "notif_link" "text", "notif_type" "text" DEFAULT 'system'::"text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_type text := replace(btrim(lower(coalesce(notif_type,'system'))),'-','_');
  v_id   uuid;
BEGIN
  IF v_type NOT IN (
    'system','message',
    'event','event_created','event_published','event_updated',
    'job','job_posted','job_approved','job_applied',
    'application','application_status',
    'mentorship','group','connection',
    'resume','alert'
  ) THEN
    v_type := 'system';
  END IF;

  INSERT INTO public.notifications (profile_id, title, message, link, type)
  VALUES (coalesce(target_profile_id, auth.uid()), notif_title, notif_message, notif_link, v_type)
  RETURNING id INTO v_id;

  RETURN v_id;
END
$$;


ALTER FUNCTION "public"."create_notification"("target_profile_id" "uuid", "notif_title" "text", "notif_message" "text", "notif_link" "text", "notif_type" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_notification"("recipient_id" "uuid", "sender_id" "uuid", "event_id" "uuid", "type" "text", "message" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE nid uuid;
BEGIN
  INSERT INTO public.notifications (recipient_id, sender_id, event_id, type, message)
  VALUES (recipient_id, sender_id, event_id, type, message)
  RETURNING id INTO nid;
  RETURN nid;
END$$;


ALTER FUNCTION "public"."create_notification"("recipient_id" "uuid", "sender_id" "uuid", "event_id" "uuid", "type" "text", "message" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_or_update_mentor_profile"("p_expertise" "text"[] DEFAULT '{}'::"text"[], "p_mentoring_statement" "text" DEFAULT NULL::"text", "p_max_mentees" integer DEFAULT NULL::integer, "p_availability" "text" DEFAULT NULL::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_existing boolean;
  v_row public.mentors;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'Authentication required' USING ERRCODE='28000';
  END IF;

  SELECT TRUE INTO v_existing FROM public.mentors WHERE user_id = v_uid;

  IF v_existing THEN
    UPDATE public.mentors
       SET expertise          = COALESCE(p_expertise, expertise),
           mentoring_statement= COALESCE(p_mentoring_statement, mentoring_statement),
           max_mentees        = COALESCE(p_max_mentees, max_mentees),
           availability       = COALESCE(p_availability, availability)
     WHERE user_id = v_uid
     RETURNING * INTO v_row;
  ELSE
    INSERT INTO public.mentors (user_id, expertise, mentoring_statement, max_mentees, availability, status)
    VALUES (v_uid, p_expertise, p_mentoring_statement, p_max_mentees, p_availability, 'pending')
    RETURNING * INTO v_row;
  END IF;

  RETURN to_jsonb(v_row);
END
$$;


ALTER FUNCTION "public"."create_or_update_mentor_profile"("p_expertise" "text"[], "p_mentoring_statement" "text", "p_max_mentees" integer, "p_availability" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."drop_all_policies"("target_table" "text") RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
  policy_record record;
BEGIN
  FOR policy_record IN 
    SELECT policyname 
    FROM pg_policies 
    WHERE schemaname = 'public' AND tablename = target_table
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', policy_record.policyname, target_table);
  END LOOP;
END;
$$;


ALTER FUNCTION "public"."drop_all_policies"("target_table" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."enqueue_user_hard_delete"("target_user_id" "uuid", "reason" "text" DEFAULT NULL::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  caller_id uuid := auth.uid();
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = caller_id
      AND (p.is_admin = true OR p.role IN ('admin','super_admin'))
  ) THEN
    RAISE EXCEPTION 'not authorized' USING ERRCODE='42501';
  END IF;

  INSERT INTO public.deletion_queue (user_id, reason)
  VALUES (target_user_id, reason);

  INSERT INTO public.admin_actions (admin_id, action_type, target_type, target_id, description)
  VALUES (caller_id, 'enqueue_hard_delete', 'user', target_user_id, COALESCE(reason, 'Enqueue hard delete'));

  RETURN jsonb_build_object('success', true);
END;
$$;


ALTER FUNCTION "public"."enqueue_user_hard_delete"("target_user_id" "uuid", "reason" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."event_changes_broadcast"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  ev_id uuid := COALESCE(NEW.id, OLD.id);
  gid   uuid;
  topic text;
BEGIN
  FOR gid IN
    SELECT eg.group_id FROM public.event_groups eg WHERE eg.event_id = ev_id
  LOOP
    topic := 'group:' || gid::text;
    PERFORM pg_notify(
      'event_updates',
      json_build_object('topic', topic, 'op', TG_OP, 'event_id', ev_id)::text
    );
  END LOOP;

  RETURN NULL;
END;
$$;


ALTER FUNCTION "public"."event_changes_broadcast"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."events_set_owner"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.created_by := COALESCE(NEW.created_by, auth.uid());
  ELSIF TG_OP = 'UPDATE' THEN
    NEW.created_by := OLD.created_by; -- lock ownership
  END IF;
  RETURN NEW;
END$$;


ALTER FUNCTION "public"."events_set_owner"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."find_or_create_conversation"("other_user_id" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_conversation_id UUID;
  v_current_user_id UUID := auth.uid();
BEGIN
  IF v_current_user_id = other_user_id THEN
    RETURN NULL;
  END IF;

  SELECT cp1.conversation_id INTO v_conversation_id
  FROM conversation_participants AS cp1
  JOIN conversation_participants AS cp2 ON cp1.conversation_id = cp2.conversation_id
  WHERE cp1.user_id = v_current_user_id AND cp2.user_id = other_user_id
  AND (
    SELECT COUNT(*)
    FROM conversation_participants
    WHERE conversation_id = cp1.conversation_id
  ) = 2
  LIMIT 1;

  IF v_conversation_id IS NOT NULL THEN
    RETURN v_conversation_id;
  END IF;

  INSERT INTO conversations DEFAULT VALUES
  RETURNING id INTO v_conversation_id;

  INSERT INTO conversation_participants (conversation_id, user_id)
  VALUES (v_conversation_id, v_current_user_id), (v_conversation_id, other_user_id);

  RETURN v_conversation_id;
END;
$$;


ALTER FUNCTION "public"."find_or_create_conversation"("other_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_add_group_creator"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  insert into public.group_members (group_id, user_id, role)
  values (new.id, auth.uid(), 'admin')
  on conflict do nothing;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_add_group_creator"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_company_jobs_with_bookmarks"("p_company_id" "uuid", "p_search_query" "text" DEFAULT NULL::"text", "p_sort_by" "text" DEFAULT 'created_at'::"text", "p_sort_order" "text" DEFAULT 'desc'::"text", "p_limit" integer DEFAULT 10, "p_offset" integer DEFAULT 0) RETURNS SETOF "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $_$
DECLARE
  v_user_id UUID;
  v_query TEXT;
  v_is_bookmarked_query TEXT;
BEGIN
  -- Get current authenticated user ID
  v_user_id := auth.uid();

  -- Create the query to fetch jobs from specified company
  v_query := '
    SELECT 
      j.*,
      c.name as company_name,
      c.logo_url as company_logo_url,
      COALESCE(a.count, 0) as applicant_count,
      EXISTS(SELECT 1 FROM job_bookmarks jb WHERE jb.job_id = j.id AND jb.user_id = $1) as is_bookmarked,
      COUNT(*) OVER() as total_count
    FROM jobs j
    LEFT JOIN companies c ON j.company_id = c.id
    LEFT JOIN (
      SELECT job_id, COUNT(*) as count
      FROM job_applications
      GROUP BY job_id
    ) a ON a.job_id = j.id
    WHERE j.company_id = $2
  ';

  -- Add search query condition if provided
  IF p_search_query IS NOT NULL AND p_search_query <> '' THEN
    v_query := v_query || ' AND (
      j.title ILIKE ''%' || p_search_query || '%'' OR
      j.description ILIKE ''%' || p_search_query || '%'' OR
      j.location ILIKE ''%' || p_search_query || '%'' OR
      c.name ILIKE ''%' || p_search_query || '%''
    )';
  END IF;

  -- Add sorting
  v_query := v_query || ' ORDER BY ' || p_sort_by || ' ' || p_sort_order;

  -- Add pagination
  v_query := v_query || ' LIMIT ' || p_limit || ' OFFSET ' || p_offset;

  -- Execute the query and return results
  RETURN QUERY EXECUTE v_query USING v_user_id, p_company_id;
END;
$_$;


ALTER FUNCTION "public"."get_company_jobs_with_bookmarks"("p_company_id" "uuid", "p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_connection_status"("user_1_id" "uuid", "user_2_id" "uuid") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  connection_status text;
BEGIN
  SELECT status INTO connection_status
  FROM connections
  WHERE (requester_id = user_1_id AND recipient_id = user_2_id)
     OR (requester_id = user_2_id AND recipient_id = user_1_id)
  LIMIT 1;

  IF connection_status IS NULL THEN
    RETURN 'idle';
  ELSE
    RETURN connection_status;
  END IF;
END;
$$;


ALTER FUNCTION "public"."get_connection_status"("user_1_id" "uuid", "user_2_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_connections_count"("p_user_id" "uuid") RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  connection_count INTEGER;
BEGIN
  -- Count connections where the user is either the requester or recipient
  -- and the connection status is 'accepted'
  SELECT COUNT(*) INTO connection_count
  FROM public.connections
  WHERE (requester_id = p_user_id OR recipient_id = p_user_id)
  AND status = 'accepted';
  
  RETURN connection_count;
END;
$$;


ALTER FUNCTION "public"."get_connections_count"("p_user_id" "uuid") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."get_connections_count"("p_user_id" "uuid") IS 'Returns the count of accepted connections for a specific user';



CREATE OR REPLACE FUNCTION "public"."get_dashboard_stats"() RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'auth'
    AS $$
DECLARE
  result jsonb;
BEGIN
  -- admin/super_admin check
  IF NOT EXISTS (
    SELECT 1 FROM profiles 
    WHERE id = auth.uid() AND (role IN ('admin','super_admin') OR is_admin = true)
  ) THEN
    RAISE EXCEPTION 'Access denied: Only administrators can access dashboard statistics';
  END IF;

  SELECT jsonb_build_object(
    'totalUsers', (SELECT count(*) FROM auth.users),
    'activeJobs', (SELECT count(*) FROM jobs WHERE is_active = true AND is_approved = true),
    'pendingApplications', (SELECT count(*) FROM job_applications WHERE status = 'submitted'),
    'totalApplications', (SELECT count(*) FROM job_applications),
    'messagesToday', (SELECT count(*) FROM messages WHERE created_at >= CURRENT_DATE),
    'usersByRole', (
      SELECT jsonb_object_agg(role_counts.role, role_counts.count)
      FROM (
        SELECT role, count(*) AS count
        FROM profiles
        GROUP BY role
      ) AS role_counts
    ),
    'recentActivity', (
      SELECT jsonb_agg(activity_data)
      FROM (
        SELECT id, description, activity_type, created_at
        FROM activity_log
        ORDER BY created_at DESC
        LIMIT 10
      ) AS activity_data
    ),
    'lastUpdated', now()
  ) INTO result;

  RETURN result;
END;
$$;


ALTER FUNCTION "public"."get_dashboard_stats"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."get_dashboard_stats"() IS 'Returns statistics for the admin dashboard';



CREATE OR REPLACE FUNCTION "public"."get_jobs_with_bookmarks"("p_search_query" "text" DEFAULT ''::"text", "p_sort_by" "text" DEFAULT 'created_at'::"text", "p_sort_order" "text" DEFAULT 'desc'::"text", "p_limit" integer DEFAULT 12, "p_offset" integer DEFAULT 0) RETURNS SETOF "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
DECLARE
  v_user_id    uuid := auth.uid();
  v_is_admin   boolean := EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = v_user_id
      AND (p.is_admin = true OR p.role IN ('admin','super_admin'))
  );
  v_sort_by    text;
  v_sort_order text;
  v_where      text := '';
  v_sql        text;
BEGIN
  -- Whitelist sort fields/direction
  v_sort_by := CASE lower(p_sort_by)
    WHEN 'created_at'      THEN 'created_at'
    WHEN 'title'           THEN 'title'
    WHEN 'location'        THEN 'location'
    WHEN 'applicant_count' THEN 'applicant_count'
    ELSE 'created_at'
  END;

  v_sort_order := CASE lower(p_sort_order)
    WHEN 'asc' THEN 'ASC'
    ELSE 'DESC'
  END;

  IF p_search_query IS NOT NULL AND length(btrim(p_search_query)) > 0 THEN
    v_where := '
      WHERE ( title ILIKE ''%'' || $2 || ''%''
           OR description ILIKE ''%'' || $2 || ''%''
           OR location ILIKE ''%'' || $2 || ''%''
           OR company_name ILIKE ''%'' || $2 || ''%'' )';
  END IF;

  v_sql := format($f$
    WITH base AS (
      SELECT
        j.*,
        c.name     AS company_name,
        c.logo_url AS company_logo_url,
        COALESCE(a.count, 0) AS applicant_count,
        EXISTS (
          SELECT 1 FROM public.job_bookmarks jb
          WHERE jb.job_id = j.id AND jb.user_id = $1
        ) AS is_bookmarked
      FROM public.jobs j
      LEFT JOIN public.companies c ON c.id = j.company_id
      LEFT JOIN (
        SELECT job_id, COUNT(*) AS count
        FROM public.job_applications
        GROUP BY job_id
      ) a ON a.job_id = j.id
      WHERE %s
    ),
    filtered AS (
      SELECT * FROM base
      %s
    )
    SELECT (to_jsonb(f) || jsonb_build_object('total_count', COUNT(*) OVER ()))::json
    FROM filtered f
    ORDER BY %I %s
    LIMIT $3 OFFSET $4
  $f$,
    CASE WHEN v_is_admin THEN 'TRUE'
         ELSE '(j.is_approved = TRUE AND j.is_active = TRUE) OR j.posted_by = $1'
    END,
    v_where,
    v_sort_by, v_sort_order
  );

  RETURN QUERY EXECUTE v_sql USING v_user_id, p_search_query, p_limit, p_offset;
END;
$_$;


ALTER FUNCTION "public"."get_jobs_with_bookmarks"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_jobs_with_bookmarks_v2"("p_search_query" "text" DEFAULT ''::"text", "p_sort_by" "text" DEFAULT 'created_at'::"text", "p_sort_order" "text" DEFAULT 'desc'::"text", "p_limit" integer DEFAULT 12, "p_offset" integer DEFAULT 0) RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
DECLARE
  v_user_id    uuid := auth.uid();
  v_is_admin   boolean := EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = v_user_id
      AND (p.is_admin = true OR p.role IN ('admin','super_admin'))
  );

  sort_col   text := CASE lower(p_sort_by)
                       WHEN 'created_at' THEN 'created_at'
                       WHEN 'deadline'   THEN 'deadline'
                       WHEN 'title'      THEN 'title'
                       ELSE 'created_at'
                     END;
  sort_dir   text := CASE lower(p_sort_order)
                       WHEN 'asc' THEN 'ASC'
                       ELSE 'DESC'
                     END;

  where_search text := '';
  v_sql        text;
  out_json     jsonb;
BEGIN
  IF p_search_query IS NOT NULL AND length(btrim(p_search_query)) > 0 THEN
    where_search := '
      AND (
           j.title       ILIKE ''%'' || $2 || ''%''
        OR j.description ILIKE ''%'' || $2 || ''%''
        OR j.location    ILIKE ''%'' || $2 || ''%''
        OR c.name        ILIKE ''%'' || $2 || ''%''
      )';
  END IF;

  v_sql := format($f$
    WITH filtered AS (
      SELECT
        j.*,
        c.name     AS company_name,
        c.logo_url AS company_logo_url,
        COALESCE(a.count, 0) AS applicant_count,
        EXISTS (
          SELECT 1 FROM public.job_bookmarks jb
          WHERE jb.job_id = j.id AND jb.user_id = $1
        ) AS is_bookmarked
      FROM public.jobs j
      LEFT JOIN public.companies c ON c.id = j.company_id
      LEFT JOIN (
        SELECT job_id, COUNT(*) AS count
        FROM public.job_applications
        GROUP BY job_id
      ) a ON a.job_id = j.id
      WHERE %s %s
    ),
    paged AS (
      SELECT * FROM filtered
      ORDER BY %I %s
      LIMIT $3 OFFSET $4
    )
    SELECT jsonb_build_object(
      'items',       COALESCE(jsonb_agg(to_jsonb(p)), '[]'::jsonb),
      'total_count', (SELECT COUNT(*) FROM filtered)
    )
    FROM paged p;
  $f$,
    CASE WHEN v_is_admin
         THEN 'TRUE'
         ELSE '(j.is_approved = TRUE AND j.is_active = TRUE) OR j.posted_by = $1'
    END,
    where_search,
    sort_col, sort_dir
  );

  EXECUTE v_sql INTO out_json USING v_user_id, p_search_query, p_limit, p_offset;

  IF out_json IS NULL THEN
    out_json := jsonb_build_object('items', '[]'::jsonb, 'total_count', 0);
  END IF;

  RETURN out_json;
END
$_$;


ALTER FUNCTION "public"."get_jobs_with_bookmarks_v2"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_latest_message"("p_conversation_id" "uuid") RETURNS TABLE("message_id" "uuid", "content" "text", "sender_id" "uuid", "sender_name" "text", "created_at" timestamp with time zone, "message_type" character varying, "attachment_url" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN QUERY
  SELECT
    m.id AS message_id,
    m.content,
    m.sender_id,
    p.full_name AS sender_name,
    m.created_at,
    m.message_type,
    m.attachment_url
  FROM
    messages m
    JOIN profiles p ON m.sender_id = p.id
  WHERE
    m.conversation_id = p_conversation_id
  ORDER BY
    m.created_at DESC
  LIMIT 1;
END;
$$;


ALTER FUNCTION "public"."get_latest_message"("p_conversation_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_my_posted_jobs"("user_id" "uuid") RETURNS TABLE("id" "uuid", "title" "text", "company_name" "text", "location" "text", "job_type" "text", "salary_range" "text", "description" "text", "posted_by" "uuid", "company_id" "uuid", "created_at" timestamp with time zone, "is_active" boolean, "is_approved" boolean, "external_url" "text", "contact_email" "text")
    LANGUAGE "sql"
    AS $$
  SELECT
    id,
    title,
    company_name,
    location,
    job_type,
    salary_range,
    description,
    posted_by,
    company_id,
    created_at,
    is_active,
    is_approved,
    external_url,
    contact_email
  FROM jobs
  WHERE posted_by = user_id
  ORDER BY created_at DESC;
$$;


ALTER FUNCTION "public"."get_my_posted_jobs"("user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_my_posted_jobs"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) RETURNS TABLE("id" "uuid", "title" "text", "company_name" "text", "company_logo_url" "text", "is_bookmarked" boolean, "is_approved" boolean, "is_active" boolean, "created_at" timestamp with time zone, "total_count" bigint)
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  RETURN QUERY
  WITH user_jobs AS (
    SELECT
      j.id,
      j.title,
      c.name AS company_name,
      c.logo_url AS company_logo_url,
      (SELECT EXISTS (
        SELECT 1
        FROM job_bookmarks jb
        WHERE jb.job_id = j.id AND jb.user_id = auth.uid()
      )) AS is_bookmarked,
      j.is_approved,
      j.is_active,
      j.created_at
    FROM jobs j
    JOIN companies c ON j.company_id = c.id
    WHERE j.posted_by = auth.uid()
      AND (
        p_search_query IS NULL OR p_search_query = '' OR
        j.title ILIKE '%' || p_search_query || '%'
      )
  )
  SELECT
    uj.*,
    (SELECT COUNT(*) FROM user_jobs) AS total_count
  FROM user_jobs uj
  ORDER BY
    CASE WHEN p_sort_by = 'created_at' AND p_sort_order = 'desc' THEN uj.created_at END DESC,
    CASE WHEN p_sort_by = 'created_at' AND p_sort_order = 'asc' THEN uj.created_at END ASC,
    CASE WHEN p_sort_by = 'title' AND p_sort_order = 'desc' THEN uj.title END DESC,
    CASE WHEN p_sort_by = 'title' AND p_sort_order = 'asc' THEN uj.title END ASC
  LIMIT p_limit OFFSET p_offset;
END;
$$;


ALTER FUNCTION "public"."get_my_posted_jobs"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_my_role"() RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Important: This function assumes the 'profiles' table and 'role' column exist.
  -- It fetches the role for the currently authenticated user.
  RETURN (SELECT role FROM public.profiles WHERE id = auth.uid());
END;
$$;


ALTER FUNCTION "public"."get_my_role"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_or_create_conversation"("user_1_id" "uuid", "user_2_id" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  conversation_id uuid;
BEGIN
  -- Try to find an existing 1-on-1 conversation
  SELECT c.id INTO conversation_id
  FROM conversations c
  JOIN conversation_participants cp1 ON c.id = cp1.conversation_id
  JOIN conversation_participants cp2 ON c.id = cp2.conversation_id
  WHERE cp1.user_id = user_1_id AND cp2.user_id = user_2_id
  AND (SELECT COUNT(*) FROM conversation_participants cp WHERE cp.conversation_id = c.id) = 2;

  -- If no conversation is found, create a new one
  IF conversation_id IS NULL THEN
    INSERT INTO conversations (last_message_at)
    VALUES (NOW()) RETURNING id INTO conversation_id;

    INSERT INTO conversation_participants (conversation_id, user_id)
    VALUES (conversation_id, user_1_id), (conversation_id, user_2_id);
  END IF;

  RETURN conversation_id;
END;
$$;


ALTER FUNCTION "public"."get_or_create_conversation"("user_1_id" "uuid", "user_2_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_pending_approvals"("content_type" "text" DEFAULT 'all'::"text", "limit_count" integer DEFAULT 50) RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  result jsonb;
  query_text text;
  conditions text := '';
BEGIN
  -- Check if user is admin or super_admin
  IF NOT EXISTS (
    SELECT 1
    FROM public.profiles
    WHERE id = auth.uid()
    AND (role = 'admin' OR role = 'super_admin')
  ) THEN
    RETURN jsonb_build_object(
      'success', false,
      'message', 'Only administrators can view pending approvals'
    );
  END IF;

  -- Add condition for content_type if not 'all'
  IF content_type != 'all' THEN
    conditions := format('AND content_type = %L', content_type);
  END IF;

  -- Query to get pending approvals from various tables
  query_text := format('
    WITH pending_items AS (
      -- Events pending approval
      SELECT
        events.id as content_id,
        ''events'' as table_name,
        ''event'' as content_type,
        events.title,
        events.description,
        events.created_by,
        events.created_at,
        profiles.full_name as created_by_name
      FROM public.events
      LEFT JOIN public.profiles ON events.created_by = profiles.id
      WHERE events.is_approved = false
      AND events.rejection_reason IS NULL

      UNION ALL

      -- Jobs pending approval
      SELECT
        jobs.id as content_id,
        ''jobs'' as table_name,
        ''job'' as content_type,
        jobs.title,
        jobs.description,
        jobs.created_by,
        jobs.created_at,
        profiles.full_name as created_by_name
      FROM public.jobs
      LEFT JOIN public.profiles ON jobs.created_by = profiles.id
      WHERE jobs.is_approved = false
      AND jobs.rejection_reason IS NULL

      UNION ALL

      -- Groups pending approval
      SELECT
        groups.id as content_id,
        ''groups'' as table_name,
        ''group'' as content_type,
        groups.name as title,
        groups.description,
        groups.created_by,
        groups.created_at,
        profiles.full_name as created_by_name
      FROM public.groups
      LEFT JOIN public.profiles ON groups.created_by = profiles.id
      WHERE groups.is_approved = false
      AND groups.rejection_reason IS NULL

      -- Add other tables as needed
    )
    SELECT jsonb_agg(row_to_json(pending_items))
    FROM pending_items
    WHERE true %s
    ORDER BY created_at DESC
    LIMIT %s
  ', conditions, limit_count);

  EXECUTE query_text INTO result;
  
  -- Handle case when no results are found
  IF result IS NULL THEN
    result := jsonb_build_array();
  END IF;

  RETURN result;
END;
$$;


ALTER FUNCTION "public"."get_pending_approvals"("content_type" "text", "limit_count" integer) OWNER TO "postgres";


COMMENT ON FUNCTION "public"."get_pending_approvals"("content_type" "text", "limit_count" integer) IS 'Gets content pending approval. Only admins can call this function';



CREATE OR REPLACE FUNCTION "public"."get_pending_content"() RETURNS TABLE("data" "jsonb")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  -- Check if user is admin/super_admin
  IF NOT EXISTS (
    SELECT 1 FROM profiles 
    WHERE id = auth.uid() AND (role IN ('admin', 'super_admin') OR is_admin = true)
  ) THEN
    RAISE EXCEPTION 'Access denied: Only administrators can access pending content';
  END IF;

  -- Pending jobs
  RETURN QUERY
  SELECT jsonb_build_object(
    'id', j.id,
    'title', j.title,
    'content_type', 'job',
    'created_at', j.created_at,
    'name', p.full_name,
    'user_id', j.posted_by,
    'status', CASE WHEN j.is_approved THEN 'approved' WHEN NOT j.is_active THEN 'inactive' ELSE 'pending' END,
    'content', j.description
  ) AS data
  FROM jobs j
  JOIN profiles p ON j.posted_by = p.id
  WHERE j.is_approved = false AND j.is_active = true;
  
  -- Pending events
  RETURN QUERY
  SELECT jsonb_build_object(
    'id', e.id,
    'title', e.title,
    'content_type', 'event',
    'created_at', e.created_at,
    'name', p.full_name,
    'user_id', e.created_by,
    'status', e.status,
    'content', e.description
  ) AS data
  FROM events e
  JOIN profiles p ON e.created_by = p.id
  WHERE e.status = 'pending_approval';
  
  -- Pending group posts
  RETURN QUERY
  SELECT jsonb_build_object(
    'id', gp.id,
    'title', COALESCE(gp.title, 'Group Post'),
    'content_type', 'group_post',
    'created_at', gp.created_at,
    'name', p.full_name,
    'user_id', gp.user_id,
    'status', gp.status,
    'content', gp.content
  ) AS data
  FROM group_posts gp
  JOIN profiles p ON gp.user_id = p.id
  WHERE gp.status = 'pending_approval'
  ORDER BY gp.created_at DESC;
END;
$$;


ALTER FUNCTION "public"."get_pending_content"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_role_by_name"("role_name" "text") RETURNS TABLE("id" "uuid", "name" "text", "description" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN QUERY SELECT r.id, r.name, r.description FROM roles r WHERE r.name = role_name;
END;
$$;


ALTER FUNCTION "public"."get_role_by_name"("role_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_role_id_by_name"("role_name" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  role_id UUID;
BEGIN
  SELECT id INTO role_id FROM roles WHERE name = role_name;
  RETURN role_id;
END;
$$;


ALTER FUNCTION "public"."get_role_id_by_name"("role_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_roles"() RETURNS TABLE("id" "uuid", "name" "text", "description" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN QUERY SELECT r.id, r.name, r.description FROM roles r;
END;
$$;


ALTER FUNCTION "public"."get_roles"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_table_columns"("table_name" "text") RETURNS TABLE("column_name" "text", "data_type" "text", "is_nullable" boolean, "column_default" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN QUERY
  SELECT
    c.column_name::text,
    c.data_type::text,
    (c.is_nullable = 'YES')::boolean,
    c.column_default::text
  FROM
    information_schema.columns c
  WHERE
    c.table_schema = 'public'
    AND c.table_name = table_name
  ORDER BY
    c.ordinal_position;
END;
$$;


ALTER FUNCTION "public"."get_table_columns"("table_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_types"("tname" "text") RETURNS TABLE("column_name" "text", "data_type" "text")
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  RETURN QUERY EXECUTE format(
    'SELECT column_name::text, data_type::text FROM information_schema.columns WHERE table_schema = ''public'' AND table_name = %L ORDER BY ordinal_position',
    tname
  );
END;
$$;


ALTER FUNCTION "public"."get_types"("tname" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_unread_message_count"("conv_id" "uuid", "user_id" "uuid") RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  count_val INTEGER;
BEGIN
  SELECT COUNT(*)::INTEGER INTO count_val
  FROM messages
  WHERE conversation_id = conv_id
    AND sender_id != user_id
    AND read_at IS NULL;
  
  RETURN count_val;
END;
$$;


ALTER FUNCTION "public"."get_unread_message_count"("conv_id" "uuid", "user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_unread_notifications_count"() RETURNS integer
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT public.get_unread_notifications_count_by_type(NULL::text);
$$;


ALTER FUNCTION "public"."get_unread_notifications_count"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_unread_notifications_count"("profile_uuid" "uuid") RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  count INTEGER;
BEGIN
  SELECT COUNT(*) INTO count
  FROM public.notifications
  WHERE profile_id = profile_uuid AND is_read = FALSE;
  
  RETURN count;
END;
$$;


ALTER FUNCTION "public"."get_unread_notifications_count"("profile_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_unread_notifications_count_by_type"("type_filter" "text") RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_uid   uuid := auth.uid();
  v_count integer := 0;
BEGIN
  IF v_uid IS NULL THEN
    RETURN 0;
  END IF;

  IF type_filter IS NULL OR type_filter = '' OR lower(type_filter) = 'all' THEN
    SELECT COUNT(*) INTO v_count
    FROM public.notifications n
    WHERE n.recipient_id = v_uid
      AND COALESCE(n.is_read, false) = false;
  ELSE
    SELECT COUNT(*) INTO v_count
    FROM public.notifications n
    WHERE n.recipient_id = v_uid
      AND COALESCE(n.is_read, false) = false
      AND n.type = type_filter;
  END IF;

  RETURN v_count;
END
$$;


ALTER FUNCTION "public"."get_unread_notifications_count_by_type"("type_filter" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_analytics"("p_user_id" "uuid" DEFAULT NULL::"uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'auth'
    AS $$
DECLARE
  result jsonb;
  target_user_id uuid;
BEGIN
  IF p_user_id IS NULL AND EXISTS (
    SELECT 1 FROM profiles 
    WHERE id = auth.uid() AND (role IN ('admin','super_admin') OR is_admin = true)
  ) THEN
    SELECT jsonb_build_object(
      'totalApplications', COUNT(DISTINCT ja.id),
      'totalUsers',        COUNT(DISTINCT p.id),
      -- use auth.users for last_sign_in_at
      'activeUsers',       COUNT(DISTINCT CASE WHEN u.last_sign_in_at >= NOW() - INTERVAL '30 days' THEN p.id END),
      'completedProfiles', COUNT(DISTINCT CASE WHEN p.is_profile_complete = true THEN p.id END),
      'jobsPosted',        COUNT(DISTINCT j.id),
      'activeJobs',        COUNT(DISTINCT CASE WHEN j.is_active = true AND j.is_approved = true THEN j.id END),
      'usersByRole', (
        SELECT jsonb_object_agg(role_data.role, role_data.count)
        FROM (SELECT role, COUNT(*) AS count FROM profiles GROUP BY role) AS role_data
      )
    ) INTO result
    FROM profiles p
    LEFT JOIN auth.users u        ON u.id = p.id
    LEFT JOIN jobs j              ON j.posted_by    = p.id
    LEFT JOIN job_applications ja ON ja.applicant_id = p.id;

  ELSE
    IF p_user_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND (role IN ('admin','super_admin') OR is_admin = true)
    ) THEN
      target_user_id := p_user_id;
    ELSE
      target_user_id := auth.uid();
    END IF;

    SELECT jsonb_build_object(
      'applications',   COUNT(DISTINCT ja.id),
      'jobsPosted',     COUNT(DISTINCT j.id),
      'activeJobs',     COUNT(DISTINCT CASE WHEN j.is_active = true AND j.is_approved = true THEN j.id END),
      'messagesReceived', (SELECT COUNT(*) FROM messages m WHERE m.receiver_id = target_user_id),
      'messagesSent',     (SELECT COUNT(*) FROM messages m WHERE m.sender_id   = target_user_id),
      'lastActivity', (
        SELECT MAX(ts)
        FROM (
          SELECT created_at AS ts FROM job_applications WHERE applicant_id = target_user_id
          UNION ALL
          SELECT created_at AS ts FROM messages         WHERE sender_id    = target_user_id
          UNION ALL
          SELECT updated_at AS ts FROM profiles         WHERE id           = target_user_id
        ) AS activities
      )
    ) INTO result
    FROM profiles p
    LEFT JOIN jobs j              ON j.posted_by    = target_user_id
    LEFT JOIN job_applications ja ON ja.applicant_id = target_user_id
    WHERE p.id = target_user_id;
  END IF;

  RETURN COALESCE(result, '{}'::jsonb);
END;
$$;


ALTER FUNCTION "public"."get_user_analytics"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_analytics_old_109720"() RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  result jsonb;
BEGIN
  -- Check if user is admin/super_admin
  IF NOT EXISTS (
    SELECT 1 FROM profiles 
    WHERE id = auth.uid() AND (role IN ('admin', 'super_admin') OR is_admin = true)
  ) THEN
    RAISE EXCEPTION 'Access denied: Only administrators can access analytics';
  END IF;

  SELECT jsonb_build_object(
    'registrationsByDate', (
      SELECT jsonb_agg(
        jsonb_build_object(
          'date', to_char(created_at::date, 'YYYY-MM-DD'),
          'count', count(*)
        )
      )
      FROM auth.users
      WHERE created_at >= NOW() - INTERVAL '30 days'
      GROUP BY created_at::date
      ORDER BY created_at::date
    ),
    'activeUsersByDay', (
      SELECT jsonb_agg(
        jsonb_build_object(
          'date', to_char(last_sign_in_at::date, 'YYYY-MM-DD'),
          'count', count(*)
        )
      )
      FROM auth.users
      WHERE last_sign_in_at >= NOW() - INTERVAL '30 days'
      GROUP BY last_sign_in_at::date
      ORDER BY last_sign_in_at::date
    ),
    'userGrowth', (
      SELECT jsonb_agg(
        jsonb_build_object(
          'month', to_char(month_date, 'YYYY-MM'),
          'count', user_count
        )
      )
      FROM (
        SELECT 
          date_trunc('month', created_at) as month_date,
          count(*) as user_count
        FROM auth.users
        WHERE created_at >= NOW() - INTERVAL '12 months'
        GROUP BY month_date
        ORDER BY month_date
      ) monthly_growth
    )
  ) INTO result;

  RETURN result;
END;
$$;


ALTER FUNCTION "public"."get_user_analytics_old_109720"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."get_user_analytics_old_109720"() IS 'Returns analytics data about user registrations and activities for admin dashboard';



CREATE OR REPLACE FUNCTION "public"."get_user_conversations"() RETURNS TABLE("conversation_id" "uuid", "last_updated" timestamp with time zone, "participants" "jsonb", "last_message_content" "text", "last_message_created_at" timestamp with time zone)
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    RETURN QUERY
    WITH user_conversations AS (
        -- Get all conversations the current user is a part of
        SELECT cp.conversation_id
        FROM public.conversation_participants cp
        WHERE cp.user_id = auth.uid()
    ),
    conversation_participants_details AS (
        -- Get details of all participants in those conversations, excluding the current user
        SELECT
            cp.conversation_id,
            jsonb_agg(jsonb_build_object('id', p.id, 'full_name', p.full_name, 'avatar_url', p.avatar_url)) AS participants
        FROM public.conversation_participants cp
        JOIN public.profiles p ON cp.user_id = p.id
        WHERE cp.conversation_id IN (SELECT uc.conversation_id FROM user_conversations)
          AND cp.user_id <> auth.uid()
        GROUP BY cp.conversation_id
    ),
    last_messages AS (
        -- Get the last message for each conversation using a window function
        SELECT
            m.conversation_id,
            m.content,
            m.created_at
        FROM (
            SELECT
                m.conversation_id,
                m.content,
                m.created_at,
                ROW_NUMBER() OVER(PARTITION BY m.conversation_id ORDER BY m.created_at DESC) as rn
            FROM public.messages m
            WHERE m.conversation_id IN (SELECT uc.conversation_id FROM user_conversations)
        ) m
        WHERE m.rn = 1
    )
    -- Final SELECT to join everything together
    SELECT
        c.id AS conversation_id,
        c.updated_at AS last_updated,
        cpd.participants,
        lm.content AS last_message_content,
        lm.created_at AS last_message_created_at
    FROM public.conversations c
    JOIN user_conversations uc ON c.id = uc.conversation_id
    LEFT JOIN conversation_participants_details cpd ON c.id = cpd.conversation_id
    LEFT JOIN last_messages lm ON c.id = lm.conversation_id
    ORDER BY c.updated_at DESC;
END;
$$;


ALTER FUNCTION "public"."get_user_conversations"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_conversations_v2"("p_user_id" "uuid") RETURNS TABLE("conversation_id" "uuid", "last_message_at" timestamp with time zone, "created_at" timestamp with time zone, "participant_id" "uuid", "participant_name" "text", "participant_avatar" "text", "is_online" boolean, "unread_count" bigint)
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN QUERY
  WITH user_conversations AS (
    SELECT cp.conversation_id
    FROM conversation_participants cp
    WHERE cp.user_id = p_user_id
  )
  SELECT
    c.id,
    c.last_message_at,
    c.created_at,
    other_participant.user_id,
    p.full_name,
    p.avatar_url,
    COALESCE(p.is_online, FALSE),
    (
      SELECT COUNT(*)
      FROM public.messages m
      WHERE m.conversation_id = c.id
        AND m.sender_id != p_user_id
        AND m.read_at IS NULL
    ) AS unread_count
  FROM conversations c
  JOIN user_conversations uc ON c.id = uc.conversation_id
  JOIN conversation_participants other_participant ON c.id = other_participant.conversation_id AND other_participant.user_id != p_user_id
  JOIN profiles p ON other_participant.user_id = p.id
  ORDER BY c.last_message_at DESC;
END;
$$;


ALTER FUNCTION "public"."get_user_conversations_v2"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_permissions"("profile_uuid" "uuid") RETURNS TABLE("permission_name" "text", "permission_description" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN QUERY
  SELECT permissions.name, permissions.description
  FROM permissions
  WHERE permissions.id IN (
    SELECT permission_id 
    FROM role_permissions
    WHERE role_permissions.role_id IN (
      SELECT role_id 
      FROM user_roles
      WHERE user_roles.profile_id = profile_uuid
    )
  );
END;
$$;


ALTER FUNCTION "public"."get_user_permissions"("profile_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_permissions_bypass_rls"("profile_uuid" "uuid") RETURNS TABLE("permission_name" "text", "permission_description" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN QUERY
  SELECT DISTINCT p.name, p.description
  FROM permissions p
  JOIN role_permissions rp ON p.id = rp.permission_id
  JOIN user_roles ur ON rp.role_id = ur.role_id
  WHERE ur.profile_id = profile_uuid;
END;
$$;


ALTER FUNCTION "public"."get_user_permissions_bypass_rls"("profile_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_role"() RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select public.get_user_role(auth.uid());
$$;


ALTER FUNCTION "public"."get_user_role"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_role"("p_user_id" "uuid") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_role text;
  v_is_admin boolean;
BEGIN
  IF p_user_id IS NULL THEN
    RETURN 'anon';
  END IF;

  SELECT role, is_admin INTO v_role, v_is_admin
  FROM public.profiles
  WHERE id = p_user_id;

  IF NOT FOUND THEN
    RETURN 'anon';
  END IF;

  IF v_is_admin THEN
    RETURN 'admin';
  END IF;

  IF v_role IS NULL OR TRIM(v_role) = '' OR v_role = 'user' THEN
    RETURN 'alumni';
  END IF;

  RETURN v_role;
END;
$$;


ALTER FUNCTION "public"."get_user_role"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_roles_bypass_rls"("profile_uuid" "uuid") RETURNS TABLE("role_name" "text", "role_description" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN QUERY
  SELECT r.name, r.description
  FROM roles r
  JOIN user_roles ur ON r.id = ur.role_id
  WHERE ur.profile_id = profile_uuid;
END;
$$;


ALTER FUNCTION "public"."get_user_roles_bypass_rls"("profile_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_view_columns"("view_name" "text") RETURNS TABLE("column_name" "text", "data_type" "text")
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  RETURN QUERY
  SELECT
    a.attname::text,
    pg_catalog.format_type(a.atttypid, a.atttypmod)
  FROM
    pg_catalog.pg_attribute a
  JOIN
    pg_catalog.pg_class c ON a.attrelid = c.oid
  WHERE
    c.relname = view_name
    AND a.attnum > 0
    AND NOT a.attisdropped;
END;
$$;


ALTER FUNCTION "public"."get_view_columns"("view_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_new_group"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
   BEGIN
     -- Add creator as member and admin
     INSERT INTO public.group_members (group_id, user_id, role)
     VALUES (new.id, auth.uid(), 'admin');
     RETURN new;
   END;
   $$;


ALTER FUNCTION "public"."handle_new_group"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  meta jsonb := NEW.raw_user_meta_data;
  role_from_meta text := coalesce(meta->>'role','user');
  is_employer_meta boolean := coalesce((meta->>'is_employer')::boolean, false);
BEGIN
  INSERT INTO public.profiles (
    id, email, created_at, role, is_verified,
    first_name, last_name, phone,
    is_employer, company_name, company_website, industry, company_size, company_location,
    linkedin_url, degree_program, about, social_links, skills, interests
  )
  VALUES (
    NEW.id,
    NEW.email,
    now(),
    role_from_meta,
    false,
    meta->>'first_name',
    meta->>'last_name',
    meta->>'phone',
    (is_employer_meta OR role_from_meta = 'employer'),
    meta->>'company_name',
    meta->>'company_website',
    meta->>'industry',
    meta->>'company_size',
    meta->>'company_location',
    meta->>'linkedin_url',
    COALESCE(meta->>'degree_program', meta->>'degree'),
    meta->>'about',
    COALESCE(meta->'social_links', '{}'::jsonb),
    COALESCE(meta->'skills', '[]'::jsonb),
    COALESCE(meta->'interests', '[]'::jsonb)
  );

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."handle_new_user"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."handle_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_permission"("user_id" "uuid", "permission_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  has_perm boolean;
BEGIN
  -- Get the user's role
  SELECT 
    CASE 
      -- Super admins have all permissions
      WHEN role = 'super_admin' THEN true
      -- Admins have all standard permissions
      WHEN role = 'admin' AND permission_name NOT IN ('assign_super_admin') THEN true
      -- Role-specific permissions
      WHEN role = 'mentor' AND permission_name IN ('create_event', 'create_post') THEN true
      WHEN role = 'employer' AND permission_name IN ('post_job', 'manage_company') THEN true
      WHEN role = 'alumni' AND permission_name IN ('apply_job', 'attend_event', 'send_message') THEN true
      ELSE false
    END INTO has_perm
  FROM public.profiles
  WHERE id = user_id;

  RETURN COALESCE(has_perm, false);
END;
$$;


ALTER FUNCTION "public"."has_permission"("user_id" "uuid", "permission_name" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."has_permission"("user_id" "uuid", "permission_name" "text") IS 'Checks if a user has a specific permission based on their role';



CREATE OR REPLACE FUNCTION "public"."is_admin"() RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$ SELECT public._is_admin(auth.uid()); $$;


ALTER FUNCTION "public"."is_admin"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_admin"("p_user_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = p_user_id
      AND (p.is_admin IS TRUE OR p.role IN ('admin','super_admin'))
  );
$$;


ALTER FUNCTION "public"."is_admin"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_connected"("a" "uuid", "b" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE
    AS $$
  select exists (
    select 1
    from public.connections c
    where c.status = 'accepted'
      and (
        (c.requester_id = a and c.recipient_id = b) or
        (c.requester_id = b and c.recipient_id = a)
      )
  );
$$;


ALTER FUNCTION "public"."is_connected"("a" "uuid", "b" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_conversation_participant"("p_conversation_id" "uuid", "p_user_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE
    AS $$
  select exists (
    select 1
    from public.conversations
    where id = p_conversation_id
      and (participant_1 = p_user_id or participant_2 = p_user_id)
  );
$$;


ALTER FUNCTION "public"."is_conversation_participant"("p_conversation_id" "uuid", "p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_group_admin"("gid" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select exists(
    select 1
    from public.group_members
    where group_id = gid and user_id = auth.uid() and role = 'admin'
  );
$$;


ALTER FUNCTION "public"."is_group_admin"("gid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_group_admin"("p_user_id" "uuid", "p_group_id" "uuid") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    is_admin boolean;
BEGIN
    -- Temporarily disable RLS
    EXECUTE 'SET LOCAL row_security = off';

    SELECT EXISTS (
        SELECT 1
        FROM group_members
        WHERE group_id = p_group_id
          AND user_id = p_user_id
          AND role = 'admin'
    )
    INTO is_admin;

    RETURN is_admin;
END;
$$;


ALTER FUNCTION "public"."is_group_admin"("p_user_id" "uuid", "p_group_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_member_of_group"("p_group_id" "uuid") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1
    FROM public.group_members
    WHERE group_id = p_group_id AND user_id = auth.uid()
  );
END;
$$;


ALTER FUNCTION "public"."is_member_of_group"("p_group_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."join_group"("group_id" "uuid") RETURNS "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $_$
   DECLARE
     result JSON;
   BEGIN
     -- Check if already a member
     IF EXISTS (
       SELECT 1 FROM public.group_members 
       WHERE user_id = auth.uid() AND group_id = $1
     ) THEN
       SELECT json_build_object(
         'success', false,
         'message', 'Already a member of this group'
       ) INTO result;
       RETURN result;
     END IF;

     -- Add as member
     INSERT INTO public.group_members (group_id, user_id, role)
     VALUES ($1, auth.uid(), 'member')
     RETURNING json_build_object(
       'success', true,
       'message', 'Successfully joined group',
       'group_id', group_id
     ) INTO result;
     
     RETURN result;
   END;
   $_$;


ALTER FUNCTION "public"."join_group"("group_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."list_tables"() RETURNS TABLE("table_name" "text")
    LANGUAGE "sql" SECURITY DEFINER
    AS $$
  select table_name
    from information_schema.tables
   where table_schema = 'public'
     and table_type = 'BASE TABLE';
$$;


ALTER FUNCTION "public"."list_tables"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."mark_conversation_as_read"("p_conversation_id" "uuid", "p_user_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  UPDATE messages
  SET is_read = TRUE
  WHERE 
    conversation_id = p_conversation_id 
    AND sender_id != p_user_id 
    AND is_read = FALSE;
END;
$$;


ALTER FUNCTION "public"."mark_conversation_as_read"("p_conversation_id" "uuid", "p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."mark_notification_as_read"("notification_uuid" "uuid") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  success BOOLEAN;
BEGIN
  UPDATE public.notifications
  SET is_read = TRUE, updated_at = NOW()
  WHERE id = notification_uuid AND profile_id = auth.uid();
  
  GET DIAGNOSTICS success = ROW_COUNT;
  RETURN success > 0;
END;
$$;


ALTER FUNCTION "public"."mark_notification_as_read"("notification_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."moderate_content"("p_content_id" "uuid", "p_content_type" "text", "p_action" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  -- Check if user is admin/super_admin
  IF NOT EXISTS (
    SELECT 1 FROM profiles 
    WHERE id = auth.uid() AND (role IN ('admin', 'super_admin') OR is_admin = true)
  ) THEN
    RAISE EXCEPTION 'Access denied: Only administrators can moderate content';
  END IF;
  
  -- Check valid action
  IF p_action NOT IN ('approve', 'reject') THEN
    RAISE EXCEPTION 'Invalid action: Must be "approve" or "reject"';
  END IF;
  
  -- Handle different content types
  CASE p_content_type
    WHEN 'job' THEN
      IF p_action = 'approve' THEN
        UPDATE jobs SET status = 'active' WHERE id = p_content_id;
      ELSE
        UPDATE jobs SET status = 'rejected' WHERE id = p_content_id;
      END IF;
      
    WHEN 'event' THEN
      IF p_action = 'approve' THEN
        UPDATE events SET status = 'active' WHERE id = p_content_id;
      ELSE
        UPDATE events SET status = 'rejected' WHERE id = p_content_id;
      END IF;
      
    WHEN 'group_post' THEN
      IF p_action = 'approve' THEN
        UPDATE group_posts SET status = 'approved' WHERE id = p_content_id;
      ELSE
        UPDATE group_posts SET status = 'rejected' WHERE id = p_content_id;
      END IF;
      
    ELSE
      RAISE EXCEPTION 'Unsupported content type: %', p_content_type;
  END CASE;
  
  -- Log the moderation action
  INSERT INTO public.activity_log (
    description,
    activity_type,
    user_id,
    metadata
  ) VALUES (
    p_action || 'd ' || p_content_type || ' (ID: ' || p_content_id || ')',
    'content_moderation',
    auth.uid(),
    jsonb_build_object(
      'content_id', p_content_id,
      'content_type', p_content_type,
      'action', p_action
    )
  );
END;
$$;


ALTER FUNCTION "public"."moderate_content"("p_content_id" "uuid", "p_content_type" "text", "p_action" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."moderate_content"("p_content_id" "uuid", "p_content_type" "text", "p_action" "text") IS 'Approves or rejects content and logs the moderation action';



CREATE OR REPLACE FUNCTION "public"."moderate_content"("content_table" "text", "content_id" "uuid", "is_approved" boolean, "rejection_reason" "text" DEFAULT ''::"text", "content_type" "text" DEFAULT 'content'::"text") RETURNS "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  result json;
  admin_user_id uuid;
  content_json json;
BEGIN
  -- Check if user is admin or super_admin
  SELECT id INTO admin_user_id
  FROM public.profiles
  WHERE id = auth.uid()
  AND (role = 'admin' OR role = 'super_admin');

  IF admin_user_id IS NULL THEN
    RETURN json_build_object(
      'success', false,
      'message', 'Only administrators can approve or reject content'
    );
  END IF;

  -- Build dynamic SQL to update the content
  EXECUTE format('
    UPDATE public.%I
    SET 
      is_approved = %L,
      approved_by = %L,
      approved_at = %L,
      rejection_reason = %L,
      updated_at = now()
    WHERE id = %L
    RETURNING to_json(%I.*)',
    content_table,
    is_approved,
    CASE WHEN is_approved THEN admin_user_id ELSE NULL END,
    CASE WHEN is_approved THEN now() ELSE NULL END,
    CASE WHEN NOT is_approved THEN rejection_reason ELSE NULL END,
    content_id,
    content_table
  ) INTO content_json;

  IF content_json IS NULL THEN
    RETURN json_build_object(
      'success', false,
      'message', format('Content with ID %s not found in table %s', content_id, content_table)
    );
  END IF;

  -- OPTIONAL: Create notification for content owner if applicable (keep or remove based on your design)
  BEGIN
    EXECUTE format('
      INSERT INTO public.notifications (
        user_id,
        type,
        title,
        message,
        data,
        created_at
      )
      SELECT 
        created_by, 
        %L, 
        %L, 
        %L, 
        %L, 
        now()
      FROM public.%I
      WHERE id = %L',
      CASE WHEN is_approved THEN 'content_approved' ELSE 'content_rejected' END,
      CASE WHEN is_approved THEN format('Your %s was approved', content_type) ELSE format('Your %s was rejected', content_type) END,
      CASE WHEN is_approved THEN format('Your %s has been approved by an administrator', content_type) ELSE format('Your %s was rejected: %s', content_type, rejection_reason) END,
      json_build_object('content_id', content_id, 'content_type', content_type),
      content_table,
      content_id
    );
  EXCEPTION
    WHEN OTHERS THEN
      RAISE NOTICE 'Failed to create notification for content moderation: %', SQLERRM;
  END;

  result := json_build_object(
    'success', true,
    'message', format('Content has been %s', CASE WHEN is_approved THEN 'approved' ELSE 'rejected' END),
    'content', content_json
  );

  RETURN result;
END;
$$;


ALTER FUNCTION "public"."moderate_content"("content_table" "text", "content_id" "uuid", "is_approved" boolean, "rejection_reason" "text", "content_type" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."moderate_content"("content_table" "text", "content_id" "uuid", "is_approved" boolean, "rejection_reason" "text", "content_type" "text") IS 'Moderates content for approval workflow. Only admins can call this function';



CREATE OR REPLACE FUNCTION "public"."notify_admins_on_event"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  admin_rec RECORD;
  creator_name text;
  event_link text;
BEGIN
  -- Attempt to build a link to the event details page
  event_link := '/events/' || NEW.id::text;

  -- A friendly creator label; fallback to uid if name missing
  SELECT trim(coalesce(first_name,'') || ' ' || coalesce(last_name,'')) INTO creator_name
  FROM public.profiles
  WHERE id = NEW.organizer_id;

  -- Notify all admins and super_admins (skip deleted admins if such flag exists)
  FOR admin_rec IN
    SELECT id
    FROM public.profiles
    WHERE (is_admin = true OR role IN ('admin','super_admin'))
      AND COALESCE(is_deleted, false) = false
  LOOP
    INSERT INTO public.notifications (recipient_id, title, message, type, link, is_read, created_at)
    VALUES (
      admin_rec.id,
      'New event created',
      COALESCE(creator_name, NEW.organizer_id::text) || ' created: ' || NEW.title,
      'events',
      event_link,
      false,
      now()
    );
  END LOOP;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."notify_admins_on_event"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."notify_connection_approved"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF NEW.status = 'accepted' THEN
    INSERT INTO notifications (profile_id, title, message, link)
    VALUES (
      NEW.requester_id,
      'Connection Accepted',
      'Your connection request was accepted.',
      '/connections'
    );
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."notify_connection_approved"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."notify_event_rsvp"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  INSERT INTO notifications (profile_id, title, message, link)
  VALUES (
    NEW.user_id,
    'RSVP Confirmed',
    'You are registered for the event.',
    '/events/' || NEW.event_id
  );

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."notify_event_rsvp"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."notify_job_application_submitted"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  INSERT INTO public.notifications (profile_id, recipient_id, type, message, is_read, created_at)
  VALUES (NEW.applicant_id, NEW.applicant_id, 'job_alert', 'Your job application has been submitted.', false, now());
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."notify_job_application_submitted"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."notify_mentorship_request"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  INSERT INTO notifications (profile_id, title, message, link)
  VALUES (
    NEW.mentor_id,
    'New Mentorship Request',
    'You have received a new mentorship request.',
    '/mentorship'
  );

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."notify_mentorship_request"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."notify_new_connection_request"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF NEW.status = 'pending' THEN
    INSERT INTO notifications (profile_id, title, message, link)
    VALUES (
      NEW.recipient_id,
      'New Connection Request',
      'You have a new connection request.',
      '/connections'
    );
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."notify_new_connection_request"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."notify_new_message"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  participant_1_id UUID;
  participant_2_id UUID;
BEGIN
  -- Get the conversation participants
  SELECT participant_1, participant_2 INTO participant_1_id, participant_2_id
  FROM public.conversations
  WHERE id = NEW.conversation_id;
  
  -- Update unread count for the other participant (not the sender)
  -- This is used for notification badges
  IF participant_1_id = NEW.sender_id THEN
    -- Sender is participant 1, notify participant 2
    PERFORM pg_notify(
      'new_message',
      json_build_object(
        'user_id', participant_2_id,
        'conversation_id', NEW.conversation_id,
        'sender_id', NEW.sender_id,
        'message_id', NEW.id
      )::text
    );
  ELSE
    -- Sender is participant 2, notify participant 1
    PERFORM pg_notify(
      'new_message',
      json_build_object(
        'user_id', participant_1_id,
        'conversation_id', NEW.conversation_id,
        'sender_id', NEW.sender_id,
        'message_id', NEW.id
      )::text
    );
  END IF;
  
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."notify_new_message"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."notify_on_job_application"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  INSERT INTO public.notifications (
    profile_id,  -- Add this
    recipient_id,  -- Or keep if needed
    type,
    message,
    is_read,
    created_at
  ) VALUES (
    NEW.applicant_id,  -- Change from NEW.user_id
    NEW.applicant_id,  -- Change from NEW.user_id
    'job_application',
    'New job application received',
    false,
    now()
  );
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."notify_on_job_application"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."notify_profile_verification"() RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  INSERT INTO notifications (profile_id, title, message, link)
  SELECT id, 'Verification Successful', 'Your alumni profile was verified.', '/profile'
  FROM profiles
  WHERE is_verified = true AND NOT EXISTS (
    SELECT 1 FROM notifications 
    WHERE profile_id = profiles.id AND title = 'Verification Successful'
  );
END;
$$;


ALTER FUNCTION "public"."notify_profile_verification"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."profiles_normalize_names"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
begin
  if new.first_name is not null then
    -- trim ends and collapse internal whitespace
    new.first_name := regexp_replace(btrim(new.first_name), '\s+', ' ', 'g');
  end if;

  if new.last_name is not null then
    new.last_name  := regexp_replace(btrim(new.last_name),  '\s+', ' ', 'g');
  end if;

  return new;
end
$$;


ALTER FUNCTION "public"."profiles_normalize_names"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."protect_jobs_admin_columns"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_is_admin boolean := EXISTS (
    SELECT 1
    FROM public.profiles p
    WHERE p.id = v_uid
      AND (p.is_admin IS TRUE OR p.role IN ('admin','super_admin'))
  );
BEGIN
  -- Only enforce on UPDATEs; allow INSERT/DELETE to pass through.
  IF TG_OP <> 'UPDATE' THEN
    RETURN NEW;
  END IF;

  IF NOT v_is_admin THEN
    -- Compare as text via JSONB so missing columns don't raise errors.
    IF (to_jsonb(NEW)->>'is_approved') IS DISTINCT FROM (to_jsonb(OLD)->>'is_approved')
       OR (to_jsonb(NEW)->>'is_rejected') IS DISTINCT FROM (to_jsonb(OLD)->>'is_rejected')
       OR (to_jsonb(NEW)->>'is_featured') IS DISTINCT FROM (to_jsonb(OLD)->>'is_featured')
       OR (to_jsonb(NEW)->>'posted_by')  IS DISTINCT FROM (to_jsonb(OLD)->>'posted_by')
    THEN
      RAISE EXCEPTION 'Only admins can modify approval/featured/posted_by fields on jobs.';
    END IF;
  END IF;

  RETURN NEW;
END
$$;


ALTER FUNCTION "public"."protect_jobs_admin_columns"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."protect_mentors_admin_columns"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF get_user_role(auth.uid()) NOT IN ('admin','super_admin') THEN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'Only admin can change mentor status' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NEW;
END$$;


ALTER FUNCTION "public"."protect_mentors_admin_columns"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."protect_profile_admin_columns"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  -- Allow system operations
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  -- If user edits their own row, block changes to admin-only fields
  IF NEW.id = auth.uid() THEN
    IF NEW.approval_status IS DISTINCT FROM OLD.approval_status
       OR NEW.role IS DISTINCT FROM OLD.role
       OR NEW.is_admin IS DISTINCT FROM OLD.is_admin THEN
      RAISE EXCEPTION 'You cannot change restricted fields' USING ERRCODE = '42501';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."protect_profile_admin_columns"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."purge_user_data"("uid" "uuid") RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
begin
  -- Messaging & groups
  delete from public.messages where sender_id = uid or recipient_id = uid;
  delete from public.conversation_participants where user_id = uid;
  delete from public.connections where requester_id = uid or recipient_id = uid;
  delete from public.group_members where user_id = uid;

  -- Events
  delete from public.event_attendees where user_id = uid;
  delete from public.event_feedback where user_id = uid;

  -- Jobs
  delete from public.job_applications where applicant_id = uid;
  delete from public.job_bookmarks where user_id = uid;
  delete from public.job_alerts where user_id = uid;

  -- Mentorship
  delete from public.mentorship_requests where mentee_id = uid or mentor_id = uid;

  -- Resumes/notifications
  delete from public.user_resumes where user_id = uid;
  delete from public.notifications where profile_id = uid;

  -- Finally, the profile
  delete from public.profiles where id = uid;
end;
$$;


ALTER FUNCTION "public"."purge_user_data"("uid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."remove_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  role_id_val UUID;
BEGIN
  -- Get role ID with fully qualified column names
  SELECT roles.id INTO role_id_val FROM roles WHERE roles.name = role_name;
  
  -- Check if role exists
  IF role_id_val IS NULL THEN
    RETURN FALSE;
  END IF;
  
  -- Remove role from user with fully qualified column names
  DELETE FROM user_roles
  WHERE user_roles.profile_id = profile_uuid AND user_roles.role_id = role_id_val;
  
  RETURN TRUE;
END;
$$;


ALTER FUNCTION "public"."remove_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."remove_user_role"("profile_uuid" "uuid", "role_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  role_id UUID;
BEGIN
  -- Get role ID
  SELECT id INTO role_id FROM roles WHERE name = role_name;
  
  -- Check if role exists
  IF role_id IS NULL THEN
    RETURN FALSE;
  END IF;
  
  -- Remove role from user
  DELETE FROM user_roles
  WHERE profile_id = profile_uuid AND role_id = role_id;
  
  RETURN TRUE;
END;
$$;


ALTER FUNCTION "public"."remove_user_role"("profile_uuid" "uuid", "role_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."rsvp_to_event"("p_event_id" "uuid", "p_attendee_id" "uuid", "p_attendance_status_text" "text") RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  INSERT INTO event_rsvps (event_id, user_id, attendance_status)
  VALUES (p_event_id, p_attendee_id, p_attendance_status_text)
  ON CONFLICT (event_id, user_id) DO
  UPDATE SET attendance_status = EXCLUDED.attendance_status;
END;
$$;


ALTER FUNCTION "public"."rsvp_to_event"("p_event_id" "uuid", "p_attendee_id" "uuid", "p_attendance_status_text" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."safe_to_jsonb"("_txt" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
DECLARE outv jsonb;
BEGIN
  IF _txt IS NULL THEN
    RETURN NULL;
  END IF;
  outv := _txt::jsonb;         -- try parsing as JSON
  RETURN outv;
EXCEPTION WHEN others THEN
  RETURN to_jsonb(_txt);       -- fallback: keep as JSON string
END
$$;


ALTER FUNCTION "public"."safe_to_jsonb"("_txt" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_group_creator"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF NEW.created_by IS NULL THEN
    NEW.created_by := auth.uid();
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."set_group_creator"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_group_creator_as_admin"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  INSERT INTO group_members (group_id, user_id, role)
  VALUES (NEW.id, NEW.created_by_user_id, 'admin');
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."set_group_creator_as_admin"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_group_member_user_id"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  -- Set user_id to the authenticated user's ID if it's not already provided
  IF NEW.user_id IS NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."set_group_member_user_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_job_owner_default"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF NEW.posted_by IS NULL THEN
    NEW.posted_by := auth.uid();
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."set_job_owner_default"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."start_or_get_conversation"("other_user" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  me uuid := auth.uid();
  a uuid;
  b uuid;
  conv_id uuid;
begin
  if me is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;

  if me = other_user then
    raise exception 'cannot DM self';
  end if;

  if not public.is_connected(me, other_user) then
    raise exception 'not connected';
  end if;

  -- normalized pair to enforce A-B uniqueness
  a := least(me, other_user);
  b := greatest(me, other_user);

  select id into conv_id
  from public.conversations
  where participant_1 = a and participant_2 = b
  limit 1;

  if conv_id is null then
    insert into public.conversations (id, participant_1, participant_2, created_at, updated_at, last_message_at)
    values (gen_random_uuid(), a, b, now(), now(), now())
    returning id into conv_id;
  end if;

  return conv_id;
end;
$$;


ALTER FUNCTION "public"."start_or_get_conversation"("other_user" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."sync_is_approved_from_status"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  NEW.is_approved := (NEW.approval_status = 'approved'::public.profile_approval_status);
  RETURN NEW;
END
$$;


ALTER FUNCTION "public"."sync_is_approved_from_status"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."trg_attach_user_to_batch_group"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  PERFORM public.attach_user_to_batch_group(NEW.id);
  RETURN NEW;
END
$$;


ALTER FUNCTION "public"."trg_attach_user_to_batch_group"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_conversation_last_message"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  UPDATE public.conversations
  SET last_message_at = NEW.created_at
  WHERE id = NEW.conversation_id;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_conversation_last_message"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_conversation_last_message_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  UPDATE public.conversations
  SET last_message_at = NOW()
  WHERE id = NEW.conversation_id;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_conversation_last_message_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_conversation_last_message_timestamp"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  -- Update the conversation's last_message_at timestamp if conversation_id is not null
  IF NEW.conversation_id IS NOT NULL THEN
    UPDATE public.conversations
    SET last_message_at = NEW.created_at
    WHERE id = NEW.conversation_id;
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_conversation_last_message_timestamp"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_conversation_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    UPDATE public.conversations
    SET updated_at = now()
    WHERE id = NEW.conversation_id;
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_conversation_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_event_published_status"("event_id" "uuid", "status_value" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    is_published_value BOOLEAN;
    result JSONB;
BEGIN
    -- Convert status string to boolean is_published value
    IF status_value = 'published' THEN
        is_published_value := TRUE;
    ELSE
        is_published_value := FALSE;
    END IF;
    
    -- Update the event status
    UPDATE public.events 
    SET 
        is_published = is_published_value,
        updated_at = now()
    WHERE id = event_id;
    
    -- Return the updated event
    SELECT row_to_json(e)::jsonb INTO result
    FROM public.events e
    WHERE id = event_id;
    
    RETURN result;
END;
$$;


ALTER FUNCTION "public"."update_event_published_status"("event_id" "uuid", "status_value" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_event_status_rpc"("event_id" "uuid", "new_status" "text") RETURNS "jsonb"
    LANGUAGE "sql"
    AS $$
    SELECT public.update_event_published_status(event_id, new_status);
$$;


ALTER FUNCTION "public"."update_event_status_rpc"("event_id" "uuid", "new_status" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_full_name"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
begin
  -- Do NOT change the case; just set full_name.
  new.full_name := trim(coalesce(new.first_name,'') || ' ' || coalesce(new.last_name,''));
  return new;
end;
$$;


ALTER FUNCTION "public"."update_full_name"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_updated_at_column"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_updated_at_column"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_user_role"("user_id" "uuid", "new_role" "text") RETURNS "json"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  admin_user_id uuid;
  target_user_role text;
  admin_user_role text;
  result json;
BEGIN
  -- Check if user is admin or super_admin
  SELECT id, role INTO admin_user_id, admin_user_role
  FROM public.profiles
  WHERE id = auth.uid()
  AND (role = 'admin' OR role = 'super_admin');

  IF admin_user_id IS NULL THEN
    RETURN json_build_object(
      'success', false,
      'message', 'Only administrators can update user roles'
    );
  END IF;

  -- Get target user's current role
  SELECT role INTO target_user_role
  FROM public.profiles
  WHERE id = user_id;

  -- Super admin role check - only super_admin can assign super_admin
  IF new_role = 'super_admin' AND admin_user_role != 'super_admin' THEN
    RETURN json_build_object(
      'success', false,
      'message', 'Only super administrators can assign the super admin role'
    );
  END IF;

  -- Update the user's role
  UPDATE public.profiles
  SET role = new_role,
      updated_at = now()
  WHERE id = user_id
  RETURNING to_json(profiles.*) INTO result;

  RETURN json_build_object(
    'success', true,
    'message', format('User role updated to %s', new_role),
    'user', result
  );
END;
$$;


ALTER FUNCTION "public"."update_user_role"("user_id" "uuid", "new_role" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."update_user_role"("user_id" "uuid", "new_role" "text") IS 'Updates a user''s role. Only admins can call this function';



CREATE OR REPLACE FUNCTION "public"."user_has_permission"("profile_uuid" "uuid", "permission_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  has_permission BOOLEAN;
BEGIN
  SELECT EXISTS (
    SELECT 1 
    FROM permissions 
    WHERE permissions.name = permission_name
    AND permissions.id IN (
      SELECT permission_id 
      FROM role_permissions
      WHERE role_permissions.role_id IN (
        SELECT role_id 
        FROM user_roles
        WHERE user_roles.profile_id = profile_uuid
      )
    )
  ) INTO has_permission;
  
  RETURN has_permission;
END;
$$;


ALTER FUNCTION "public"."user_has_permission"("profile_uuid" "uuid", "permission_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."user_has_role"("profile_uuid" "uuid", "role_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  has_role BOOLEAN;
BEGIN
  SELECT EXISTS (
    SELECT 1 
    FROM roles 
    WHERE roles.name = role_name
    AND roles.id IN (
      SELECT role_id 
      FROM user_roles
      WHERE user_roles.profile_id = profile_uuid
    )
  ) INTO has_role;
  
  RETURN has_role;
END;
$$;


ALTER FUNCTION "public"."user_has_role"("profile_uuid" "uuid", "role_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_profile_fields"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $_$
BEGIN
  -- Normalize and validate email
  IF NEW.email IS NOT NULL THEN
    NEW.email := lower(btrim(NEW.email));

    -- Basic email format validation
    IF NEW.email !~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' THEN
      RAISE EXCEPTION 'Invalid email format'
        USING ERRCODE = '22000';
    END IF;

    -- Disallow .co TLD (e.g., example@domain.co)
    IF NEW.email ~* '@[^@]+\.co$' THEN
      RAISE EXCEPTION 'Email addresses ending with .co are not allowed'
        USING ERRCODE = '22000';
    END IF;
  END IF;

  -- Validate first_name: allow only letters and spaces when provided
  IF NEW.first_name IS NOT NULL AND btrim(NEW.first_name) <> '' THEN
    IF NEW.first_name !~ '^[A-Za-z ]+$' THEN
      RAISE EXCEPTION 'First name can only contain letters and spaces'
        USING ERRCODE = '22000';
    END IF;
  END IF;

  -- Validate last_name: allow only letters and spaces when provided
  IF NEW.last_name IS NOT NULL AND btrim(NEW.last_name) <> '' THEN
    IF NEW.last_name !~ '^[A-Za-z ]+$' THEN
      RAISE EXCEPTION 'Last name can only contain letters and spaces'
        USING ERRCODE = '22000';
    END IF;
  END IF;

  -- Validate phone number: optional leading + and 7-15 digits when provided
  IF NEW.phone IS NOT NULL AND btrim(NEW.phone) <> '' THEN
    IF NEW.phone !~ '^\+?\d{7,15}$' THEN
      RAISE EXCEPTION 'Phone number must be 7-15 digits with optional leading +'
        USING ERRCODE = '22000';
    END IF;
  END IF;

  RETURN NEW;
END;
$_$;


ALTER FUNCTION "public"."validate_profile_fields"() OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."achievements" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "profile_id" "uuid",
    "title" "text" NOT NULL,
    "description" "text",
    "year" integer,
    "url" "text",
    "achievement_type" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "achievements_achievement_type_check" CHECK (("achievement_type" = ANY (ARRAY['professional'::"text", 'academic'::"text", 'personal'::"text", 'other'::"text"])))
);


ALTER TABLE "public"."achievements" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."activity_log" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "description" "text" NOT NULL,
    "activity_type" "text" NOT NULL,
    "user_id" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "metadata" "jsonb" DEFAULT '{}'::"jsonb"
);


ALTER TABLE "public"."activity_log" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."activity_logs" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "profile_id" "uuid",
    "action" "text" NOT NULL,
    "entity_type" "text" NOT NULL,
    "entity_id" "text" NOT NULL,
    "details" "jsonb",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."activity_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."admin_actions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "admin_id" "uuid",
    "action_type" "text" NOT NULL,
    "target_type" "text" NOT NULL,
    "target_id" "uuid",
    "description" "text",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."admin_actions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."admin_invalid_degree_programs_audit" (
    "id" "uuid" NOT NULL,
    "old_degree_program" "text",
    "snapshot_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."admin_invalid_degree_programs_audit" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."backup_bad_conversations_20250905" (
    "conversation_id" "uuid",
    "conversation_created_at" timestamp with time zone,
    "conversation_updated_at" timestamp with time zone,
    "last_message_at" timestamp with time zone,
    "participant_1" "uuid",
    "participant_2" "uuid",
    "message_id" "uuid",
    "sender_id" "uuid",
    "recipient_id" "uuid",
    "content" "text",
    "message_created_at" timestamp with time zone,
    "message_updated_at" timestamp with time zone,
    "read_at" timestamp with time zone,
    "client_id" "uuid"
);


ALTER TABLE "public"."backup_bad_conversations_20250905" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."backup_bad_conversations_20250905_json" (
    "conversation_id" "uuid",
    "conversation" "json",
    "message" "json"
);


ALTER TABLE "public"."backup_bad_conversations_20250905_json" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."bookmarked_jobs" (
    "id" bigint NOT NULL,
    "user_id" "uuid" NOT NULL,
    "job_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."bookmarked_jobs" OWNER TO "postgres";


COMMENT ON TABLE "public"."bookmarked_jobs" IS 'Stores user bookmarks for job listings.';



COMMENT ON COLUMN "public"."bookmarked_jobs"."id" IS 'Unique identifier for the bookmark entry.';



COMMENT ON COLUMN "public"."bookmarked_jobs"."user_id" IS 'Foreign key referencing the user (from auth.users) who made the bookmark.';



COMMENT ON COLUMN "public"."bookmarked_jobs"."job_id" IS 'Foreign key referencing the bookmarked job (from public.jobs).';



COMMENT ON COLUMN "public"."bookmarked_jobs"."created_at" IS 'Timestamp of when the bookmark was created.';



ALTER TABLE "public"."bookmarked_jobs" ALTER COLUMN "id" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "public"."bookmarked_jobs_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."clarification_requests" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "comment" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."clarification_requests" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."companies" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "logo_url" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "created_by" "uuid"
);


ALTER TABLE "public"."companies" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."connections" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "requester_id" "uuid",
    "recipient_id" "uuid",
    "status" "text" DEFAULT 'pending'::"text",
    "created_at" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()),
    "updated_at" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()),
    CONSTRAINT "connections_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'accepted'::"text", 'rejected'::"text"]))),
    CONSTRAINT "different_requester_recipient" CHECK (("requester_id" <> "recipient_id"))
);


ALTER TABLE "public"."connections" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."content_approvals" (
    "id" bigint NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "content_type" "text" NOT NULL,
    "content_data" "jsonb",
    "creator_id" "uuid" NOT NULL,
    "reviewer_id" "uuid",
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "reviewed_at" timestamp with time zone,
    "rejection_reason" "text",
    CONSTRAINT "content_approvals_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'approved'::"text", 'rejected'::"text"])))
);


ALTER TABLE "public"."content_approvals" OWNER TO "postgres";


COMMENT ON TABLE "public"."content_approvals" IS 'Manages the approval workflow for user-submitted content like posts, comments, etc.';



COMMENT ON COLUMN "public"."content_approvals"."content_data" IS 'JSONB blob containing the content to be reviewed, e.g., post text or comment body.';



COMMENT ON COLUMN "public"."content_approvals"."creator_id" IS 'The ID of the user who submitted the content.';



ALTER TABLE "public"."content_approvals" ALTER COLUMN "id" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "public"."content_approvals_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."content_moderation" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "content_type" "text" NOT NULL,
    "content_id" "uuid" NOT NULL,
    "moderator_id" "uuid",
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "review_notes" "text",
    "reviewed_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."content_moderation" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."conversation_participants" (
    "conversation_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "joined_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."conversation_participants" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."conversations" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "last_message_at" timestamp with time zone DEFAULT "now"(),
    "participant_1" "uuid",
    "participant_2" "uuid"
);


ALTER TABLE "public"."conversations" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."csv_import_history" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "filename" "text" NOT NULL,
    "record_count" integer,
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "target_table" "text" NOT NULL,
    "error_details" "text",
    "mapping_config" "jsonb",
    "action_type" "text"
);


ALTER TABLE "public"."csv_import_history" OWNER TO "postgres";


COMMENT ON COLUMN "public"."csv_import_history"."action_type" IS 'Describes the action being logged (e.g. export, import, failed).';



CREATE TABLE IF NOT EXISTS "public"."degrees" (
    "code" "text" NOT NULL,
    "label" "text" NOT NULL
);


ALTER TABLE "public"."degrees" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."deletion_queue" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "reason" "text",
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "error" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "processed_at" timestamp with time zone
);


ALTER TABLE "public"."deletion_queue" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."event_feedback" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "event_id" "uuid",
    "user_id" "uuid",
    "rating" integer,
    "comments" "text",
    "submitted_at" timestamp with time zone DEFAULT "now"(),
    "created_at" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()),
    "comment" "text",
    "rsvp_status" "text",
    CONSTRAINT "event_feedback_rating_check" CHECK ((("rating" >= 1) AND ("rating" <= 5)))
);


ALTER TABLE "public"."event_feedback" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "title" "text" NOT NULL,
    "description" "text" NOT NULL,
    "start_date" timestamp with time zone NOT NULL,
    "end_date" timestamp with time zone NOT NULL,
    "venue" "text",
    "is_virtual" boolean DEFAULT false,
    "virtual_link" "text",
    "organizer_id" "uuid" NOT NULL,
    "featured_image_url" "text",
    "is_featured" boolean DEFAULT false,
    "category" "text" DEFAULT 'General'::"text" NOT NULL,
    "max_attendees" integer,
    "is_published" boolean DEFAULT false,
    "tags" "text"[],
    "slug" "text",
    "agenda" "jsonb",
    "event_type" "text" DEFAULT 'networking'::"text",
    "cost" "text",
    "sponsors" "text",
    "registration_url" "text",
    "registration_deadline" timestamp with time zone,
    "created_by" "uuid",
    "creator_id" "uuid",
    "virtual_meeting_link" "text",
    "user_id" "uuid",
    "is_approved" boolean DEFAULT false,
    "reminder_sent" boolean DEFAULT false,
    "address" "text",
    "organizer_email" "text",
    "organizer_name" "text",
    "organizer_phone" "text",
    "price" numeric,
    "price_type" "text",
    "long_description" "text",
    "requirements" "text"[],
    "amenities" "text"[],
    "gallery" "text"[],
    "status" "text" DEFAULT 'upcoming'::"text",
    "additional_info" "text",
    "requires_approval" boolean DEFAULT false,
    "is_public" boolean DEFAULT true,
    "registration_required" boolean DEFAULT true,
    "updated_by" "uuid",
    "location" "text",
    "rejection_reason" "text",
    "approval_status" "public"."approval_status" DEFAULT 'pending'::"public"."approval_status" NOT NULL,
    "reviewed_by" "uuid",
    "reviewed_at" timestamp with time zone,
    "group_id" "uuid",
    "short_description" "text",
    "is_rejected" boolean DEFAULT false
);


ALTER TABLE "public"."events" OWNER TO "postgres";


COMMENT ON COLUMN "public"."events"."is_published" IS 'Whether the event is published and visible to users';



COMMENT ON COLUMN "public"."events"."agenda" IS 'Event agenda or schedule of activities';



COMMENT ON COLUMN "public"."events"."rejection_reason" IS 'Reason provided by the admin for rejecting an event.';



COMMENT ON COLUMN "public"."events"."is_rejected" IS 'Flag to mark an event as rejected by an admin.';



CREATE OR REPLACE VIEW "public"."detailed_event_feedback" AS
 SELECT "ef"."id" AS "feedback_id",
    "ef"."rating",
    "ef"."comments",
    "ef"."submitted_at" AS "feedback_submitted_at",
    "ef"."event_id",
    "e"."title" AS "event_title",
    "ef"."user_id",
    "p"."full_name",
    "p"."avatar_url"
   FROM (("public"."event_feedback" "ef"
     JOIN "public"."events" "e" ON (("ef"."event_id" = "e"."id")))
     JOIN "public"."profiles" "p" ON (("ef"."user_id" = "p"."id")));


ALTER TABLE "public"."detailed_event_feedback" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."education_history" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "institution_name" "text" NOT NULL,
    "degree_type" "text" NOT NULL,
    "major" "text",
    "graduation_year" integer,
    "gpa" numeric(3,2),
    "honors" "text",
    "notable_achievements" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."education_history" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."event_attendees" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "event_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "attendance_status" "text" DEFAULT 'registered'::"text" NOT NULL,
    "check_in_time" timestamp with time zone,
    "attendee_id" "uuid",
    "registration_date" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"())
);


ALTER TABLE "public"."event_attendees" OWNER TO "postgres";


COMMENT ON TABLE "public"."event_attendees" IS 'Tracks user RSVPs for events.';



COMMENT ON COLUMN "public"."event_attendees"."attendance_status" IS 'The attendance status of the user for the event.';



CREATE OR REPLACE VIEW "public"."event_attendees_with_profiles" AS
 SELECT "ea"."id",
    "ea"."created_at",
    "ea"."event_id",
    "ea"."user_id",
    "ea"."attendance_status" AS "status",
    "ea"."check_in_time",
    "p"."id" AS "profile_id",
    "p"."full_name",
    "p"."avatar_url",
    "e"."title" AS "event_title",
    "e"."start_date" AS "event_start_date"
   FROM (("public"."event_attendees" "ea"
     JOIN "public"."profiles" "p" ON (("ea"."user_id" = "p"."id")))
     JOIN "public"."events" "e" ON (("ea"."event_id" = "e"."id")));


ALTER TABLE "public"."event_attendees_with_profiles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."event_groups" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "event_id" "uuid" NOT NULL,
    "group_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "created_by" "uuid"
);


ALTER TABLE "public"."event_groups" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."event_rsvps" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "event_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "attendance_status" "text"
);


ALTER TABLE "public"."event_rsvps" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."event_stats" AS
SELECT
    NULL::"uuid" AS "event_id",
    NULL::"text" AS "title",
    NULL::timestamp with time zone AS "start_date",
    NULL::timestamp with time zone AS "end_date",
    NULL::"text" AS "location",
    NULL::boolean AS "is_virtual",
    NULL::"text" AS "category",
    NULL::boolean AS "is_featured",
    NULL::boolean AS "is_published",
    NULL::integer AS "max_attendees",
    NULL::"uuid" AS "organizer_id",
    NULL::"text" AS "organizer_name",
    NULL::bigint AS "attendee_count",
    NULL::bigint AS "spots_remaining";


ALTER TABLE "public"."event_stats" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."feature_flags" (
    "key" "text" NOT NULL,
    "enabled" boolean DEFAULT false NOT NULL
);


ALTER TABLE "public"."feature_flags" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."group_members" (
    "group_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "role" "text" DEFAULT 'member'::"text" NOT NULL,
    "joined_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "group_members_role_check" CHECK (("role" = ANY (ARRAY['admin'::"text", 'member'::"text"])))
);


ALTER TABLE "public"."group_members" OWNER TO "postgres";


COMMENT ON TABLE "public"."group_members" IS 'Manages memberships and roles of users in groups.';



CREATE TABLE IF NOT EXISTS "public"."group_posts" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "group_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "parent_post_id" "uuid",
    "content" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "image_url" "text",
    "has_image" boolean DEFAULT false,
    "status" "text" DEFAULT 'approved'::"text",
    "title" "text"
);


ALTER TABLE "public"."group_posts" OWNER TO "postgres";


COMMENT ON TABLE "public"."group_posts" IS 'Stores posts, comments, and replies within networking groups.';



CREATE TABLE IF NOT EXISTS "public"."groups" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "is_private" boolean DEFAULT false NOT NULL,
    "group_avatar_url" "text",
    "tags" "text"[],
    "is_admin_only_posts" boolean DEFAULT false,
    "created_by_user_id" "uuid",
    "is_approved" boolean DEFAULT false NOT NULL,
    "approval_status" "public"."approval_status" DEFAULT 'pending'::"public"."approval_status" NOT NULL,
    "reviewed_by" "uuid",
    "reviewed_at" timestamp with time zone,
    "is_rejected" boolean DEFAULT false,
    "rejection_reason" "text",
    "name_norm" "text" GENERATED ALWAYS AS ("lower"("regexp_replace"("btrim"("name"), '\s+'::"text", ' '::"text", 'g'::"text"))) STORED
);


ALTER TABLE "public"."groups" OWNER TO "postgres";


COMMENT ON TABLE "public"."groups" IS 'Stores information about user-created networking groups.';



COMMENT ON COLUMN "public"."groups"."is_rejected" IS 'Flag to mark a group as rejected by an admin.';



COMMENT ON COLUMN "public"."groups"."rejection_reason" IS 'Reason provided by the admin for rejecting a group.';



CREATE TABLE IF NOT EXISTS "public"."job_alert_notifications" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "job_id" "uuid" NOT NULL,
    "alert_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "sent_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."job_alert_notifications" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."job_alerts" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "user_id" "uuid",
    "alert_name" "text" NOT NULL,
    "job_titles" "text"[],
    "industries" "text"[],
    "locations" "text"[],
    "job_types" "text"[],
    "min_salary" integer,
    "keywords" "text"[],
    "frequency" "text",
    "is_active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "job_type" "text",
    "location" "text",
    "max_salary" integer,
    "experience_level" "text",
    "desired_roles" "text"[],
    "desired_industries" "text"[],
    "alert_frequency" "text",
    "name" "text",
    CONSTRAINT "job_alerts_frequency_check" CHECK (("frequency" = ANY (ARRAY['daily'::"text", 'weekly'::"text", 'immediate'::"text"]))),
    CONSTRAINT "job_alerts_job_type_check" CHECK (("job_type" = ANY (ARRAY['full-time'::"text", 'part-time'::"text", 'contract'::"text", 'internship'::"text"])))
);


ALTER TABLE "public"."job_alerts" OWNER TO "postgres";


COMMENT ON TABLE "public"."job_alerts" IS 'trigger schema reload';



CREATE TABLE IF NOT EXISTS "public"."job_applications" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "job_id" "uuid",
    "applicant_id" "uuid",
    "resume_url" "text",
    "cover_letter" "text",
    "status" "text" DEFAULT 'submitted'::"text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "submitted_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "job_applications_status_check" CHECK (("status" = ANY (ARRAY['submitted'::"text", 'reviewed'::"text", 'interviewing'::"text", 'offered'::"text", 'rejected'::"text"])))
);


ALTER TABLE "public"."job_applications" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."job_bookmarks" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "job_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL
);


ALTER TABLE "public"."job_bookmarks" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."jobs" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "title" "text" NOT NULL,
    "company_name" "text",
    "location" "text",
    "job_type" "text",
    "description" "text",
    "requirements" "text",
    "salary_range" "text",
    "application_url" "text",
    "contact_email" "text",
    "expires_at" timestamp with time zone,
    "posted_by" "uuid" NOT NULL,
    "is_active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "education_required" "text",
    "required_skills" "text",
    "deadline" timestamp with time zone,
    "experience_required" "text",
    "education_level" "text",
    "external_url" "text",
    "industry" "text",
    "application_instructions" "text",
    "user_id" "uuid",
    "is_approved" boolean DEFAULT false,
    "company_id" "uuid",
    "apply_url" "text",
    "is_verified" boolean DEFAULT false NOT NULL,
    "created_by" "uuid",
    "primary_role" "text",
    "approval_status" "public"."approval_status" DEFAULT 'pending'::"public"."approval_status" NOT NULL,
    "reviewed_by" "uuid",
    "reviewed_at" timestamp with time zone,
    "is_rejected" boolean DEFAULT false,
    "rejection_reason" "text",
    "application_deadline" timestamp with time zone GENERATED ALWAYS AS ("deadline") STORED,
    "department" "text",
    "experience_level" "text",
    "salary_min" bigint,
    "salary_max" bigint,
    "skills" "text"[]
);

ALTER TABLE ONLY "public"."jobs" FORCE ROW LEVEL SECURITY;


ALTER TABLE "public"."jobs" OWNER TO "postgres";


COMMENT ON COLUMN "public"."jobs"."is_rejected" IS 'Flag to mark a job post as rejected by an admin.';



COMMENT ON COLUMN "public"."jobs"."rejection_reason" IS 'Reason provided by the admin for rejecting a job post.';



CREATE OR REPLACE VIEW "public"."job_postings" AS
 SELECT "jobs"."id",
    "jobs"."title",
    "jobs"."company_name",
    "jobs"."location",
    "jobs"."job_type",
    "jobs"."description",
    "jobs"."requirements",
    "jobs"."salary_range",
    "jobs"."application_url",
    "jobs"."contact_email",
    "jobs"."expires_at",
    "jobs"."posted_by",
    "jobs"."is_active",
    "jobs"."created_at",
    "jobs"."updated_at",
    "jobs"."education_required",
    "jobs"."required_skills",
    "jobs"."deadline",
    "jobs"."experience_required",
    "jobs"."education_level",
    "jobs"."external_url",
    "jobs"."industry",
    "jobs"."application_instructions",
    "jobs"."user_id",
    "jobs"."is_approved",
    "jobs"."company_id",
    "jobs"."apply_url",
    "jobs"."is_verified",
    "jobs"."created_by"
   FROM "public"."jobs";


ALTER TABLE "public"."job_postings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mentee_profiles" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "career_goals" "text",
    "areas_seeking_mentorship" "text"[],
    "specific_skills_to_develop" "text"[],
    "preferred_mentor_characteristics" "text"[],
    "time_commitment_available" "text",
    "preferred_communication_method" "text"[],
    "statement_of_expectations" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."mentee_profiles" OWNER TO "postgres";


COMMENT ON TABLE "public"."mentee_profiles" IS 'Stores detailed profiles for users who register as mentees.';



COMMENT ON COLUMN "public"."mentee_profiles"."user_id" IS 'Foreign key to the user''s main profile in public.profiles.';



COMMENT ON COLUMN "public"."mentee_profiles"."career_goals" IS 'Mentee''s stated career goals.';



COMMENT ON COLUMN "public"."mentee_profiles"."areas_seeking_mentorship" IS 'List of areas the mentee is seeking mentorship in.';



COMMENT ON COLUMN "public"."mentee_profiles"."specific_skills_to_develop" IS 'List of specific skills the mentee wants to develop.';



COMMENT ON COLUMN "public"."mentee_profiles"."preferred_mentor_characteristics" IS 'Characteristics the mentee prefers in a mentor.';



COMMENT ON COLUMN "public"."mentee_profiles"."time_commitment_available" IS 'Mentee''s available time commitment (e.g., hours per week/month).';



COMMENT ON COLUMN "public"."mentee_profiles"."preferred_communication_method" IS 'Mentee''s preferred methods of communication.';



COMMENT ON COLUMN "public"."mentee_profiles"."statement_of_expectations" IS 'Mentee''s brief statement of expectations from the mentorship.';



COMMENT ON COLUMN "public"."mentee_profiles"."created_at" IS 'Timestamp of when the mentee profile was created.';



COMMENT ON COLUMN "public"."mentee_profiles"."updated_at" IS 'Timestamp of when the mentee profile was last updated.';



CREATE TABLE IF NOT EXISTS "public"."mentees" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "user_id" "uuid",
    "status" "text" DEFAULT 'pending'::"text",
    "career_goals" "text",
    "preferred_industry" "text"[],
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "mentees_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'active'::"text", 'inactive'::"text"])))
);


ALTER TABLE "public"."mentees" OWNER TO "postgres";


COMMENT ON TABLE "public"."mentees" IS 'Stores mentee profiles and preferences';



CREATE TABLE IF NOT EXISTS "public"."mentor_availability" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "mentor_id" "uuid",
    "date" "date" NOT NULL,
    "start_time" time without time zone NOT NULL,
    "end_time" time without time zone NOT NULL,
    "is_booked" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "time_range_check" CHECK (("start_time" < "end_time"))
);


ALTER TABLE "public"."mentor_availability" OWNER TO "postgres";


COMMENT ON TABLE "public"."mentor_availability" IS 'Stores availability slots for mentors';



CREATE TABLE IF NOT EXISTS "public"."mentor_profiles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "mentoring_capacity_hours" integer DEFAULT 2,
    "areas_of_expertise" "text"[],
    "mentoring_preferences" "text",
    "mentoring_experience" "text",
    "mentoring_statement" "text",
    "max_mentees" integer DEFAULT 3,
    "is_accepting_mentees" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."mentor_profiles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mentors" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "user_id" "uuid",
    "status" "text" DEFAULT 'pending'::"text",
    "expertise" "text"[],
    "mentoring_experience_years" integer,
    "max_mentees" integer DEFAULT 5,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "mentoring_capacity_hours_per_month" integer,
    "mentoring_preferences" "jsonb",
    "mentoring_statement" "text",
    "mentoring_experience_description" "text",
    CONSTRAINT "mentors_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'approved'::"text", 'rejected'::"text"])))
);


ALTER TABLE "public"."mentors" OWNER TO "postgres";


COMMENT ON TABLE "public"."mentors" IS 'Stores mentor profiles and expertise';



CREATE TABLE IF NOT EXISTS "public"."mentorship_appointments" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "availability_id" "uuid",
    "mentee_id" "uuid",
    "topic" "text" NOT NULL,
    "notes" "text",
    "status" "text" DEFAULT 'scheduled'::"text",
    "feedback_provided" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "mentorship_appointments_status_check" CHECK (("status" = ANY (ARRAY['scheduled'::"text", 'completed'::"text", 'cancelled'::"text", 'no_show'::"text"])))
);


ALTER TABLE "public"."mentorship_appointments" OWNER TO "postgres";


COMMENT ON TABLE "public"."mentorship_appointments" IS 'Stores booked mentorship appointments';



CREATE TABLE IF NOT EXISTS "public"."mentorship_feedback" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "mentorship_request_id" "uuid",
    "submitted_by" "uuid",
    "rating" integer,
    "comments" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "mentorship_feedback_rating_check" CHECK ((("rating" >= 1) AND ("rating" <= 5)))
);


ALTER TABLE "public"."mentorship_feedback" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mentorship_messages" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "mentorship_request_id" "uuid",
    "sender_id" "uuid",
    "message" "text" NOT NULL,
    "sent_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."mentorship_messages" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mentorship_programs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "title" "text" NOT NULL,
    "description" "text",
    "start_date" timestamp with time zone,
    "end_date" timestamp with time zone,
    "is_active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."mentorship_programs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mentorship_relationships" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "program_id" "uuid",
    "mentor_id" "uuid",
    "mentee_id" "uuid",
    "status" "text" DEFAULT 'pending'::"text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "mentorship_relationships_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'active'::"text", 'completed'::"text", 'cancelled'::"text"])))
);


ALTER TABLE "public"."mentorship_relationships" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mentorship_requests" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "mentee_id" "uuid",
    "mentor_id" "uuid",
    "status" "text",
    "message" "text",
    "goals" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "mentorship_requests_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'accepted'::"text", 'rejected'::"text", 'completed'::"text"])))
);


ALTER TABLE "public"."mentorship_requests" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mentorship_sessions" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "mentorship_request_id" "uuid",
    "scheduled_time" timestamp with time zone NOT NULL,
    "duration_minutes" integer DEFAULT 30,
    "meeting_url" "text",
    "notes" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."mentorship_sessions" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."mentorship_stats" AS
 SELECT "count"(*) FILTER (WHERE ("mentorship_requests"."status" = 'approved'::"text")) AS "total_approved",
    "count"(*) FILTER (WHERE ("mentorship_requests"."status" = 'pending'::"text")) AS "pending_requests",
    "count"(*) FILTER (WHERE ("mentorship_requests"."status" = 'rejected'::"text")) AS "rejected_requests"
   FROM "public"."mentorship_requests";


ALTER TABLE "public"."mentorship_stats" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mentorships" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "mentor_id" "uuid" NOT NULL,
    "mentee_id" "uuid" NOT NULL,
    "status" "text" DEFAULT 'requested'::"text" NOT NULL,
    "goals" "text",
    CONSTRAINT "mentorships_status_check" CHECK (("status" = ANY (ARRAY['requested'::"text", 'active'::"text", 'completed'::"text", 'declined'::"text"])))
);


ALTER TABLE "public"."mentorships" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."messages" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "conversation_id" "uuid" NOT NULL,
    "sender_id" "uuid" NOT NULL,
    "content" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "read_at" timestamp with time zone,
    "recipient_id" "uuid",
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "client_id" "uuid",
    "client_uuid" "uuid",
    CONSTRAINT "messages_content_check" CHECK (("content" <> ''::"text"))
);


ALTER TABLE "public"."messages" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."networking_group_members" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "group_id" "uuid",
    "user_id" "uuid",
    "role" "text" DEFAULT 'member'::"text",
    "joined_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."networking_group_members" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."networking_groups" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "type" "text",
    "image_url" "text",
    "visibility" "text" DEFAULT 'public'::"text",
    "admin_user_ids" "uuid"[],
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."networking_groups" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."notification_preferences" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "notification_type" "text" NOT NULL,
    "email_enabled" boolean DEFAULT true,
    "push_enabled" boolean DEFAULT true,
    "in_app_enabled" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."notification_preferences" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."notifications" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "title" "text",
    "message" "text" NOT NULL,
    "link" "text",
    "is_read" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "type" "text" DEFAULT 'system'::"text" NOT NULL,
    "recipient_id" "uuid" NOT NULL,
    "sender_id" "uuid",
    "event_id" "uuid",
    "profile_id" "uuid",
    CONSTRAINT "chk_notifications_type" CHECK (("btrim"("lower"("type")) = ANY (ARRAY['system'::"text", 'message'::"text", 'event'::"text", 'event_created'::"text", 'event_published'::"text", 'event_updated'::"text", 'job'::"text", 'job_posted'::"text", 'job_approved'::"text", 'job_applied'::"text", 'application'::"text", 'application_status'::"text", 'mentorship'::"text", 'group'::"text", 'connection'::"text", 'resume'::"text", 'alert'::"text"])))
);


ALTER TABLE "public"."notifications" OWNER TO "postgres";


COMMENT ON TABLE "public"."notifications" IS 'Stores user notifications for the alumni management system';



CREATE TABLE IF NOT EXISTS "public"."permissions" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "created_at" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()) NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()) NOT NULL
);


ALTER TABLE "public"."permissions" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_profiles_view" AS
 SELECT "profiles"."id",
    "profiles"."first_name",
    "profiles"."last_name",
    "profiles"."full_name",
    "profiles"."avatar_url",
    "profiles"."graduation_year",
    "profiles"."degree_program",
    "profiles"."current_job_title",
    "profiles"."company_name",
    "profiles"."current_location" AS "location",
    "profiles"."social_links",
    "profiles"."headline",
    "profiles"."is_mentor",
    "profiles"."is_employer"
   FROM "public"."profiles";


ALTER TABLE "public"."public_profiles_view" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."resources" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "title" "text" NOT NULL,
    "description" "text",
    "url" "text",
    "resource_type" "text" NOT NULL,
    "created_by" "uuid",
    "is_approved" boolean DEFAULT false NOT NULL
);


ALTER TABLE "public"."resources" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."resume_profiles" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "resume_url" "text",
    "cover_letter_url" "text",
    "portfolio_link" "text",
    "linkedin_profile" "text",
    "desired_job_titles" "text"[],
    "desired_industries" "text"[],
    "preferred_locations" "text"[],
    "willing_to_relocate" boolean DEFAULT false,
    "job_alert_active" boolean DEFAULT true,
    "job_alert_frequency" "text" DEFAULT 'daily'::"text",
    "job_alert_keywords" "text"[],
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."resume_profiles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."role_permissions" (
    "role_id" "uuid" NOT NULL,
    "permission_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()) NOT NULL
);


ALTER TABLE "public"."role_permissions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."roles" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "permissions" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."roles" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."social_links" (
    "id" bigint NOT NULL,
    "profile_id" "uuid",
    "type" "public"."social_type" NOT NULL,
    "url" "text" NOT NULL,
    CONSTRAINT "chk_social_domain" CHECK (((("type" = 'linkedin'::"public"."social_type") AND ("url" ~* 'linkedin\\.com'::"text")) OR (("type" = 'github'::"public"."social_type") AND ("url" ~* 'github\\.com'::"text")) OR (("type" = 'x'::"public"."social_type") AND (("url" ~* 'x\\.com'::"text") OR ("url" ~* 'twitter\\.com'::"text"))) OR (("type" = 'instagram'::"public"."social_type") AND ("url" ~* 'instagram\\.com'::"text")) OR (("type" = 'facebook'::"public"."social_type") AND ("url" ~* 'facebook\\.com'::"text")) OR ("type" = 'website'::"public"."social_type")))
);


ALTER TABLE "public"."social_links" OWNER TO "postgres";


CREATE SEQUENCE IF NOT EXISTS "public"."social_links_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "public"."social_links_id_seq" OWNER TO "postgres";


ALTER SEQUENCE "public"."social_links_id_seq" OWNED BY "public"."social_links"."id";



CREATE TABLE IF NOT EXISTS "public"."system_alerts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "alert_type" "text" NOT NULL,
    "title" "text" NOT NULL,
    "message" "text" NOT NULL,
    "is_resolved" boolean DEFAULT false,
    "resolved_by" "uuid",
    "resolved_at" timestamp with time zone,
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."system_alerts" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."system_analytics" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "metric_name" "text" NOT NULL,
    "metric_value" numeric,
    "metric_type" "text",
    "tags" "jsonb",
    "recorded_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."system_analytics" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_activity_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "action" "text" NOT NULL,
    "resource_type" "text",
    "resource_id" "uuid",
    "metadata" "jsonb",
    "ip_address" "inet",
    "user_agent" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."user_activity_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_feedback" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "user_id" "uuid",
    "page" "text" NOT NULL,
    "feedback_type" "text" NOT NULL,
    "description" "text" NOT NULL,
    "screenshot_url" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "status" "text" DEFAULT 'pending'::"text" NOT NULL
);


ALTER TABLE "public"."user_feedback" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."user_jobs_with_bookmark" AS
 SELECT "j"."id",
    "j"."title",
    "j"."company_name",
    "j"."location",
    "j"."job_type",
    "j"."description",
    "j"."requirements",
    "j"."salary_range",
    "j"."application_url",
    "j"."contact_email",
    "j"."expires_at",
    "j"."posted_by",
    "j"."is_active",
    "j"."created_at",
    "j"."updated_at",
    "j"."education_required",
    "j"."required_skills",
    "j"."deadline",
    "j"."experience_required",
    "j"."education_level",
    "j"."external_url",
    "j"."industry",
    "j"."application_instructions",
    "j"."user_id",
    "j"."is_approved",
    "j"."company_id",
    "j"."apply_url",
    "j"."is_verified",
    "j"."created_by",
        CASE
            WHEN ("jb"."job_id" IS NOT NULL) THEN true
            ELSE false
        END AS "is_bookmarked",
    "jb"."created_at" AS "bookmarked_at",
    "jb"."user_id" AS "bookmarked_by"
   FROM ("public"."jobs" "j"
     LEFT JOIN "public"."job_bookmarks" "jb" ON (("j"."id" = "jb"."job_id")));


ALTER TABLE "public"."user_jobs_with_bookmark" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_resumes" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "filename" "text" NOT NULL,
    "file_url" "text" NOT NULL,
    "file_size" integer,
    "is_primary" boolean DEFAULT false,
    "uploaded_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."user_resumes" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_roles" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "profile_id" "uuid" NOT NULL,
    "role_id" "uuid" NOT NULL,
    "assigned_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."user_roles" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."v_profiles_directory_card" AS
 SELECT "p"."id",
    TRIM(BOTH FROM ((COALESCE("p"."first_name", ''::"text") || ' '::"text") || COALESCE("p"."last_name", ''::"text"))) AS "full_name",
    "p"."graduation_year",
    COALESCE(( SELECT ("pos"."value" ->> 'title'::"text")
           FROM "jsonb_array_elements"("p"."positions") "pos"("value")
          WHERE ((("pos"."value" ->> 'end_date'::"text") IS NULL) OR (("pos"."value" ->> 'end_date'::"text") = ''::"text"))
          ORDER BY ("pos"."value" ->> 'start_date'::"text") DESC NULLS LAST
         LIMIT 1), ( SELECT ("pos"."value" ->> 'title'::"text")
           FROM "jsonb_array_elements"("p"."positions") "pos"("value")
          ORDER BY ("pos"."value" ->> 'end_date'::"text") DESC NULLS LAST, ("pos"."value" ->> 'start_date'::"text") DESC NULLS LAST
         LIMIT 1)) AS "current_title",
    COALESCE(( SELECT ("pos"."value" ->> 'company'::"text")
           FROM "jsonb_array_elements"("p"."positions") "pos"("value")
          WHERE ((("pos"."value" ->> 'end_date'::"text") IS NULL) OR (("pos"."value" ->> 'end_date'::"text") = ''::"text"))
          ORDER BY ("pos"."value" ->> 'start_date'::"text") DESC NULLS LAST
         LIMIT 1), ( SELECT ("pos"."value" ->> 'company'::"text")
           FROM "jsonb_array_elements"("p"."positions") "pos"("value")
          ORDER BY ("pos"."value" ->> 'end_date'::"text") DESC NULLS LAST, ("pos"."value" ->> 'start_date'::"text") DESC NULLS LAST
         LIMIT 1)) AS "current_company",
    NULLIF("p"."profession", ''::"text") AS "profession",
    NULLIF(TRIM(BOTH FROM ((COALESCE("p"."location_city", ''::"text") ||
        CASE
            WHEN (("p"."location_city" IS NOT NULL) AND ("p"."location_city" <> ''::"text") AND ("p"."location_country" IS NOT NULL) AND ("p"."location_country" <> ''::"text")) THEN ', '::"text"
            ELSE ''::"text"
        END) || COALESCE("p"."location_country", ''::"text"))), ''::"text") AS "location_label",
    NULLIF(TRIM(BOTH FROM ((COALESCE("p"."degree", ''::"text") ||
        CASE
            WHEN (("p"."department" IS NOT NULL) AND ("p"."department" <> ''::"text")) THEN ', '::"text"
            ELSE ''::"text"
        END) || COALESCE("p"."department", ''::"text"))), ''::"text") AS "degree_department",
    "p"."skills",
    "p"."is_approved"
   FROM "public"."profiles" "p"
  WHERE (("p"."is_approved" = true) AND (COALESCE("p"."is_employer", false) = false) AND (COALESCE("p"."role", 'alumni'::"text") = ANY (ARRAY['alumni'::"text", 'user'::"text", 'student'::"text"])));


ALTER TABLE "public"."v_profiles_directory_card" OWNER TO "postgres";


ALTER TABLE ONLY "public"."social_links" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."social_links_id_seq"'::"regclass");



ALTER TABLE ONLY "public"."achievements"
    ADD CONSTRAINT "achievements_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."activity_log"
    ADD CONSTRAINT "activity_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."activity_logs"
    ADD CONSTRAINT "activity_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."admin_actions"
    ADD CONSTRAINT "admin_actions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."admin_invalid_degree_programs_audit"
    ADD CONSTRAINT "admin_invalid_degree_programs_audit_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."bookmarked_jobs"
    ADD CONSTRAINT "bookmarked_jobs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."clarification_requests"
    ADD CONSTRAINT "clarification_requests_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."companies"
    ADD CONSTRAINT "companies_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."companies"
    ADD CONSTRAINT "companies_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."connections"
    ADD CONSTRAINT "connections_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."connections"
    ADD CONSTRAINT "connections_requester_id_recipient_id_key" UNIQUE ("requester_id", "recipient_id");



ALTER TABLE ONLY "public"."content_approvals"
    ADD CONSTRAINT "content_approvals_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."content_moderation"
    ADD CONSTRAINT "content_moderation_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."conversation_participants"
    ADD CONSTRAINT "conversation_participants_pkey" PRIMARY KEY ("conversation_id", "user_id");



ALTER TABLE ONLY "public"."conversations"
    ADD CONSTRAINT "conversations_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."csv_import_history"
    ADD CONSTRAINT "csv_import_history_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."degrees"
    ADD CONSTRAINT "degrees_pkey" PRIMARY KEY ("code");



ALTER TABLE ONLY "public"."deletion_queue"
    ADD CONSTRAINT "deletion_queue_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."education_history"
    ADD CONSTRAINT "education_history_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."event_attendees"
    ADD CONSTRAINT "event_attendees_event_id_attendee_id_key" UNIQUE ("event_id", "attendee_id");



ALTER TABLE ONLY "public"."event_attendees"
    ADD CONSTRAINT "event_attendees_event_id_user_id_key" UNIQUE ("event_id", "user_id");



ALTER TABLE ONLY "public"."event_attendees"
    ADD CONSTRAINT "event_attendees_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."event_feedback"
    ADD CONSTRAINT "event_feedback_event_id_user_id_key" UNIQUE ("event_id", "user_id");



ALTER TABLE ONLY "public"."event_feedback"
    ADD CONSTRAINT "event_feedback_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."event_groups"
    ADD CONSTRAINT "event_groups_event_id_group_id_key" UNIQUE ("event_id", "group_id");



ALTER TABLE ONLY "public"."event_groups"
    ADD CONSTRAINT "event_groups_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."event_rsvps"
    ADD CONSTRAINT "event_rsvps_event_id_user_id_key" UNIQUE ("event_id", "user_id");



ALTER TABLE ONLY "public"."event_rsvps"
    ADD CONSTRAINT "event_rsvps_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_slug_unique" UNIQUE ("slug");



ALTER TABLE ONLY "public"."feature_flags"
    ADD CONSTRAINT "feature_flags_pkey" PRIMARY KEY ("key");



ALTER TABLE ONLY "public"."group_members"
    ADD CONSTRAINT "group_members_pkey" PRIMARY KEY ("group_id", "user_id");



ALTER TABLE ONLY "public"."group_posts"
    ADD CONSTRAINT "group_posts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."groups"
    ADD CONSTRAINT "groups_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."job_alert_notifications"
    ADD CONSTRAINT "job_alert_notifications_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."job_alerts"
    ADD CONSTRAINT "job_alerts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."job_applications"
    ADD CONSTRAINT "job_applications_job_id_applicant_id_key" UNIQUE ("job_id", "applicant_id");



ALTER TABLE ONLY "public"."job_applications"
    ADD CONSTRAINT "job_applications_job_user_unq" UNIQUE ("job_id", "applicant_id");



ALTER TABLE ONLY "public"."job_applications"
    ADD CONSTRAINT "job_applications_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."job_bookmarks"
    ADD CONSTRAINT "job_bookmarks_job_id_user_id_key" UNIQUE ("job_id", "user_id");



ALTER TABLE ONLY "public"."job_bookmarks"
    ADD CONSTRAINT "job_bookmarks_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."jobs"
    ADD CONSTRAINT "jobs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentee_profiles"
    ADD CONSTRAINT "mentee_profiles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentees"
    ADD CONSTRAINT "mentees_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentor_availability"
    ADD CONSTRAINT "mentor_availability_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentor_profiles"
    ADD CONSTRAINT "mentor_profiles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentors"
    ADD CONSTRAINT "mentors_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentors"
    ADD CONSTRAINT "mentors_user_unique" UNIQUE ("user_id");



ALTER TABLE ONLY "public"."mentorship_appointments"
    ADD CONSTRAINT "mentorship_appointments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentorship_feedback"
    ADD CONSTRAINT "mentorship_feedback_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentorship_messages"
    ADD CONSTRAINT "mentorship_messages_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentorship_programs"
    ADD CONSTRAINT "mentorship_programs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentorship_relationships"
    ADD CONSTRAINT "mentorship_relationships_mentor_id_mentee_id_program_id_key" UNIQUE ("mentor_id", "mentee_id", "program_id");



ALTER TABLE ONLY "public"."mentorship_relationships"
    ADD CONSTRAINT "mentorship_relationships_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentorship_requests"
    ADD CONSTRAINT "mentorship_requests_mentee_id_mentor_id_key" UNIQUE ("mentee_id", "mentor_id");



ALTER TABLE ONLY "public"."mentorship_requests"
    ADD CONSTRAINT "mentorship_requests_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentorship_sessions"
    ADD CONSTRAINT "mentorship_sessions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentorships"
    ADD CONSTRAINT "mentorships_mentor_id_mentee_id_key" UNIQUE ("mentor_id", "mentee_id");



ALTER TABLE ONLY "public"."mentorships"
    ADD CONSTRAINT "mentorships_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."messages"
    ADD CONSTRAINT "messages_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."networking_group_members"
    ADD CONSTRAINT "networking_group_members_group_id_user_id_key" UNIQUE ("group_id", "user_id");



ALTER TABLE ONLY "public"."networking_group_members"
    ADD CONSTRAINT "networking_group_members_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."networking_groups"
    ADD CONSTRAINT "networking_groups_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."notification_preferences"
    ADD CONSTRAINT "notification_preferences_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."notification_preferences"
    ADD CONSTRAINT "notification_preferences_user_id_notification_type_key" UNIQUE ("user_id", "notification_type");



ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "notifications_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."permissions"
    ADD CONSTRAINT "permissions_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."permissions"
    ADD CONSTRAINT "permissions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_email_key" UNIQUE ("email");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."resources"
    ADD CONSTRAINT "resources_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."resume_profiles"
    ADD CONSTRAINT "resume_profiles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."role_permissions"
    ADD CONSTRAINT "role_permissions_pkey" PRIMARY KEY ("role_id", "permission_id");



ALTER TABLE ONLY "public"."roles"
    ADD CONSTRAINT "roles_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."roles"
    ADD CONSTRAINT "roles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."social_links"
    ADD CONSTRAINT "social_links_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."social_links"
    ADD CONSTRAINT "social_links_profile_id_type_key" UNIQUE ("profile_id", "type");



ALTER TABLE ONLY "public"."system_alerts"
    ADD CONSTRAINT "system_alerts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."system_analytics"
    ADD CONSTRAINT "system_analytics_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."bookmarked_jobs"
    ADD CONSTRAINT "unique_user_job_bookmark" UNIQUE ("user_id", "job_id");



ALTER TABLE ONLY "public"."groups"
    ADD CONSTRAINT "uq_groups_name_norm" UNIQUE ("name_norm");



ALTER TABLE ONLY "public"."user_activity_logs"
    ADD CONSTRAINT "user_activity_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_feedback"
    ADD CONSTRAINT "user_feedback_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mentee_profiles"
    ADD CONSTRAINT "user_id_unique_mentee_profile" UNIQUE ("user_id");



ALTER TABLE ONLY "public"."user_resumes"
    ADD CONSTRAINT "user_resumes_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_profile_id_role_id_key" UNIQUE ("profile_id", "role_id");



CREATE INDEX "event_attendees_event_id_idx" ON "public"."event_attendees" USING "btree" ("event_id");



CREATE INDEX "event_attendees_status_idx" ON "public"."event_attendees" USING "btree" ("attendance_status");



CREATE INDEX "event_attendees_user_id_idx" ON "public"."event_attendees" USING "btree" ("user_id");



CREATE INDEX "events_category_idx" ON "public"."events" USING "btree" ("category");



CREATE INDEX "events_is_featured_idx" ON "public"."events" USING "btree" ("is_featured");



CREATE INDEX "events_is_published_idx" ON "public"."events" USING "btree" ("is_published");



CREATE INDEX "events_organizer_id_idx" ON "public"."events" USING "btree" ("organizer_id");



CREATE INDEX "events_start_date_idx" ON "public"."events" USING "btree" ("start_date");



CREATE INDEX "idx_admin_actions_admin_id" ON "public"."admin_actions" USING "btree" ("admin_id");



CREATE INDEX "idx_admin_actions_created_at" ON "public"."admin_actions" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_connections_recipient_id" ON "public"."connections" USING "btree" ("recipient_id");



CREATE INDEX "idx_connections_requester_id" ON "public"."connections" USING "btree" ("requester_id");



CREATE INDEX "idx_connections_status" ON "public"."connections" USING "btree" ("status");



CREATE INDEX "idx_content_approvals_creator_id" ON "public"."content_approvals" USING "btree" ("creator_id");



CREATE INDEX "idx_content_approvals_status" ON "public"."content_approvals" USING "btree" ("status");



CREATE INDEX "idx_content_moderation_content_type" ON "public"."content_moderation" USING "btree" ("content_type");



CREATE INDEX "idx_content_moderation_status" ON "public"."content_moderation" USING "btree" ("status");



CREATE INDEX "idx_conversation_participants_conversation_id" ON "public"."conversation_participants" USING "btree" ("conversation_id");



CREATE INDEX "idx_conversation_participants_user_id" ON "public"."conversation_participants" USING "btree" ("user_id");



CREATE INDEX "idx_deletion_queue_status" ON "public"."deletion_queue" USING "btree" ("status");



CREATE INDEX "idx_event_attendees_attendee" ON "public"."event_attendees" USING "btree" ("user_id");



CREATE INDEX "idx_event_attendees_event_id" ON "public"."event_attendees" USING "btree" ("event_id");



CREATE INDEX "idx_events_category" ON "public"."events" USING "btree" ("category");



CREATE INDEX "idx_events_event_type" ON "public"."events" USING "btree" ("event_type");



CREATE INDEX "idx_events_group_id" ON "public"."events" USING "btree" ("group_id");



CREATE INDEX "idx_events_is_published" ON "public"."events" USING "btree" ("is_published");



CREATE INDEX "idx_events_organizer_id" ON "public"."events" USING "btree" ("organizer_id");



CREATE INDEX "idx_events_start_date" ON "public"."events" USING "btree" ("start_date");



CREATE INDEX "idx_events_tags" ON "public"."events" USING "gin" ("tags");



CREATE INDEX "idx_events_user_id" ON "public"."events" USING "btree" ("user_id");



CREATE INDEX "idx_group_members_group_id" ON "public"."group_members" USING "btree" ("group_id");



CREATE INDEX "idx_group_members_user_id" ON "public"."group_members" USING "btree" ("user_id");



CREATE INDEX "idx_group_posts_group_id" ON "public"."group_posts" USING "btree" ("group_id");



CREATE INDEX "idx_groups_is_private" ON "public"."groups" USING "btree" ("is_private");



CREATE INDEX "idx_job_applications_applicant_id" ON "public"."job_applications" USING "btree" ("applicant_id");



CREATE INDEX "idx_job_applications_job" ON "public"."job_applications" USING "btree" ("job_id");



CREATE INDEX "idx_job_applications_job_id" ON "public"."job_applications" USING "btree" ("job_id");



CREATE INDEX "idx_job_bookmarks_job_id" ON "public"."job_bookmarks" USING "btree" ("job_id");



CREATE INDEX "idx_job_bookmarks_user_id" ON "public"."job_bookmarks" USING "btree" ("user_id");



CREATE INDEX "idx_job_bookmarks_user_job" ON "public"."job_bookmarks" USING "btree" ("user_id", "job_id");



CREATE INDEX "idx_jobs_approved_active" ON "public"."jobs" USING "btree" ("is_approved", "is_active");



CREATE INDEX "idx_jobs_company_id" ON "public"."jobs" USING "btree" ("company_id");



CREATE INDEX "idx_jobs_is_active" ON "public"."jobs" USING "btree" ("is_active");



CREATE INDEX "idx_jobs_job_type" ON "public"."jobs" USING "btree" ("job_type");



CREATE INDEX "idx_jobs_posted_by" ON "public"."jobs" USING "btree" ("posted_by");



CREATE INDEX "idx_jobs_visibility" ON "public"."jobs" USING "btree" ("is_active", "is_approved", "posted_by");



CREATE INDEX "idx_mentorship_requests_mentee_id" ON "public"."mentorship_requests" USING "btree" ("mentee_id");



CREATE INDEX "idx_mentorship_requests_mentor_id" ON "public"."mentorship_requests" USING "btree" ("mentor_id");



CREATE INDEX "idx_mentorship_requests_status" ON "public"."mentorship_requests" USING "btree" ("status");



CREATE INDEX "idx_messages_on_conversation_id" ON "public"."messages" USING "btree" ("conversation_id");



CREATE INDEX "idx_notifications_event_id" ON "public"."notifications" USING "btree" ("event_id");



CREATE INDEX "idx_notifications_inbox" ON "public"."notifications" USING "btree" ("recipient_id", "is_read", "created_at" DESC);



CREATE INDEX "idx_notifications_profile_id" ON "public"."notifications" USING "btree" ("profile_id");



CREATE INDEX "idx_notifications_recipient_id" ON "public"."notifications" USING "btree" ("recipient_id");



CREATE INDEX "idx_notifications_recipient_type_unread" ON "public"."notifications" USING "btree" ("recipient_id", "type") WHERE ("is_read" = false);



CREATE INDEX "idx_notifications_recipient_unread" ON "public"."notifications" USING "btree" ("recipient_id") WHERE ("is_read" = false);



CREATE INDEX "idx_notifications_sender_id" ON "public"."notifications" USING "btree" ("sender_id");



CREATE INDEX "idx_profiles_achievements_gin" ON "public"."profiles" USING "gin" ("achievements");



CREATE INDEX "idx_profiles_graduation_year" ON "public"."profiles" USING "btree" ("graduation_year");



CREATE INDEX "idx_profiles_interests_gin" ON "public"."profiles" USING "gin" ("interests");



CREATE INDEX "idx_profiles_is_mentor" ON "public"."profiles" USING "btree" ("is_mentor");



CREATE INDEX "idx_profiles_location" ON "public"."profiles" USING "btree" ("location");



CREATE INDEX "idx_profiles_major" ON "public"."profiles" USING "btree" ("major");



CREATE INDEX "idx_profiles_skills_gin" ON "public"."profiles" USING "gin" ("skills");



CREATE INDEX "idx_relationships_mentee_id" ON "public"."mentorship_relationships" USING "btree" ("mentee_id");



CREATE INDEX "idx_relationships_mentor_id" ON "public"."mentorship_relationships" USING "btree" ("mentor_id");



CREATE INDEX "idx_system_alerts_created_at" ON "public"."system_alerts" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_system_alerts_is_resolved" ON "public"."system_alerts" USING "btree" ("is_resolved");



CREATE INDEX "mentees_status_idx" ON "public"."mentees" USING "btree" ("status");



CREATE INDEX "mentees_user_id_idx" ON "public"."mentees" USING "btree" ("user_id");



CREATE INDEX "mentor_availability_date_idx" ON "public"."mentor_availability" USING "btree" ("date");



CREATE INDEX "mentor_availability_is_booked_idx" ON "public"."mentor_availability" USING "btree" ("is_booked");



CREATE INDEX "mentor_availability_mentor_id_idx" ON "public"."mentor_availability" USING "btree" ("mentor_id");



CREATE INDEX "mentors_status_idx" ON "public"."mentors" USING "btree" ("status");



CREATE INDEX "mentors_user_id_idx" ON "public"."mentors" USING "btree" ("user_id");



CREATE INDEX "mentorship_appointments_availability_id_idx" ON "public"."mentorship_appointments" USING "btree" ("availability_id");



CREATE INDEX "mentorship_appointments_created_at_idx" ON "public"."mentorship_appointments" USING "btree" ("created_at");



CREATE INDEX "mentorship_appointments_mentee_id_idx" ON "public"."mentorship_appointments" USING "btree" ("mentee_id");



CREATE INDEX "mentorship_appointments_status_idx" ON "public"."mentorship_appointments" USING "btree" ("status");



CREATE INDEX "mentorship_sessions_request_id_idx" ON "public"."mentorship_sessions" USING "btree" ("mentorship_request_id");



CREATE INDEX "mentorship_sessions_scheduled_time_idx" ON "public"."mentorship_sessions" USING "btree" ("scheduled_time");



CREATE UNIQUE INDEX "messages_client_uuid_unique" ON "public"."messages" USING "btree" ("client_uuid") WHERE ("client_uuid" IS NOT NULL);



CREATE INDEX "notifications_created_at_idx" ON "public"."notifications" USING "btree" ("created_at");



CREATE INDEX "notifications_is_read_idx" ON "public"."notifications" USING "btree" ("is_read");



CREATE UNIQUE INDEX "uq_groups_name_norm_idx" ON "public"."groups" USING "btree" ("lower"("regexp_replace"("btrim"("name"), '\s+'::"text", ' '::"text", 'g'::"text"))) WHERE ("name" IS NOT NULL);



CREATE UNIQUE INDEX "uq_profiles_email_lower" ON "public"."profiles" USING "btree" ("lower"("email"));



CREATE UNIQUE INDEX "ux_messages_client_id" ON "public"."messages" USING "btree" ("client_id");



CREATE OR REPLACE VIEW "public"."event_stats" AS
 SELECT "e"."id" AS "event_id",
    "e"."title",
    "e"."start_date",
    "e"."end_date",
    "e"."venue" AS "location",
    "e"."is_virtual",
    "e"."category",
    "e"."is_featured",
    "e"."is_published",
    "e"."max_attendees",
    "e"."organizer_id",
    "p"."full_name" AS "organizer_name",
    "count"("ea"."id") AS "attendee_count",
        CASE
            WHEN ("e"."max_attendees" IS NOT NULL) THEN GREATEST((0)::bigint, ("e"."max_attendees" - "count"("ea"."id")))
            ELSE NULL::bigint
        END AS "spots_remaining"
   FROM (("public"."events" "e"
     LEFT JOIN "public"."event_attendees" "ea" ON (("e"."id" = "ea"."event_id")))
     LEFT JOIN "public"."profiles" "p" ON (("e"."organizer_id" = "p"."id")))
  GROUP BY "e"."id", "p"."full_name";



CREATE OR REPLACE TRIGGER "enforce_bookmark_limit" BEFORE INSERT ON "public"."job_bookmarks" FOR EACH ROW EXECUTE FUNCTION "public"."check_bookmark_limit"();



CREATE OR REPLACE TRIGGER "event_update_notify" AFTER INSERT OR DELETE OR UPDATE ON "public"."events" FOR EACH ROW EXECUTE FUNCTION "public"."event_changes_broadcast"();



CREATE OR REPLACE TRIGGER "handle_event_attendees_updated_at" BEFORE UPDATE ON "public"."event_attendees" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "handle_updated_at" BEFORE UPDATE ON "public"."companies" FOR EACH ROW EXECUTE FUNCTION "public"."moddatetime"('updated_at');



CREATE OR REPLACE TRIGGER "handle_updated_at_connections" BEFORE UPDATE ON "public"."connections" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "handle_updated_at_events" BEFORE UPDATE ON "public"."events" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "handle_updated_at_jobs" BEFORE UPDATE ON "public"."jobs" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "handle_updated_at_mentorship_requests" BEFORE UPDATE ON "public"."mentorship_requests" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "handle_updated_at_profiles" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "limit_bookmarks" BEFORE INSERT ON "public"."job_bookmarks" FOR EACH ROW EXECUTE FUNCTION "public"."check_bookmark_limit"();



CREATE OR REPLACE TRIGGER "mentorship_chat_trigger" AFTER INSERT ON "public"."mentorship_relationships" FOR EACH ROW EXECUTE FUNCTION "public"."auto_conversation_on_match"();



CREATE OR REPLACE TRIGGER "on_group_created" AFTER INSERT ON "public"."groups" FOR EACH ROW EXECUTE FUNCTION "public"."handle_new_group"();



CREATE OR REPLACE TRIGGER "on_group_posts_update" BEFORE UPDATE ON "public"."group_posts" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "on_groups_update" BEFORE UPDATE ON "public"."groups" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "on_mentee_profiles_updated" BEFORE UPDATE ON "public"."mentee_profiles" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "on_new_message" AFTER INSERT ON "public"."messages" FOR EACH ROW EXECUTE FUNCTION "public"."update_conversation_updated_at"();



CREATE OR REPLACE TRIGGER "on_new_message_update_conversation_timestamp" AFTER INSERT ON "public"."messages" FOR EACH ROW EXECUTE FUNCTION "public"."update_conversation_last_message_at"();



CREATE OR REPLACE TRIGGER "protect_jobs_admin_columns_trg" BEFORE UPDATE ON "public"."jobs" FOR EACH ROW EXECUTE FUNCTION "public"."protect_jobs_admin_columns"();



CREATE OR REPLACE TRIGGER "protect_mentors_admin_columns_trg" BEFORE UPDATE ON "public"."mentors" FOR EACH ROW EXECUTE FUNCTION "public"."protect_mentors_admin_columns"();



CREATE OR REPLACE TRIGGER "protect_profile_admin_columns_trg" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."protect_profile_admin_columns"();



CREATE OR REPLACE TRIGGER "set_job_owner_default_trg" BEFORE INSERT ON "public"."jobs" FOR EACH ROW EXECUTE FUNCTION "public"."set_job_owner_default"();



CREATE OR REPLACE TRIGGER "set_mentees_updated_at" BEFORE UPDATE ON "public"."mentees" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "set_mentorship_sessions_updated_at" BEFORE UPDATE ON "public"."mentorship_sessions" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "set_requests_updated_at" BEFORE UPDATE ON "public"."mentorship_requests" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "set_sessions_updated_at" BEFORE UPDATE ON "public"."mentorship_sessions" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "set_user_id_on_group_members" BEFORE INSERT ON "public"."group_members" FOR EACH ROW EXECUTE FUNCTION "public"."set_group_member_user_id"();



CREATE OR REPLACE TRIGGER "tr_add_group_creator" AFTER INSERT ON "public"."groups" FOR EACH ROW EXECUTE FUNCTION "public"."fn_add_group_creator"();



CREATE OR REPLACE TRIGGER "trg_add_creator_as_group_admin" AFTER INSERT ON "public"."groups" FOR EACH ROW EXECUTE FUNCTION "public"."add_creator_as_group_admin"();



CREATE OR REPLACE TRIGGER "trg_events_set_owner" BEFORE INSERT OR UPDATE ON "public"."events" FOR EACH ROW EXECUTE FUNCTION "public"."events_set_owner"();



CREATE OR REPLACE TRIGGER "trg_notify_admins_event" AFTER INSERT ON "public"."events" FOR EACH ROW EXECUTE FUNCTION "public"."notify_admins_on_event"();



CREATE OR REPLACE TRIGGER "trg_notify_admins_on_event" AFTER INSERT ON "public"."events" FOR EACH ROW EXECUTE FUNCTION "public"."notify_admins_on_event"();



CREATE OR REPLACE TRIGGER "trg_notify_connection_approved" AFTER UPDATE ON "public"."connections" FOR EACH ROW WHEN (("old"."status" IS DISTINCT FROM "new"."status")) EXECUTE FUNCTION "public"."notify_connection_approved"();



CREATE OR REPLACE TRIGGER "trg_notify_connection_request" AFTER INSERT ON "public"."connections" FOR EACH ROW EXECUTE FUNCTION "public"."notify_new_connection_request"();



CREATE OR REPLACE TRIGGER "trg_notify_event_rsvp" AFTER INSERT ON "public"."event_rsvps" FOR EACH ROW EXECUTE FUNCTION "public"."notify_event_rsvp"();



CREATE OR REPLACE TRIGGER "trg_notify_job_application_submitted" AFTER INSERT ON "public"."job_applications" FOR EACH ROW EXECUTE FUNCTION "public"."notify_job_application_submitted"();



CREATE OR REPLACE TRIGGER "trg_notify_mentorship_request" AFTER INSERT ON "public"."mentorship_requests" FOR EACH ROW EXECUTE FUNCTION "public"."notify_mentorship_request"();



CREATE OR REPLACE TRIGGER "trg_profiles_after_insert_batch" AFTER INSERT ON "public"."profiles" FOR EACH ROW WHEN (("new"."is_approved" IS TRUE)) EXECUTE FUNCTION "public"."trg_attach_user_to_batch_group"();



CREATE OR REPLACE TRIGGER "trg_profiles_after_update_batch" AFTER UPDATE OF "alumni_verification_status" ON "public"."profiles" FOR EACH ROW WHEN ((("new"."alumni_verification_status" = 'approved'::"text") AND ("old"."alumni_verification_status" IS DISTINCT FROM 'approved'::"text"))) EXECUTE FUNCTION "public"."trg_attach_user_to_batch_group"();



CREATE OR REPLACE TRIGGER "trg_profiles_after_update_batch_canonical" AFTER UPDATE OF "approval_status", "is_approved" ON "public"."profiles" FOR EACH ROW WHEN ((("new"."is_approved" IS TRUE) AND ("old"."is_approved" IS DISTINCT FROM true))) EXECUTE FUNCTION "public"."trg_attach_user_to_batch_group"();



CREATE OR REPLACE TRIGGER "trg_profiles_sync_is_approved" BEFORE INSERT OR UPDATE OF "approval_status" ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."sync_is_approved_from_status"();



CREATE OR REPLACE TRIGGER "trg_profiles_upper" BEFORE INSERT OR UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."profiles_normalize_names"();



CREATE OR REPLACE TRIGGER "trg_set_group_creator" BEFORE INSERT ON "public"."groups" FOR EACH ROW EXECUTE FUNCTION "public"."set_group_creator"();



CREATE OR REPLACE TRIGGER "trg_update_conversation_last_message" AFTER INSERT ON "public"."messages" FOR EACH ROW EXECUTE FUNCTION "public"."update_conversation_last_message"();



CREATE OR REPLACE TRIGGER "update_achievements_updated_at" BEFORE UPDATE ON "public"."achievements" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at"();



CREATE OR REPLACE TRIGGER "update_csv_import_history_updated_at" BEFORE UPDATE ON "public"."csv_import_history" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "update_event_attendees_updated_at" BEFORE UPDATE ON "public"."event_attendees" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at"();



CREATE OR REPLACE TRIGGER "update_events_updated_at" BEFORE UPDATE ON "public"."events" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_full_name_trigger" BEFORE INSERT OR UPDATE OF "first_name", "last_name" ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."update_full_name"();



CREATE OR REPLACE TRIGGER "update_job_alerts_updated_at" BEFORE UPDATE ON "public"."job_alerts" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_job_applications_updated_at" BEFORE UPDATE ON "public"."job_applications" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at"();



CREATE OR REPLACE TRIGGER "update_mentees_updated_at" BEFORE UPDATE ON "public"."mentees" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_mentor_availability_updated_at" BEFORE UPDATE ON "public"."mentor_availability" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_mentor_profiles_updated_at" BEFORE UPDATE ON "public"."mentor_profiles" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_mentors_updated_at" BEFORE UPDATE ON "public"."mentors" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_mentorship_appointments_updated_at" BEFORE UPDATE ON "public"."mentorship_appointments" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_mentorship_programs_updated_at" BEFORE UPDATE ON "public"."mentorship_programs" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at"();



CREATE OR REPLACE TRIGGER "update_mentorship_relationships_updated_at" BEFORE UPDATE ON "public"."mentorship_relationships" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at"();



CREATE OR REPLACE TRIGGER "update_profiles_updated_at" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "validate_event_feedback" BEFORE INSERT ON "public"."event_feedback" FOR EACH ROW EXECUTE FUNCTION "public"."check_event_completed"();



CREATE OR REPLACE TRIGGER "validate_profile_fields_trigger" BEFORE INSERT OR UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."validate_profile_fields"();



ALTER TABLE ONLY "public"."achievements"
    ADD CONSTRAINT "achievements_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."activity_log"
    ADD CONSTRAINT "activity_log_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."activity_logs"
    ADD CONSTRAINT "activity_logs_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."admin_actions"
    ADD CONSTRAINT "admin_actions_admin_id_fkey" FOREIGN KEY ("admin_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."bookmarked_jobs"
    ADD CONSTRAINT "bookmarked_jobs_job_id_fkey" FOREIGN KEY ("job_id") REFERENCES "public"."jobs"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."bookmarked_jobs"
    ADD CONSTRAINT "bookmarked_jobs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."clarification_requests"
    ADD CONSTRAINT "clarification_requests_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."companies"
    ADD CONSTRAINT "companies_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."connections"
    ADD CONSTRAINT "connections_recipient_id_fkey" FOREIGN KEY ("recipient_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."connections"
    ADD CONSTRAINT "connections_requester_id_fkey" FOREIGN KEY ("requester_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."content_approvals"
    ADD CONSTRAINT "content_approvals_creator_id_fkey" FOREIGN KEY ("creator_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."content_approvals"
    ADD CONSTRAINT "content_approvals_reviewer_id_fkey" FOREIGN KEY ("reviewer_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."content_moderation"
    ADD CONSTRAINT "content_moderation_moderator_id_fkey" FOREIGN KEY ("moderator_id") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."conversation_participants"
    ADD CONSTRAINT "conversation_participants_conversation_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "public"."conversations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."conversation_participants"
    ADD CONSTRAINT "conversation_participants_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."conversations"
    ADD CONSTRAINT "conversations_participant_1_fkey" FOREIGN KEY ("participant_1") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."conversations"
    ADD CONSTRAINT "conversations_participant_2_fkey" FOREIGN KEY ("participant_2") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."csv_import_history"
    ADD CONSTRAINT "csv_import_history_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."education_history"
    ADD CONSTRAINT "education_history_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."event_attendees"
    ADD CONSTRAINT "event_attendees_attendee_id_fkey" FOREIGN KEY ("attendee_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."event_attendees"
    ADD CONSTRAINT "event_attendees_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "public"."events"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."event_attendees"
    ADD CONSTRAINT "event_attendees_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."event_feedback"
    ADD CONSTRAINT "event_feedback_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "public"."events"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."event_feedback"
    ADD CONSTRAINT "event_feedback_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."event_groups"
    ADD CONSTRAINT "event_groups_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."event_groups"
    ADD CONSTRAINT "event_groups_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "public"."events"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."event_rsvps"
    ADD CONSTRAINT "event_rsvps_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "public"."events"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."event_rsvps"
    ADD CONSTRAINT "event_rsvps_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_creator_id_fkey" FOREIGN KEY ("creator_id") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES "public"."groups"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_organizer_id_fkey" FOREIGN KEY ("organizer_id") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_reviewed_by_fkey" FOREIGN KEY ("reviewed_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."events"
    ADD CONSTRAINT "events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON UPDATE CASCADE ON DELETE SET NULL;



ALTER TABLE ONLY "public"."group_posts"
    ADD CONSTRAINT "fk_group_posts_user" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."jobs"
    ADD CONSTRAINT "fk_jobs_company_id" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "fk_notification_event" FOREIGN KEY ("event_id") REFERENCES "public"."events"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "fk_notification_recipient" FOREIGN KEY ("recipient_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "fk_notification_sender" FOREIGN KEY ("sender_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."group_members"
    ADD CONSTRAINT "group_members_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES "public"."groups"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."group_members"
    ADD CONSTRAINT "group_members_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."group_posts"
    ADD CONSTRAINT "group_posts_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES "public"."groups"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."group_posts"
    ADD CONSTRAINT "group_posts_parent_post_id_fkey" FOREIGN KEY ("parent_post_id") REFERENCES "public"."group_posts"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."group_posts"
    ADD CONSTRAINT "group_posts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."groups"
    ADD CONSTRAINT "groups_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



COMMENT ON CONSTRAINT "groups_created_by_fkey" ON "public"."groups" IS 'Ensures that the creator of a group is a valid user profile.';



ALTER TABLE ONLY "public"."groups"
    ADD CONSTRAINT "groups_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."groups"
    ADD CONSTRAINT "groups_reviewed_by_fkey" FOREIGN KEY ("reviewed_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."job_alert_notifications"
    ADD CONSTRAINT "job_alert_notifications_alert_id_fkey" FOREIGN KEY ("alert_id") REFERENCES "public"."job_alerts"("id");



ALTER TABLE ONLY "public"."job_alert_notifications"
    ADD CONSTRAINT "job_alert_notifications_job_id_fkey" FOREIGN KEY ("job_id") REFERENCES "public"."jobs"("id");



ALTER TABLE ONLY "public"."job_alert_notifications"
    ADD CONSTRAINT "job_alert_notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."job_alerts"
    ADD CONSTRAINT "job_alerts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."job_applications"
    ADD CONSTRAINT "job_applications_applicant_id_fkey" FOREIGN KEY ("applicant_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."job_applications"
    ADD CONSTRAINT "job_applications_job_id_fkey" FOREIGN KEY ("job_id") REFERENCES "public"."jobs"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."job_bookmarks"
    ADD CONSTRAINT "job_bookmarks_job_id_fkey" FOREIGN KEY ("job_id") REFERENCES "public"."jobs"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."job_bookmarks"
    ADD CONSTRAINT "job_bookmarks_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."jobs"
    ADD CONSTRAINT "jobs_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."jobs"
    ADD CONSTRAINT "jobs_posted_by_fkey" FOREIGN KEY ("posted_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."jobs"
    ADD CONSTRAINT "jobs_reviewed_by_fkey" FOREIGN KEY ("reviewed_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."jobs"
    ADD CONSTRAINT "jobs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON UPDATE CASCADE ON DELETE SET NULL;



ALTER TABLE ONLY "public"."mentee_profiles"
    ADD CONSTRAINT "mentee_profiles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentees"
    ADD CONSTRAINT "mentees_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentor_availability"
    ADD CONSTRAINT "mentor_availability_mentor_id_fkey" FOREIGN KEY ("mentor_id") REFERENCES "public"."mentors"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentor_profiles"
    ADD CONSTRAINT "mentor_profiles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentors"
    ADD CONSTRAINT "mentors_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorship_appointments"
    ADD CONSTRAINT "mentorship_appointments_availability_id_fkey" FOREIGN KEY ("availability_id") REFERENCES "public"."mentor_availability"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorship_appointments"
    ADD CONSTRAINT "mentorship_appointments_mentee_id_fkey" FOREIGN KEY ("mentee_id") REFERENCES "public"."mentee_profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."mentorship_feedback"
    ADD CONSTRAINT "mentorship_feedback_mentorship_request_id_fkey" FOREIGN KEY ("mentorship_request_id") REFERENCES "public"."mentorship_requests"("id");



ALTER TABLE ONLY "public"."mentorship_feedback"
    ADD CONSTRAINT "mentorship_feedback_submitted_by_fkey" FOREIGN KEY ("submitted_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."mentorship_messages"
    ADD CONSTRAINT "mentorship_messages_mentorship_request_id_fkey" FOREIGN KEY ("mentorship_request_id") REFERENCES "public"."mentorship_requests"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorship_messages"
    ADD CONSTRAINT "mentorship_messages_sender_id_fkey" FOREIGN KEY ("sender_id") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."mentorship_relationships"
    ADD CONSTRAINT "mentorship_relationships_mentee_id_fkey" FOREIGN KEY ("mentee_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorship_relationships"
    ADD CONSTRAINT "mentorship_relationships_mentor_id_fkey" FOREIGN KEY ("mentor_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorship_relationships"
    ADD CONSTRAINT "mentorship_relationships_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "public"."mentorship_programs"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."mentorship_requests"
    ADD CONSTRAINT "mentorship_requests_mentee_id_fkey" FOREIGN KEY ("mentee_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorship_requests"
    ADD CONSTRAINT "mentorship_requests_mentor_id_fkey" FOREIGN KEY ("mentor_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorship_sessions"
    ADD CONSTRAINT "mentorship_sessions_mentorship_request_id_fkey" FOREIGN KEY ("mentorship_request_id") REFERENCES "public"."mentorship_requests"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorships"
    ADD CONSTRAINT "mentorships_mentee_id_fkey" FOREIGN KEY ("mentee_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mentorships"
    ADD CONSTRAINT "mentorships_mentor_id_fkey" FOREIGN KEY ("mentor_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."messages"
    ADD CONSTRAINT "messages_conversation_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "public"."conversations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."messages"
    ADD CONSTRAINT "messages_recipient_id_fkey" FOREIGN KEY ("recipient_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."messages"
    ADD CONSTRAINT "messages_sender_id_fkey" FOREIGN KEY ("sender_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."networking_group_members"
    ADD CONSTRAINT "networking_group_members_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES "public"."networking_groups"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."networking_group_members"
    ADD CONSTRAINT "networking_group_members_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notification_preferences"
    ADD CONSTRAINT "notification_preferences_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "notifications_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_degree_code_fkey" FOREIGN KEY ("degree_code") REFERENCES "public"."degrees"("code");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_deleted_by_fkey" FOREIGN KEY ("deleted_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_id_fkey" FOREIGN KEY ("id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_verification_reviewed_by_fkey" FOREIGN KEY ("verification_reviewed_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."resources"
    ADD CONSTRAINT "resources_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."resume_profiles"
    ADD CONSTRAINT "resume_profiles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."role_permissions"
    ADD CONSTRAINT "role_permissions_permission_id_fkey" FOREIGN KEY ("permission_id") REFERENCES "public"."permissions"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."social_links"
    ADD CONSTRAINT "social_links_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."system_alerts"
    ADD CONSTRAINT "system_alerts_resolved_by_fkey" FOREIGN KEY ("resolved_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."user_activity_logs"
    ADD CONSTRAINT "user_activity_logs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."user_feedback"
    ADD CONSTRAINT "user_feedback_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."user_resumes"
    ADD CONSTRAINT "user_resumes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE CASCADE;



CREATE POLICY "Admins can delete any feedback" ON "public"."event_feedback" FOR DELETE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."is_admin" = true)))));



CREATE POLICY "Admins can insert admin actions" ON "public"."admin_actions" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))))));



CREATE POLICY "Admins can manage all content submissions" ON "public"."content_approvals" USING (("public"."get_my_role"() = 'admin'::"text")) WITH CHECK (("public"."get_my_role"() = 'admin'::"text"));



CREATE POLICY "Admins can manage all resources" ON "public"."resources" USING (("public"."get_my_role"() = 'admin'::"text")) WITH CHECK (("public"."get_my_role"() = 'admin'::"text"));



CREATE POLICY "Admins can manage content moderation" ON "public"."content_moderation" USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))))));



CREATE POLICY "Admins can manage event groups" ON "public"."event_groups" USING ((("auth"."role"() = 'authenticated'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."is_admin" = true))))));



CREATE POLICY "Admins can manage system alerts" ON "public"."system_alerts" USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))))));



CREATE POLICY "Admins can manage user roles" ON "public"."user_roles" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_roles" "ur"
     JOIN "public"."roles" "r" ON (("ur"."role_id" = "r"."id")))
  WHERE (("ur"."profile_id" = "auth"."uid"()) AND ("r"."name" = 'admin'::"text")))));



CREATE POLICY "Admins can view all admin actions" ON "public"."admin_actions" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))))));



CREATE POLICY "Admins can view all event feedback" ON "public"."event_feedback" FOR SELECT USING ((( SELECT "profiles"."role"
   FROM "public"."profiles"
  WHERE ("profiles"."id" = "auth"."uid"())) = 'admin'::"text"));



CREATE POLICY "Admins manage features" ON "public"."feature_flags" TO "authenticated" USING (("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))) WITH CHECK (("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"])));



CREATE POLICY "Allow authenticated users to view RSVPs" ON "public"."event_rsvps" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "Allow insert for all users" ON "public"."user_feedback" FOR INSERT WITH CHECK (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Allow select for developer only" ON "public"."user_feedback" FOR SELECT USING (("auth"."uid"() = '5371e2d5-0697-46c0-bf5b-aab2e4d88b58'::"uuid"));



CREATE POLICY "Allow select for super_admin only" ON "public"."user_feedback" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = 'super_admin'::"text")))));



CREATE POLICY "Allow update status for super_admin only" ON "public"."user_feedback" FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = 'super_admin'::"text")))));



CREATE POLICY "Allow users and admins to view mentee profiles" ON "public"."mentee_profiles" FOR SELECT USING ((("user_id" = "auth"."uid"()) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



CREATE POLICY "Allow users to create their own mentee profile" ON "public"."mentee_profiles" FOR INSERT WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "Allow users to delete their own bookmarks" ON "public"."bookmarked_jobs" FOR DELETE TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Allow users to insert their own bookmarks" ON "public"."bookmarked_jobs" FOR INSERT TO "authenticated" WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Allow users to update their own mentee profile" ON "public"."mentee_profiles" FOR UPDATE USING (("user_id" = "auth"."uid"()));



CREATE POLICY "Allow users to view their own bookmarks" ON "public"."bookmarked_jobs" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Anyone can view achievements" ON "public"."achievements" FOR SELECT USING (true);



CREATE POLICY "Anyone can view active mentorship programs" ON "public"."mentorship_programs" FOR SELECT USING (("is_active" = true));



CREATE POLICY "Anyone can view mentor availability" ON "public"."mentor_availability" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."mentors"
  WHERE (("mentors"."id" = "mentor_availability"."mentor_id") AND (("mentors"."status" = 'approved'::"text") OR ("mentors"."user_id" = "auth"."uid"()))))));



CREATE POLICY "Creators can view their own content submissions" ON "public"."content_approvals" FOR SELECT USING (("auth"."uid"() = "creator_id"));



CREATE POLICY "Employers can view applications" ON "public"."job_applications" FOR SELECT TO "authenticated" USING (("job_id" IN ( SELECT "jobs"."id"
   FROM "public"."jobs"
  WHERE ("jobs"."posted_by" = "auth"."uid"()))));



CREATE POLICY "Employers can view applications for their jobs" ON "public"."job_applications" FOR SELECT USING ((( SELECT "jobs"."created_by"
   FROM "public"."jobs"
  WHERE ("jobs"."id" = "job_applications"."job_id")) = "auth"."uid"()));



CREATE POLICY "Enable delete for users based on user_id" ON "public"."job_alerts" FOR DELETE TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Enable insert for users based on user_id" ON "public"."job_alerts" FOR INSERT TO "authenticated" WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Enable select for users based on user_id" ON "public"."job_alerts" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Enable update for users based on user_id" ON "public"."job_alerts" FOR UPDATE TO "authenticated" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Group admins can delete any post in their group." ON "public"."group_posts" FOR DELETE USING ((( SELECT "group_members"."role"
   FROM "public"."group_members"
  WHERE (("group_members"."group_id" = "group_posts"."group_id") AND ("group_members"."user_id" = "auth"."uid"()))) = 'admin'::"text"));



CREATE POLICY "Group members can create posts." ON "public"."group_posts" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."group_members"
  WHERE (("group_members"."group_id" = "group_posts"."group_id") AND ("group_members"."user_id" = "auth"."uid"())))));



CREATE POLICY "Group members can view posts." ON "public"."group_posts" FOR SELECT USING (("group_id" IN ( SELECT "group_members"."group_id"
   FROM "public"."group_members"
  WHERE ("group_members"."user_id" = "auth"."uid"()))));



CREATE POLICY "Group posts are viewable by group members." ON "public"."group_posts" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."group_members"
  WHERE (("group_members"."group_id" = "group_posts"."group_id") AND ("group_members"."user_id" = "auth"."uid"())))));



CREATE POLICY "Import history visible to creator" ON "public"."csv_import_history" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Job creators can view applications" ON "public"."job_applications" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."jobs"
  WHERE (("jobs"."id" = "job_applications"."job_id") AND ("jobs"."posted_by" = "auth"."uid"())))));



CREATE POLICY "Job posters can update application status" ON "public"."job_applications" FOR UPDATE USING (("auth"."uid"() IN ( SELECT "jobs"."posted_by"
   FROM "public"."jobs"
  WHERE ("jobs"."id" = "job_applications"."job_id"))));



CREATE POLICY "Mentee can create request" ON "public"."mentorship_requests" FOR INSERT WITH CHECK (("auth"."uid"() = "mentee_id"));



CREATE POLICY "Mentee can manage own data" ON "public"."mentees" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Mentees can create appointments" ON "public"."mentorship_appointments" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."mentees"
  WHERE (("mentees"."id" = "mentorship_appointments"."mentee_id") AND ("mentees"."user_id" = "auth"."uid"())))));



CREATE POLICY "Mentees can request mentorship" ON "public"."mentorships" FOR INSERT WITH CHECK ((("auth"."uid"() = "mentee_id") AND (EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "mentorships"."mentor_id") AND ("profiles"."is_available_for_mentorship" = true))))));



CREATE POLICY "Mentor or mentee can update request" ON "public"."mentorship_requests" FOR UPDATE USING ((("auth"."uid"() = "mentor_id") OR ("auth"."uid"() = "mentee_id")));



CREATE POLICY "Mentor or mentee can view relationship" ON "public"."mentorship_relationships" FOR SELECT USING ((("auth"."uid"() = "mentor_id") OR ("auth"."uid"() = "mentee_id")));



CREATE POLICY "Mentor or mentee can view request" ON "public"."mentorship_requests" FOR SELECT USING ((("auth"."uid"() = "mentor_id") OR ("auth"."uid"() = "mentee_id")));



CREATE POLICY "Mentors can manage their own availability" ON "public"."mentor_availability" USING ((EXISTS ( SELECT 1
   FROM "public"."mentors"
  WHERE (("mentors"."id" = "mentor_availability"."mentor_id") AND ("mentors"."user_id" = "auth"."uid"())))));



CREATE POLICY "Mentors can respond to requests" ON "public"."mentorship_requests" FOR UPDATE USING (("auth"."uid"() = "mentor_id")) WITH CHECK (("status" <> 'pending'::"text"));



CREATE POLICY "Mentors can update mentorship requests" ON "public"."mentorships" FOR UPDATE USING (("auth"."uid"() = "mentor_id"));



CREATE POLICY "Only connected users can send messages" ON "public"."messages" FOR INSERT TO "authenticated" WITH CHECK ((("auth"."uid"() = "sender_id") AND (EXISTS ( SELECT 1
   FROM "public"."connections"
  WHERE (((("connections"."requester_id" = "auth"."uid"()) AND ("connections"."recipient_id" = "messages"."recipient_id")) OR (("connections"."recipient_id" = "auth"."uid"()) AND ("connections"."requester_id" = "messages"."recipient_id"))) AND ("connections"."status" = 'accepted'::"text"))))));



CREATE POLICY "Organizers can view event feedback" ON "public"."event_feedback" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."events"
  WHERE (("events"."id" = "event_feedback"."event_id") AND ("events"."organizer_id" = "auth"."uid"())))));



CREATE POLICY "Public can view approved resources" ON "public"."resources" FOR SELECT USING (("is_approved" = true));



CREATE POLICY "Recipients can update messages" ON "public"."messages" FOR UPDATE USING (("auth"."uid"() = "recipient_id"));



CREATE POLICY "Resume profiles are viewable by everyone" ON "public"."resume_profiles" FOR SELECT USING (true);



CREATE POLICY "Resumes are viewable by everyone" ON "public"."resume_profiles" FOR SELECT USING (true);



CREATE POLICY "Roles are viewable by everyone" ON "public"."roles" FOR SELECT USING (true);



CREATE POLICY "Super admins can create roles" ON "public"."roles" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = 'super_admin'::"text")))));



CREATE POLICY "Super admins can delete roles" ON "public"."roles" FOR DELETE USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = 'super_admin'::"text")))));



CREATE POLICY "Super admins can update roles" ON "public"."roles" FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = 'super_admin'::"text")))));



CREATE POLICY "User can insert import history" ON "public"."csv_import_history" FOR INSERT WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can accept/reject connection requests" ON "public"."connections" FOR UPDATE USING (("auth"."uid"() = "recipient_id")) WITH CHECK (("status" <> 'pending'::"text"));



CREATE POLICY "Users can access conversations they participate in" ON "public"."conversations" FOR SELECT USING ("public"."is_conversation_participant"("id", "auth"."uid"()));



CREATE POLICY "Users can apply to jobs" ON "public"."job_applications" FOR INSERT WITH CHECK (("auth"."uid"() = "applicant_id"));



CREATE POLICY "Users can create bookmarks" ON "public"."job_bookmarks" FOR INSERT WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can create resources" ON "public"."resources" FOR INSERT WITH CHECK (("auth"."uid"() = "created_by"));



CREATE POLICY "Users can create their own feedback" ON "public"."event_feedback" FOR INSERT TO "authenticated" WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can create their own resume profile" ON "public"."resume_profiles" FOR INSERT WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can create their own resumes" ON "public"."resume_profiles" FOR INSERT WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can delete their connection requests" ON "public"."connections" FOR DELETE USING ((("auth"."uid"() = "requester_id") OR ("auth"."uid"() = "recipient_id")));



CREATE POLICY "Users can delete their mentorship requests" ON "public"."mentorship_requests" FOR DELETE USING ((("auth"."uid"() = "mentee_id") OR ("auth"."uid"() = "mentor_id")));



CREATE POLICY "Users can delete their own bookmarks" ON "public"."job_bookmarks" FOR DELETE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can delete their own posts." ON "public"."group_posts" FOR DELETE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can delete their own resume profile" ON "public"."resume_profiles" FOR DELETE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can delete their own resumes" ON "public"."user_resumes" FOR DELETE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can insert messages in their conversations" ON "public"."messages" FOR INSERT WITH CHECK (("public"."is_conversation_participant"("conversation_id", "auth"."uid"()) AND ("sender_id" = "auth"."uid"())));



CREATE POLICY "Users can insert their own participation" ON "public"."conversation_participants" FOR INSERT WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "Users can insert their own resumes" ON "public"."user_resumes" FOR INSERT WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can manage their own RSVPs" ON "public"."event_rsvps" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can manage their own appointments" ON "public"."mentorship_appointments" USING ((EXISTS ( SELECT 1
   FROM "public"."mentee_profiles"
  WHERE (("mentee_profiles"."id" = "mentorship_appointments"."mentee_id") AND ("mentee_profiles"."user_id" = "auth"."uid"())))));



CREATE POLICY "Users can manage their own bookmarks" ON "public"."job_bookmarks" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can manage their own event feedback" ON "public"."event_feedback" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can manage their own job applications" ON "public"."job_applications" USING (("auth"."uid"() = "applicant_id")) WITH CHECK (("auth"."uid"() = "applicant_id"));



CREATE POLICY "Users can manage their own job bookmarks" ON "public"."job_bookmarks" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can manage their own mentee profile" ON "public"."mentees" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can read event groups" ON "public"."event_groups" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "Users can request connections" ON "public"."connections" FOR INSERT WITH CHECK (("auth"."uid"() = "requester_id"));



CREATE POLICY "Users can request mentorship" ON "public"."mentorship_requests" FOR INSERT WITH CHECK (("auth"."uid"() = "mentee_id"));



CREATE POLICY "Users can send messages" ON "public"."messages" FOR INSERT WITH CHECK (("auth"."uid"() = "sender_id"));



CREATE POLICY "Users can send messages in their conversations" ON "public"."messages" FOR INSERT WITH CHECK ((("auth"."uid"() = "sender_id") AND (EXISTS ( SELECT 1
   FROM "public"."conversation_participants"
  WHERE (("conversation_participants"."conversation_id" = "messages"."conversation_id") AND ("conversation_participants"."user_id" = "auth"."uid"()))))));



CREATE POLICY "Users can submit applications" ON "public"."job_applications" FOR INSERT WITH CHECK (("auth"."uid"() = "applicant_id"));



CREATE POLICY "Users can submit feedback" ON "public"."event_feedback" FOR INSERT WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can update connection requests they received" ON "public"."connections" FOR UPDATE USING (("auth"."uid"() = "recipient_id"));



CREATE POLICY "Users can update their own achievements" ON "public"."achievements" USING (("auth"."uid"() = "profile_id"));



CREATE POLICY "Users can update their own feedback" ON "public"."event_feedback" FOR UPDATE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can update their own mentorship relationships" ON "public"."mentorship_relationships" FOR UPDATE USING ((("auth"."uid"() = "mentor_id") OR ("auth"."uid"() = "mentee_id")));



CREATE POLICY "Users can update their own posts." ON "public"."group_posts" FOR UPDATE USING (("user_id" = "auth"."uid"()));



CREATE POLICY "Users can update their own resume profile" ON "public"."resume_profiles" FOR UPDATE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can update their own resumes" ON "public"."resume_profiles" FOR UPDATE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can update their own resumes" ON "public"."user_resumes" FOR UPDATE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view all feedback" ON "public"."event_feedback" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "Users can view applications for their jobs or their own applica" ON "public"."job_applications" FOR SELECT USING ((("auth"."uid"() = "applicant_id") OR ("auth"."uid"() IN ( SELECT "jobs"."posted_by"
   FROM "public"."jobs"
  WHERE ("jobs"."id" = "job_applications"."job_id")))));



CREATE POLICY "Users can view mentees they are mentoring" ON "public"."mentees" FOR SELECT USING ((("auth"."uid"() = "user_id") OR (EXISTS ( SELECT 1
   FROM "public"."mentorship_relationships"
  WHERE (("mentorship_relationships"."mentee_id" = "mentees"."user_id") AND ("mentorship_relationships"."mentor_id" = "auth"."uid"()))))));



CREATE POLICY "Users can view messages in their conversations" ON "public"."messages" FOR SELECT USING ("public"."is_conversation_participant"("conversation_id", "auth"."uid"()));



CREATE POLICY "Users can view participants of their conversations" ON "public"."conversation_participants" FOR SELECT USING ("public"."is_conversation_participant"("conversation_id", "auth"."uid"()));



CREATE POLICY "Users can view their mentor/mentee requests" ON "public"."mentorship_requests" FOR SELECT USING ((("auth"."uid"() = "mentee_id") OR ("auth"."uid"() = "mentor_id")));



CREATE POLICY "Users can view their own applications" ON "public"."job_applications" FOR SELECT USING ((("auth"."uid"() = "applicant_id") OR (EXISTS ( SELECT 1
   FROM "public"."jobs"
  WHERE (("jobs"."id" = "job_applications"."job_id") AND ("jobs"."posted_by" = "auth"."uid"()))))));



CREATE POLICY "Users can view their own appointments" ON "public"."mentorship_appointments" FOR SELECT USING (((EXISTS ( SELECT 1
   FROM "public"."mentees"
  WHERE (("mentees"."id" = "mentorship_appointments"."mentee_id") AND ("mentees"."user_id" = "auth"."uid"())))) OR (EXISTS ( SELECT 1
   FROM ("public"."mentor_availability" "ma"
     JOIN "public"."mentors" "m" ON (("ma"."mentor_id" = "m"."id")))
  WHERE (("ma"."id" = "mentorship_appointments"."availability_id") AND ("m"."user_id" = "auth"."uid"()))))));



CREATE POLICY "Users can view their own bookmarks" ON "public"."job_bookmarks" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view their own connections" ON "public"."connections" FOR SELECT USING ((("auth"."uid"() = "requester_id") OR ("auth"."uid"() = "recipient_id")));



CREATE POLICY "Users can view their own feedback" ON "public"."event_feedback" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view their own mentorship relationships" ON "public"."mentorship_relationships" FOR SELECT USING ((("auth"."uid"() = "mentor_id") OR ("auth"."uid"() = "mentee_id")));



CREATE POLICY "Users can view their own mentorships" ON "public"."mentorships" FOR SELECT USING ((("auth"."uid"() = "mentor_id") OR ("auth"."uid"() = "mentee_id")));



CREATE POLICY "Users can view their own messages" ON "public"."messages" FOR SELECT USING ((("auth"."uid"() = "sender_id") OR ("auth"."uid"() = "recipient_id")));



CREATE POLICY "Users can view their own resumes" ON "public"."user_resumes" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view their own roles" ON "public"."user_roles" FOR SELECT USING (("profile_id" = "auth"."uid"()));



ALTER TABLE "public"."achievements" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "achv_public_read" ON "public"."achievements" FOR SELECT USING (true);



CREATE POLICY "achv_self_all" ON "public"."achievements" TO "authenticated" USING (("profile_id" = "auth"."uid"())) WITH CHECK (("profile_id" = "auth"."uid"()));



ALTER TABLE "public"."activity_log" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "activity_log_insert_policy" ON "public"."activity_log" FOR INSERT WITH CHECK (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "activity_log_select_policy" ON "public"."activity_log" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND (("profiles"."role" = ANY (ARRAY['admin'::"text", 'super_admin'::"text"])) OR ("profiles"."is_admin" = true))))));



ALTER TABLE "public"."activity_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."admin_actions" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "admin_actions_insert" ON "public"."admin_actions" FOR INSERT WITH CHECK ("public"."is_admin"());



CREATE POLICY "admin_actions_select" ON "public"."admin_actions" FOR SELECT USING ("public"."is_admin"());



CREATE POLICY "admin_delete_post_policy" ON "public"."group_posts" FOR DELETE USING (("auth"."uid"() IN ( SELECT "group_members"."user_id"
   FROM "public"."group_members"
  WHERE (("group_members"."group_id" = "group_posts"."group_id") AND ("group_members"."role" = 'admin'::"text")))));



ALTER TABLE "public"."bookmarked_jobs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."connections" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."content_approvals" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."content_moderation" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."conversation_participants" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."conversations" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."csv_import_history" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "delete_own_message" ON "public"."messages" FOR DELETE TO "authenticated" USING (("sender_id" = "auth"."uid"()));



CREATE POLICY "delete_own_messages" ON "public"."messages" FOR DELETE TO "authenticated" USING (("auth"."uid"() = "sender_id"));



CREATE POLICY "delete_own_post_policy" ON "public"."group_posts" FOR DELETE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "dev_event_attendees_select" ON "public"."event_attendees" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "dev_events_select" ON "public"."events" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "dev_group_members_select" ON "public"."group_members" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "dev_groups_select" ON "public"."groups" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "dev_jobs_select" ON "public"."jobs" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "dev_profiles_select" ON "public"."profiles" FOR SELECT TO "authenticated" USING (true);



ALTER TABLE "public"."education_history" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."event_attendees" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."event_feedback" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."event_groups" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."event_rsvps" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."group_members" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."group_posts" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "group_posts_delete" ON "public"."group_posts" FOR DELETE TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



CREATE POLICY "group_posts_insert" ON "public"."group_posts" FOR INSERT TO "authenticated" WITH CHECK (((EXISTS ( SELECT 1
   FROM "public"."group_members" "gm"
  WHERE (("gm"."group_id" = "group_posts"."group_id") AND ("gm"."user_id" = "auth"."uid"())))) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



CREATE POLICY "group_posts_select" ON "public"."group_posts" FOR SELECT TO "authenticated", "anon" USING ((EXISTS ( SELECT 1
   FROM "public"."groups" "g"
  WHERE (("g"."id" = "group_posts"."group_id") AND (("g"."is_private" = false) OR (EXISTS ( SELECT 1
           FROM "public"."group_members" "gm"
          WHERE (("gm"."group_id" = "g"."id") AND ("gm"."user_id" = "auth"."uid"())))) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"])))))));



CREATE POLICY "group_posts_update" ON "public"."group_posts" FOR UPDATE TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



ALTER TABLE "public"."groups" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."job_alerts" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "job_app insert own" ON "public"."job_applications" FOR INSERT TO "authenticated" WITH CHECK (("applicant_id" = "auth"."uid"()));



CREATE POLICY "job_app read applicant or poster or admin" ON "public"."job_applications" FOR SELECT TO "authenticated" USING ((("applicant_id" = "auth"."uid"()) OR (EXISTS ( SELECT 1
   FROM "public"."jobs" "j"
  WHERE (("j"."id" = "job_applications"."job_id") AND (("j"."posted_by" = "auth"."uid"()) OR (EXISTS ( SELECT 1
           FROM "public"."profiles" "p"
          WHERE (("p"."id" = "auth"."uid"()) AND (("p"."is_admin" = true) OR ("p"."role" = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))))))))))));



CREATE POLICY "job_app update status by poster or admin" ON "public"."job_applications" FOR UPDATE TO "authenticated" USING ((("applicant_id" = "auth"."uid"()) OR (EXISTS ( SELECT 1
   FROM "public"."jobs" "j"
  WHERE (("j"."id" = "job_applications"."job_id") AND (("j"."posted_by" = "auth"."uid"()) OR (EXISTS ( SELECT 1
           FROM "public"."profiles" "p"
          WHERE (("p"."id" = "auth"."uid"()) AND (("p"."is_admin" = true) OR ("p"."role" = ANY (ARRAY['admin'::"text", 'super_admin'::"text"])))))))))))) WITH CHECK (true);



ALTER TABLE "public"."job_applications" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."job_bookmarks" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."jobs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."mentee_profiles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."mentees" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "mentees_insert_policy" ON "public"."mentees" FOR INSERT WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "mentees_select_policy" ON "public"."mentees" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "mentees_update_policy" ON "public"."mentees" FOR UPDATE USING (("auth"."uid"() = "user_id"));



ALTER TABLE "public"."mentor_availability" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "mentor_availability_delete_policy" ON "public"."mentor_availability" FOR DELETE USING (("auth"."uid"() = "mentor_id"));



CREATE POLICY "mentor_availability_insert_policy" ON "public"."mentor_availability" FOR INSERT WITH CHECK (("auth"."uid"() = "mentor_id"));



CREATE POLICY "mentor_availability_select_mentee_policy" ON "public"."mentor_availability" FOR SELECT USING (true);



CREATE POLICY "mentor_availability_select_policy" ON "public"."mentor_availability" FOR SELECT USING (("auth"."uid"() = "mentor_id"));



CREATE POLICY "mentor_availability_update_policy" ON "public"."mentor_availability" FOR UPDATE USING (("auth"."uid"() = "mentor_id"));



CREATE POLICY "mentor_ins_self" ON "public"."mentor_profiles" FOR INSERT WITH CHECK ((("user_id" = "auth"."uid"()) OR "public"."is_admin"()));



ALTER TABLE "public"."mentor_profiles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "mentor_sel_self_or_admin" ON "public"."mentor_profiles" FOR SELECT USING ((("user_id" = "auth"."uid"()) OR "public"."is_admin"()));



CREATE POLICY "mentor_upd_self_or_admin" ON "public"."mentor_profiles" FOR UPDATE USING ((("user_id" = "auth"."uid"()) OR "public"."is_admin"())) WITH CHECK ((("user_id" = "auth"."uid"()) OR "public"."is_admin"()));



ALTER TABLE "public"."mentors" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "mentors_insert" ON "public"."mentors" FOR INSERT TO "authenticated" WITH CHECK (((("user_id" = "auth"."uid"()) AND (NOT (EXISTS ( SELECT 1
   FROM "public"."mentors" "m"
  WHERE ("m"."user_id" = "auth"."uid"()))))) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



CREATE POLICY "mentors_select" ON "public"."mentors" FOR SELECT TO "authenticated", "anon" USING ((("status" = 'approved'::"text") OR ("user_id" = "auth"."uid"()) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



CREATE POLICY "mentors_update" ON "public"."mentors" FOR UPDATE TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"])))) WITH CHECK ((("user_id" = "auth"."uid"()) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



ALTER TABLE "public"."mentorship_appointments" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "mentorship_appointments_delete_policy" ON "public"."mentorship_appointments" FOR DELETE USING (("auth"."uid"() = "mentee_id"));



CREATE POLICY "mentorship_appointments_insert_policy" ON "public"."mentorship_appointments" FOR INSERT WITH CHECK (("auth"."uid"() = "mentee_id"));



CREATE POLICY "mentorship_appointments_select_policy" ON "public"."mentorship_appointments" FOR SELECT USING (("auth"."uid"() = "mentee_id"));



CREATE POLICY "mentorship_appointments_update_policy" ON "public"."mentorship_appointments" FOR UPDATE USING (("auth"."uid"() = "mentee_id"));



ALTER TABLE "public"."mentorship_programs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."mentorship_relationships" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."mentorship_requests" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."mentorship_sessions" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "mentorship_sessions_delete_policy" ON "public"."mentorship_sessions" FOR DELETE USING (((EXISTS ( SELECT 1
   FROM "public"."mentorship_requests" "mr"
  WHERE (("mr"."id" = "mentorship_sessions"."mentorship_request_id") AND ("mr"."mentor_id" = "auth"."uid"())))) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



CREATE POLICY "mentorship_sessions_insert_policy" ON "public"."mentorship_sessions" FOR INSERT WITH CHECK (((EXISTS ( SELECT 1
   FROM "public"."mentorship_requests" "mr"
  WHERE (("mr"."id" = "mentorship_sessions"."mentorship_request_id") AND ("mr"."mentor_id" = "auth"."uid"()) AND ("mr"."status" = 'approved'::"text")))) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



CREATE POLICY "mentorship_sessions_select_policy" ON "public"."mentorship_sessions" FOR SELECT USING (((EXISTS ( SELECT 1
   FROM "public"."mentorship_requests" "mr"
  WHERE (("mr"."id" = "mentorship_sessions"."mentorship_request_id") AND (("mr"."mentor_id" = "auth"."uid"()) OR ("mr"."mentee_id" = "auth"."uid"()))))) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



CREATE POLICY "mentorship_sessions_update_policy" ON "public"."mentorship_sessions" FOR UPDATE USING (((EXISTS ( SELECT 1
   FROM "public"."mentorship_requests" "mr"
  WHERE (("mr"."id" = "mentorship_sessions"."mentorship_request_id") AND ("mr"."mentor_id" = "auth"."uid"())))) OR ("public"."get_user_role"("auth"."uid"()) = ANY (ARRAY['admin'::"text", 'super_admin'::"text"]))));



ALTER TABLE "public"."mentorships" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."messages" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."notification_preferences" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."notifications" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "notifications_insert_policy" ON "public"."notifications" FOR INSERT WITH CHECK (true);



CREATE POLICY "notifications_select_policy" ON "public"."notifications" FOR SELECT USING (("auth"."uid"() = COALESCE("profile_id", "recipient_id")));



CREATE POLICY "notifications_update_policy" ON "public"."notifications" FOR UPDATE USING (("auth"."uid"() = COALESCE("profile_id", "recipient_id")));



ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "realtime: connections" ON "public"."connections" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: conversations" ON "public"."conversations" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: event_feedback" ON "public"."event_feedback" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: job_applications" ON "public"."job_applications" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: mentorship_requests" ON "public"."mentorship_requests" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: mentorship_sessions" ON "public"."mentorship_sessions" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: messages" ON "public"."messages" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: notifications" ON "public"."notifications" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: participants" ON "public"."conversation_participants" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



CREATE POLICY "realtime: rsvps" ON "public"."event_rsvps" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



ALTER TABLE "public"."resources" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."resume_profiles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."roles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."system_alerts" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "update_own_messages" ON "public"."messages" FOR UPDATE TO "authenticated" USING (("auth"."uid"() = "sender_id"));



ALTER TABLE "public"."user_activity_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_feedback" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_resumes" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_roles" ENABLE ROW LEVEL SECURITY;




ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";






ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."notifications";









GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";





































































































































































































































































GRANT ALL ON FUNCTION "public"."_is_admin"("uid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."_is_admin"("uid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."_is_admin"("uid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."add_creator_as_group_admin"() TO "anon";
GRANT ALL ON FUNCTION "public"."add_creator_as_group_admin"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."add_creator_as_group_admin"() TO "service_role";



GRANT ALL ON FUNCTION "public"."add_creator_to_group_members"() TO "anon";
GRANT ALL ON FUNCTION "public"."add_creator_to_group_members"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."add_creator_to_group_members"() TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_delete_job"("p_job_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_delete_job"("p_job_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_delete_job"("p_job_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_delete_user_fallback"("target_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_delete_user_fallback"("target_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_delete_user_fallback"("target_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."admin_delete_user_rpc"("target" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."admin_delete_user_rpc"("target" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_delete_user_rpc"("target" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_delete_user_rpc"("target" "uuid") TO "service_role";



GRANT ALL ON TABLE "public"."profiles" TO "anon";
GRANT ALL ON TABLE "public"."profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."profiles" TO "service_role";



GRANT ALL ON TABLE "public"."admin_user_logins" TO "anon";
GRANT ALL ON TABLE "public"."admin_user_logins" TO "authenticated";
GRANT ALL ON TABLE "public"."admin_user_logins" TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_list_user_logins"() TO "anon";
GRANT ALL ON FUNCTION "public"."admin_list_user_logins"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_list_user_logins"() TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_list_users_with_last_login"("p_search" "text", "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."admin_list_users_with_last_login"("p_search" "text", "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_list_users_with_last_login"("p_search" "text", "p_limit" integer, "p_offset" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_purge_user_data"("target" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_purge_user_data"("target" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_purge_user_data"("target" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_request_user_delete"("target" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_request_user_delete"("target" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_request_user_delete"("target" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_revoke_super_admin"("target_user_id" "uuid", "new_role" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_revoke_super_admin"("target_user_id" "uuid", "new_role" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_revoke_super_admin"("target_user_id" "uuid", "new_role" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_set_approval"("tname" "text", "row_id" "uuid", "new_status" "public"."approval_status", "note" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_set_approval"("tname" "text", "row_id" "uuid", "new_status" "public"."approval_status", "note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_set_approval"("tname" "text", "row_id" "uuid", "new_status" "public"."approval_status", "note" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_set_profile_approval"("target" "uuid", "new_status" "public"."profile_approval_status", "reason" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_set_profile_approval"("target" "uuid", "new_status" "public"."profile_approval_status", "reason" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_set_profile_approval"("target" "uuid", "new_status" "public"."profile_approval_status", "reason" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."admin_set_role"("p_user" "uuid", "p_role" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."admin_set_role"("p_user" "uuid", "p_role" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_set_role"("p_user" "uuid", "p_role" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_set_role"("p_user" "uuid", "p_role" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_set_user_role"("target" "uuid", "new_role" "text", "make_admin" boolean) TO "anon";
GRANT ALL ON FUNCTION "public"."admin_set_user_role"("target" "uuid", "new_role" "text", "make_admin" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_set_user_role"("target" "uuid", "new_role" "text", "make_admin" boolean) TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_soft_delete_user"("target" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_soft_delete_user"("target" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_soft_delete_user"("target" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_soft_delete_user"("target_user_id" "uuid", "reason" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_soft_delete_user"("target_user_id" "uuid", "reason" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_soft_delete_user"("target_user_id" "uuid", "reason" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."assign_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."assign_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."assign_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."assign_user_role"("profile_uuid" "uuid", "role_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."assign_user_role"("profile_uuid" "uuid", "role_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."assign_user_role"("profile_uuid" "uuid", "role_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."attach_user_to_batch_group"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."attach_user_to_batch_group"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."attach_user_to_batch_group"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."auto_confirm_email"() TO "anon";
GRANT ALL ON FUNCTION "public"."auto_confirm_email"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."auto_confirm_email"() TO "service_role";



GRANT ALL ON FUNCTION "public"."auto_conversation_on_match"() TO "anon";
GRANT ALL ON FUNCTION "public"."auto_conversation_on_match"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."auto_conversation_on_match"() TO "service_role";



GRANT ALL ON FUNCTION "public"."check_bookmark_limit"() TO "anon";
GRANT ALL ON FUNCTION "public"."check_bookmark_limit"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_bookmark_limit"() TO "service_role";



GRANT ALL ON FUNCTION "public"."check_event_completed"() TO "anon";
GRANT ALL ON FUNCTION "public"."check_event_completed"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_event_completed"() TO "service_role";



GRANT ALL ON FUNCTION "public"."check_user_permission_bypass_rls"("profile_uuid" "uuid", "permission_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."check_user_permission_bypass_rls"("profile_uuid" "uuid", "permission_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_user_permission_bypass_rls"("profile_uuid" "uuid", "permission_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."check_user_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."check_user_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_user_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_conversation_for_mentorship"("mentor_uuid" "uuid", "mentee_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."create_conversation_for_mentorship"("mentor_uuid" "uuid", "mentee_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_conversation_for_mentorship"("mentor_uuid" "uuid", "mentee_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_event_with_agenda"("event_data" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."create_event_with_agenda"("event_data" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_event_with_agenda"("event_data" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_group_and_add_admin"("group_name" "text", "group_description" "text", "group_is_private" boolean, "group_tags" "text"[]) TO "anon";
GRANT ALL ON FUNCTION "public"."create_group_and_add_admin"("group_name" "text", "group_description" "text", "group_is_private" boolean, "group_tags" "text"[]) TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_group_and_add_admin"("group_name" "text", "group_description" "text", "group_is_private" boolean, "group_tags" "text"[]) TO "service_role";



GRANT ALL ON FUNCTION "public"."create_new_event"("event_data" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."create_new_event"("event_data" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_new_event"("event_data" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_notification"("user_id" "uuid", "notification_title" "text", "notification_message" "text", "notification_link" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."create_notification"("user_id" "uuid", "notification_title" "text", "notification_message" "text", "notification_link" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_notification"("user_id" "uuid", "notification_title" "text", "notification_message" "text", "notification_link" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_notification"("target_profile_id" "uuid", "notif_title" "text", "notif_message" "text", "notif_link" "text", "notif_type" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."create_notification"("target_profile_id" "uuid", "notif_title" "text", "notif_message" "text", "notif_link" "text", "notif_type" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_notification"("target_profile_id" "uuid", "notif_title" "text", "notif_message" "text", "notif_link" "text", "notif_type" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_notification"("recipient_id" "uuid", "sender_id" "uuid", "event_id" "uuid", "type" "text", "message" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."create_notification"("recipient_id" "uuid", "sender_id" "uuid", "event_id" "uuid", "type" "text", "message" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_notification"("recipient_id" "uuid", "sender_id" "uuid", "event_id" "uuid", "type" "text", "message" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_or_update_mentor_profile"("p_expertise" "text"[], "p_mentoring_statement" "text", "p_max_mentees" integer, "p_availability" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."create_or_update_mentor_profile"("p_expertise" "text"[], "p_mentoring_statement" "text", "p_max_mentees" integer, "p_availability" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_or_update_mentor_profile"("p_expertise" "text"[], "p_mentoring_statement" "text", "p_max_mentees" integer, "p_availability" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."drop_all_policies"("target_table" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."drop_all_policies"("target_table" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."drop_all_policies"("target_table" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."enqueue_user_hard_delete"("target_user_id" "uuid", "reason" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."enqueue_user_hard_delete"("target_user_id" "uuid", "reason" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."enqueue_user_hard_delete"("target_user_id" "uuid", "reason" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."event_changes_broadcast"() TO "anon";
GRANT ALL ON FUNCTION "public"."event_changes_broadcast"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."event_changes_broadcast"() TO "service_role";



GRANT ALL ON FUNCTION "public"."events_set_owner"() TO "anon";
GRANT ALL ON FUNCTION "public"."events_set_owner"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."events_set_owner"() TO "service_role";



GRANT ALL ON FUNCTION "public"."find_or_create_conversation"("other_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."find_or_create_conversation"("other_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."find_or_create_conversation"("other_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_add_group_creator"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_add_group_creator"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_add_group_creator"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_company_jobs_with_bookmarks"("p_company_id" "uuid", "p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."get_company_jobs_with_bookmarks"("p_company_id" "uuid", "p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_company_jobs_with_bookmarks"("p_company_id" "uuid", "p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_connection_status"("user_1_id" "uuid", "user_2_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_connection_status"("user_1_id" "uuid", "user_2_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_connection_status"("user_1_id" "uuid", "user_2_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_connections_count"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_connections_count"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_connections_count"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_dashboard_stats"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_dashboard_stats"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_dashboard_stats"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_jobs_with_bookmarks"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."get_jobs_with_bookmarks"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_jobs_with_bookmarks"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_jobs_with_bookmarks_v2"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."get_jobs_with_bookmarks_v2"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_jobs_with_bookmarks_v2"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_latest_message"("p_conversation_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_latest_message"("p_conversation_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_latest_message"("p_conversation_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_my_posted_jobs"("user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_my_posted_jobs"("user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_my_posted_jobs"("user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_my_posted_jobs"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."get_my_posted_jobs"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_my_posted_jobs"("p_search_query" "text", "p_sort_by" "text", "p_sort_order" "text", "p_limit" integer, "p_offset" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_my_role"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_my_role"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_my_role"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_or_create_conversation"("user_1_id" "uuid", "user_2_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_or_create_conversation"("user_1_id" "uuid", "user_2_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_or_create_conversation"("user_1_id" "uuid", "user_2_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_pending_approvals"("content_type" "text", "limit_count" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."get_pending_approvals"("content_type" "text", "limit_count" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_pending_approvals"("content_type" "text", "limit_count" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_pending_content"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_pending_content"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_pending_content"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_role_by_name"("role_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_role_by_name"("role_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_role_by_name"("role_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_role_id_by_name"("role_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_role_id_by_name"("role_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_role_id_by_name"("role_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_roles"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_roles"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_roles"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_table_columns"("table_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_table_columns"("table_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_table_columns"("table_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_types"("tname" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_types"("tname" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_types"("tname" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_unread_message_count"("conv_id" "uuid", "user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_unread_message_count"("conv_id" "uuid", "user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_unread_message_count"("conv_id" "uuid", "user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_unread_notifications_count"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_unread_notifications_count"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_unread_notifications_count"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_unread_notifications_count"("profile_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_unread_notifications_count"("profile_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_unread_notifications_count"("profile_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_unread_notifications_count_by_type"("type_filter" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_unread_notifications_count_by_type"("type_filter" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_unread_notifications_count_by_type"("type_filter" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_analytics"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_analytics"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_analytics"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_analytics_old_109720"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_analytics_old_109720"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_analytics_old_109720"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_conversations"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_conversations"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_conversations"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_conversations_v2"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_conversations_v2"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_conversations_v2"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_permissions"("profile_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_permissions"("profile_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_permissions"("profile_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_permissions_bypass_rls"("profile_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_permissions_bypass_rls"("profile_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_permissions_bypass_rls"("profile_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_role"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_role"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_role"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_user_role"("p_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_user_role"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_role"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_role"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_roles_bypass_rls"("profile_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_roles_bypass_rls"("profile_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_roles_bypass_rls"("profile_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_view_columns"("view_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_view_columns"("view_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_view_columns"("view_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_new_group"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_new_group"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_new_group"() TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_updated_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."has_permission"("user_id" "uuid", "permission_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."has_permission"("user_id" "uuid", "permission_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."has_permission"("user_id" "uuid", "permission_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_admin"() TO "anon";
GRANT ALL ON FUNCTION "public"."is_admin"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_admin"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."is_admin"("p_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_admin"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_admin"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_admin"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_connected"("a" "uuid", "b" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_connected"("a" "uuid", "b" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_connected"("a" "uuid", "b" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_conversation_participant"("p_conversation_id" "uuid", "p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_conversation_participant"("p_conversation_id" "uuid", "p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_conversation_participant"("p_conversation_id" "uuid", "p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_group_admin"("gid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_group_admin"("gid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_group_admin"("gid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_group_admin"("p_user_id" "uuid", "p_group_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_group_admin"("p_user_id" "uuid", "p_group_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_group_admin"("p_user_id" "uuid", "p_group_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_member_of_group"("p_group_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_member_of_group"("p_group_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_member_of_group"("p_group_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."join_group"("group_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."join_group"("group_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."join_group"("group_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."list_tables"() TO "anon";
GRANT ALL ON FUNCTION "public"."list_tables"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."list_tables"() TO "service_role";



GRANT ALL ON FUNCTION "public"."mark_conversation_as_read"("p_conversation_id" "uuid", "p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."mark_conversation_as_read"("p_conversation_id" "uuid", "p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."mark_conversation_as_read"("p_conversation_id" "uuid", "p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."mark_notification_as_read"("notification_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."mark_notification_as_read"("notification_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."mark_notification_as_read"("notification_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."moddatetime"() TO "postgres";
GRANT ALL ON FUNCTION "public"."moddatetime"() TO "anon";
GRANT ALL ON FUNCTION "public"."moddatetime"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."moddatetime"() TO "service_role";



GRANT ALL ON FUNCTION "public"."moderate_content"("p_content_id" "uuid", "p_content_type" "text", "p_action" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."moderate_content"("p_content_id" "uuid", "p_content_type" "text", "p_action" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."moderate_content"("p_content_id" "uuid", "p_content_type" "text", "p_action" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."moderate_content"("content_table" "text", "content_id" "uuid", "is_approved" boolean, "rejection_reason" "text", "content_type" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."moderate_content"("content_table" "text", "content_id" "uuid", "is_approved" boolean, "rejection_reason" "text", "content_type" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."moderate_content"("content_table" "text", "content_id" "uuid", "is_approved" boolean, "rejection_reason" "text", "content_type" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_admins_on_event"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_admins_on_event"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_admins_on_event"() TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_connection_approved"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_connection_approved"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_connection_approved"() TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_event_rsvp"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_event_rsvp"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_event_rsvp"() TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_job_application_submitted"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_job_application_submitted"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_job_application_submitted"() TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_mentorship_request"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_mentorship_request"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_mentorship_request"() TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_new_connection_request"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_new_connection_request"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_new_connection_request"() TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_new_message"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_new_message"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_new_message"() TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_on_job_application"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_on_job_application"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_on_job_application"() TO "service_role";



GRANT ALL ON FUNCTION "public"."notify_profile_verification"() TO "anon";
GRANT ALL ON FUNCTION "public"."notify_profile_verification"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."notify_profile_verification"() TO "service_role";



GRANT ALL ON FUNCTION "public"."profiles_normalize_names"() TO "anon";
GRANT ALL ON FUNCTION "public"."profiles_normalize_names"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."profiles_normalize_names"() TO "service_role";



GRANT ALL ON FUNCTION "public"."protect_jobs_admin_columns"() TO "anon";
GRANT ALL ON FUNCTION "public"."protect_jobs_admin_columns"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."protect_jobs_admin_columns"() TO "service_role";



GRANT ALL ON FUNCTION "public"."protect_mentors_admin_columns"() TO "anon";
GRANT ALL ON FUNCTION "public"."protect_mentors_admin_columns"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."protect_mentors_admin_columns"() TO "service_role";



GRANT ALL ON FUNCTION "public"."protect_profile_admin_columns"() TO "anon";
GRANT ALL ON FUNCTION "public"."protect_profile_admin_columns"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."protect_profile_admin_columns"() TO "service_role";



GRANT ALL ON FUNCTION "public"."purge_user_data"("uid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."purge_user_data"("uid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."purge_user_data"("uid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."remove_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."remove_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."remove_role_bypass_rls"("profile_uuid" "uuid", "role_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."remove_user_role"("profile_uuid" "uuid", "role_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."remove_user_role"("profile_uuid" "uuid", "role_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."remove_user_role"("profile_uuid" "uuid", "role_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."rsvp_to_event"("p_event_id" "uuid", "p_attendee_id" "uuid", "p_attendance_status_text" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."rsvp_to_event"("p_event_id" "uuid", "p_attendee_id" "uuid", "p_attendance_status_text" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."rsvp_to_event"("p_event_id" "uuid", "p_attendee_id" "uuid", "p_attendance_status_text" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."safe_to_jsonb"("_txt" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."safe_to_jsonb"("_txt" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."safe_to_jsonb"("_txt" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."set_group_creator"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_group_creator"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_group_creator"() TO "service_role";



GRANT ALL ON FUNCTION "public"."set_group_creator_as_admin"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_group_creator_as_admin"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_group_creator_as_admin"() TO "service_role";



GRANT ALL ON FUNCTION "public"."set_group_member_user_id"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_group_member_user_id"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_group_member_user_id"() TO "service_role";



GRANT ALL ON FUNCTION "public"."set_job_owner_default"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_job_owner_default"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_job_owner_default"() TO "service_role";



GRANT ALL ON FUNCTION "public"."start_or_get_conversation"("other_user" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."start_or_get_conversation"("other_user" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."start_or_get_conversation"("other_user" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."sync_is_approved_from_status"() TO "anon";
GRANT ALL ON FUNCTION "public"."sync_is_approved_from_status"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."sync_is_approved_from_status"() TO "service_role";



GRANT ALL ON FUNCTION "public"."trg_attach_user_to_batch_group"() TO "anon";
GRANT ALL ON FUNCTION "public"."trg_attach_user_to_batch_group"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."trg_attach_user_to_batch_group"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_conversation_last_message"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_conversation_last_message"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_conversation_last_message"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_conversation_last_message_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_conversation_last_message_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_conversation_last_message_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_conversation_last_message_timestamp"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_conversation_last_message_timestamp"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_conversation_last_message_timestamp"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_conversation_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_conversation_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_conversation_updated_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_event_published_status"("event_id" "uuid", "status_value" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."update_event_published_status"("event_id" "uuid", "status_value" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_event_published_status"("event_id" "uuid", "status_value" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."update_event_status_rpc"("event_id" "uuid", "new_status" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."update_event_status_rpc"("event_id" "uuid", "new_status" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_event_status_rpc"("event_id" "uuid", "new_status" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."update_full_name"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_full_name"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_full_name"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_updated_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_user_role"("user_id" "uuid", "new_role" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."update_user_role"("user_id" "uuid", "new_role" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_user_role"("user_id" "uuid", "new_role" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."user_has_permission"("profile_uuid" "uuid", "permission_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."user_has_permission"("profile_uuid" "uuid", "permission_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."user_has_permission"("profile_uuid" "uuid", "permission_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."user_has_role"("profile_uuid" "uuid", "role_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."user_has_role"("profile_uuid" "uuid", "role_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."user_has_role"("profile_uuid" "uuid", "role_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_profile_fields"() TO "anon";
GRANT ALL ON FUNCTION "public"."validate_profile_fields"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_profile_fields"() TO "service_role";

































GRANT ALL ON TABLE "public"."achievements" TO "anon";
GRANT ALL ON TABLE "public"."achievements" TO "authenticated";
GRANT ALL ON TABLE "public"."achievements" TO "service_role";



GRANT ALL ON TABLE "public"."activity_log" TO "anon";
GRANT ALL ON TABLE "public"."activity_log" TO "authenticated";
GRANT ALL ON TABLE "public"."activity_log" TO "service_role";



GRANT ALL ON TABLE "public"."activity_logs" TO "anon";
GRANT ALL ON TABLE "public"."activity_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."activity_logs" TO "service_role";



GRANT ALL ON TABLE "public"."admin_actions" TO "anon";
GRANT ALL ON TABLE "public"."admin_actions" TO "authenticated";
GRANT ALL ON TABLE "public"."admin_actions" TO "service_role";



GRANT ALL ON TABLE "public"."admin_invalid_degree_programs_audit" TO "anon";
GRANT ALL ON TABLE "public"."admin_invalid_degree_programs_audit" TO "authenticated";
GRANT ALL ON TABLE "public"."admin_invalid_degree_programs_audit" TO "service_role";



GRANT ALL ON TABLE "public"."backup_bad_conversations_20250905" TO "anon";
GRANT ALL ON TABLE "public"."backup_bad_conversations_20250905" TO "authenticated";
GRANT ALL ON TABLE "public"."backup_bad_conversations_20250905" TO "service_role";



GRANT ALL ON TABLE "public"."backup_bad_conversations_20250905_json" TO "anon";
GRANT ALL ON TABLE "public"."backup_bad_conversations_20250905_json" TO "authenticated";
GRANT ALL ON TABLE "public"."backup_bad_conversations_20250905_json" TO "service_role";



GRANT ALL ON TABLE "public"."bookmarked_jobs" TO "anon";
GRANT ALL ON TABLE "public"."bookmarked_jobs" TO "authenticated";
GRANT ALL ON TABLE "public"."bookmarked_jobs" TO "service_role";



GRANT ALL ON SEQUENCE "public"."bookmarked_jobs_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."bookmarked_jobs_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."bookmarked_jobs_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."clarification_requests" TO "anon";
GRANT ALL ON TABLE "public"."clarification_requests" TO "authenticated";
GRANT ALL ON TABLE "public"."clarification_requests" TO "service_role";



GRANT ALL ON TABLE "public"."companies" TO "anon";
GRANT ALL ON TABLE "public"."companies" TO "authenticated";
GRANT ALL ON TABLE "public"."companies" TO "service_role";



GRANT ALL ON TABLE "public"."connections" TO "anon";
GRANT ALL ON TABLE "public"."connections" TO "authenticated";
GRANT ALL ON TABLE "public"."connections" TO "service_role";



GRANT ALL ON TABLE "public"."content_approvals" TO "anon";
GRANT ALL ON TABLE "public"."content_approvals" TO "authenticated";
GRANT ALL ON TABLE "public"."content_approvals" TO "service_role";



GRANT ALL ON SEQUENCE "public"."content_approvals_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."content_approvals_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."content_approvals_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."content_moderation" TO "anon";
GRANT ALL ON TABLE "public"."content_moderation" TO "authenticated";
GRANT ALL ON TABLE "public"."content_moderation" TO "service_role";



GRANT ALL ON TABLE "public"."conversation_participants" TO "anon";
GRANT ALL ON TABLE "public"."conversation_participants" TO "authenticated";
GRANT ALL ON TABLE "public"."conversation_participants" TO "service_role";



GRANT ALL ON TABLE "public"."conversations" TO "anon";
GRANT ALL ON TABLE "public"."conversations" TO "authenticated";
GRANT ALL ON TABLE "public"."conversations" TO "service_role";



GRANT ALL ON TABLE "public"."csv_import_history" TO "anon";
GRANT ALL ON TABLE "public"."csv_import_history" TO "authenticated";
GRANT ALL ON TABLE "public"."csv_import_history" TO "service_role";



GRANT ALL ON TABLE "public"."degrees" TO "anon";
GRANT ALL ON TABLE "public"."degrees" TO "authenticated";
GRANT ALL ON TABLE "public"."degrees" TO "service_role";



GRANT ALL ON TABLE "public"."deletion_queue" TO "anon";
GRANT ALL ON TABLE "public"."deletion_queue" TO "authenticated";
GRANT ALL ON TABLE "public"."deletion_queue" TO "service_role";



GRANT ALL ON TABLE "public"."event_feedback" TO "anon";
GRANT ALL ON TABLE "public"."event_feedback" TO "authenticated";
GRANT ALL ON TABLE "public"."event_feedback" TO "service_role";



GRANT ALL ON TABLE "public"."events" TO "anon";
GRANT ALL ON TABLE "public"."events" TO "authenticated";
GRANT ALL ON TABLE "public"."events" TO "service_role";



GRANT ALL ON TABLE "public"."detailed_event_feedback" TO "anon";
GRANT ALL ON TABLE "public"."detailed_event_feedback" TO "authenticated";
GRANT ALL ON TABLE "public"."detailed_event_feedback" TO "service_role";



GRANT ALL ON TABLE "public"."education_history" TO "anon";
GRANT ALL ON TABLE "public"."education_history" TO "authenticated";
GRANT ALL ON TABLE "public"."education_history" TO "service_role";



GRANT ALL ON TABLE "public"."event_attendees" TO "anon";
GRANT ALL ON TABLE "public"."event_attendees" TO "authenticated";
GRANT ALL ON TABLE "public"."event_attendees" TO "service_role";



GRANT ALL ON TABLE "public"."event_attendees_with_profiles" TO "anon";
GRANT ALL ON TABLE "public"."event_attendees_with_profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."event_attendees_with_profiles" TO "service_role";



GRANT ALL ON TABLE "public"."event_groups" TO "anon";
GRANT ALL ON TABLE "public"."event_groups" TO "authenticated";
GRANT ALL ON TABLE "public"."event_groups" TO "service_role";



GRANT ALL ON TABLE "public"."event_rsvps" TO "anon";
GRANT ALL ON TABLE "public"."event_rsvps" TO "authenticated";
GRANT ALL ON TABLE "public"."event_rsvps" TO "service_role";



GRANT ALL ON TABLE "public"."event_stats" TO "anon";
GRANT ALL ON TABLE "public"."event_stats" TO "authenticated";
GRANT ALL ON TABLE "public"."event_stats" TO "service_role";



GRANT ALL ON TABLE "public"."feature_flags" TO "anon";
GRANT ALL ON TABLE "public"."feature_flags" TO "authenticated";
GRANT ALL ON TABLE "public"."feature_flags" TO "service_role";



GRANT ALL ON TABLE "public"."group_members" TO "anon";
GRANT ALL ON TABLE "public"."group_members" TO "authenticated";
GRANT ALL ON TABLE "public"."group_members" TO "service_role";



GRANT ALL ON TABLE "public"."group_posts" TO "anon";
GRANT ALL ON TABLE "public"."group_posts" TO "authenticated";
GRANT ALL ON TABLE "public"."group_posts" TO "service_role";



GRANT ALL ON TABLE "public"."groups" TO "anon";
GRANT ALL ON TABLE "public"."groups" TO "authenticated";
GRANT ALL ON TABLE "public"."groups" TO "service_role";



GRANT ALL ON TABLE "public"."job_alert_notifications" TO "anon";
GRANT ALL ON TABLE "public"."job_alert_notifications" TO "authenticated";
GRANT ALL ON TABLE "public"."job_alert_notifications" TO "service_role";



GRANT ALL ON TABLE "public"."job_alerts" TO "anon";
GRANT ALL ON TABLE "public"."job_alerts" TO "authenticated";
GRANT ALL ON TABLE "public"."job_alerts" TO "service_role";



GRANT ALL ON TABLE "public"."job_applications" TO "anon";
GRANT ALL ON TABLE "public"."job_applications" TO "authenticated";
GRANT ALL ON TABLE "public"."job_applications" TO "service_role";



GRANT ALL ON TABLE "public"."job_bookmarks" TO "anon";
GRANT ALL ON TABLE "public"."job_bookmarks" TO "authenticated";
GRANT ALL ON TABLE "public"."job_bookmarks" TO "service_role";



GRANT ALL ON TABLE "public"."jobs" TO "anon";
GRANT ALL ON TABLE "public"."jobs" TO "authenticated";
GRANT ALL ON TABLE "public"."jobs" TO "service_role";



GRANT ALL ON TABLE "public"."job_postings" TO "anon";
GRANT ALL ON TABLE "public"."job_postings" TO "authenticated";
GRANT ALL ON TABLE "public"."job_postings" TO "service_role";



GRANT ALL ON TABLE "public"."mentee_profiles" TO "anon";
GRANT ALL ON TABLE "public"."mentee_profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."mentee_profiles" TO "service_role";



GRANT ALL ON TABLE "public"."mentees" TO "anon";
GRANT ALL ON TABLE "public"."mentees" TO "authenticated";
GRANT ALL ON TABLE "public"."mentees" TO "service_role";



GRANT ALL ON TABLE "public"."mentor_availability" TO "anon";
GRANT ALL ON TABLE "public"."mentor_availability" TO "authenticated";
GRANT ALL ON TABLE "public"."mentor_availability" TO "service_role";



GRANT ALL ON TABLE "public"."mentor_profiles" TO "anon";
GRANT ALL ON TABLE "public"."mentor_profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."mentor_profiles" TO "service_role";



GRANT ALL ON TABLE "public"."mentors" TO "anon";
GRANT ALL ON TABLE "public"."mentors" TO "authenticated";
GRANT ALL ON TABLE "public"."mentors" TO "service_role";



GRANT ALL ON TABLE "public"."mentorship_appointments" TO "anon";
GRANT ALL ON TABLE "public"."mentorship_appointments" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorship_appointments" TO "service_role";



GRANT ALL ON TABLE "public"."mentorship_feedback" TO "anon";
GRANT ALL ON TABLE "public"."mentorship_feedback" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorship_feedback" TO "service_role";



GRANT ALL ON TABLE "public"."mentorship_messages" TO "anon";
GRANT ALL ON TABLE "public"."mentorship_messages" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorship_messages" TO "service_role";



GRANT ALL ON TABLE "public"."mentorship_programs" TO "anon";
GRANT ALL ON TABLE "public"."mentorship_programs" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorship_programs" TO "service_role";



GRANT ALL ON TABLE "public"."mentorship_relationships" TO "anon";
GRANT ALL ON TABLE "public"."mentorship_relationships" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorship_relationships" TO "service_role";



GRANT ALL ON TABLE "public"."mentorship_requests" TO "anon";
GRANT ALL ON TABLE "public"."mentorship_requests" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorship_requests" TO "service_role";



GRANT ALL ON TABLE "public"."mentorship_sessions" TO "anon";
GRANT ALL ON TABLE "public"."mentorship_sessions" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorship_sessions" TO "service_role";



GRANT ALL ON TABLE "public"."mentorship_stats" TO "anon";
GRANT ALL ON TABLE "public"."mentorship_stats" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorship_stats" TO "service_role";



GRANT ALL ON TABLE "public"."mentorships" TO "anon";
GRANT ALL ON TABLE "public"."mentorships" TO "authenticated";
GRANT ALL ON TABLE "public"."mentorships" TO "service_role";



GRANT ALL ON TABLE "public"."messages" TO "anon";
GRANT ALL ON TABLE "public"."messages" TO "authenticated";
GRANT ALL ON TABLE "public"."messages" TO "service_role";



GRANT ALL ON TABLE "public"."networking_group_members" TO "anon";
GRANT ALL ON TABLE "public"."networking_group_members" TO "authenticated";
GRANT ALL ON TABLE "public"."networking_group_members" TO "service_role";



GRANT ALL ON TABLE "public"."networking_groups" TO "anon";
GRANT ALL ON TABLE "public"."networking_groups" TO "authenticated";
GRANT ALL ON TABLE "public"."networking_groups" TO "service_role";



GRANT ALL ON TABLE "public"."notification_preferences" TO "anon";
GRANT ALL ON TABLE "public"."notification_preferences" TO "authenticated";
GRANT ALL ON TABLE "public"."notification_preferences" TO "service_role";



GRANT ALL ON TABLE "public"."notifications" TO "anon";
GRANT ALL ON TABLE "public"."notifications" TO "authenticated";
GRANT ALL ON TABLE "public"."notifications" TO "service_role";



GRANT ALL ON TABLE "public"."permissions" TO "anon";
GRANT ALL ON TABLE "public"."permissions" TO "authenticated";
GRANT ALL ON TABLE "public"."permissions" TO "service_role";



GRANT ALL ON TABLE "public"."public_profiles_view" TO "anon";
GRANT ALL ON TABLE "public"."public_profiles_view" TO "authenticated";
GRANT ALL ON TABLE "public"."public_profiles_view" TO "service_role";



GRANT ALL ON TABLE "public"."resources" TO "anon";
GRANT ALL ON TABLE "public"."resources" TO "authenticated";
GRANT ALL ON TABLE "public"."resources" TO "service_role";



GRANT ALL ON TABLE "public"."resume_profiles" TO "anon";
GRANT ALL ON TABLE "public"."resume_profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."resume_profiles" TO "service_role";



GRANT ALL ON TABLE "public"."role_permissions" TO "anon";
GRANT ALL ON TABLE "public"."role_permissions" TO "authenticated";
GRANT ALL ON TABLE "public"."role_permissions" TO "service_role";



GRANT ALL ON TABLE "public"."roles" TO "anon";
GRANT ALL ON TABLE "public"."roles" TO "authenticated";
GRANT ALL ON TABLE "public"."roles" TO "service_role";



GRANT ALL ON TABLE "public"."social_links" TO "anon";
GRANT ALL ON TABLE "public"."social_links" TO "authenticated";
GRANT ALL ON TABLE "public"."social_links" TO "service_role";



GRANT ALL ON SEQUENCE "public"."social_links_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."social_links_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."social_links_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."system_alerts" TO "anon";
GRANT ALL ON TABLE "public"."system_alerts" TO "authenticated";
GRANT ALL ON TABLE "public"."system_alerts" TO "service_role";



GRANT ALL ON TABLE "public"."system_analytics" TO "anon";
GRANT ALL ON TABLE "public"."system_analytics" TO "authenticated";
GRANT ALL ON TABLE "public"."system_analytics" TO "service_role";



GRANT ALL ON TABLE "public"."user_activity_logs" TO "anon";
GRANT ALL ON TABLE "public"."user_activity_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."user_activity_logs" TO "service_role";



GRANT ALL ON TABLE "public"."user_feedback" TO "anon";
GRANT ALL ON TABLE "public"."user_feedback" TO "authenticated";
GRANT ALL ON TABLE "public"."user_feedback" TO "service_role";



GRANT ALL ON TABLE "public"."user_jobs_with_bookmark" TO "anon";
GRANT ALL ON TABLE "public"."user_jobs_with_bookmark" TO "authenticated";
GRANT ALL ON TABLE "public"."user_jobs_with_bookmark" TO "service_role";



GRANT ALL ON TABLE "public"."user_resumes" TO "anon";
GRANT ALL ON TABLE "public"."user_resumes" TO "authenticated";
GRANT ALL ON TABLE "public"."user_resumes" TO "service_role";



GRANT ALL ON TABLE "public"."user_roles" TO "anon";
GRANT ALL ON TABLE "public"."user_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."user_roles" TO "service_role";



GRANT ALL ON TABLE "public"."v_profiles_directory_card" TO "anon";
GRANT ALL ON TABLE "public"."v_profiles_directory_card" TO "authenticated";
GRANT ALL ON TABLE "public"."v_profiles_directory_card" TO "service_role";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "service_role";






























RESET ALL;
