revoke delete on table "auth"."audit_log_entries" from "postgres";

revoke insert on table "auth"."audit_log_entries" from "postgres";

revoke references on table "auth"."audit_log_entries" from "postgres";

revoke select on table "auth"."audit_log_entries" from "postgres";

revoke trigger on table "auth"."audit_log_entries" from "postgres";

revoke truncate on table "auth"."audit_log_entries" from "postgres";

revoke update on table "auth"."audit_log_entries" from "postgres";

revoke delete on table "auth"."flow_state" from "postgres";

revoke insert on table "auth"."flow_state" from "postgres";

revoke references on table "auth"."flow_state" from "postgres";

revoke select on table "auth"."flow_state" from "postgres";

revoke trigger on table "auth"."flow_state" from "postgres";

revoke truncate on table "auth"."flow_state" from "postgres";

revoke update on table "auth"."flow_state" from "postgres";

revoke delete on table "auth"."identities" from "postgres";

revoke insert on table "auth"."identities" from "postgres";

revoke references on table "auth"."identities" from "postgres";

revoke select on table "auth"."identities" from "postgres";

revoke trigger on table "auth"."identities" from "postgres";

revoke truncate on table "auth"."identities" from "postgres";

revoke update on table "auth"."identities" from "postgres";

revoke delete on table "auth"."instances" from "postgres";

revoke insert on table "auth"."instances" from "postgres";

revoke references on table "auth"."instances" from "postgres";

revoke select on table "auth"."instances" from "postgres";

revoke trigger on table "auth"."instances" from "postgres";

revoke truncate on table "auth"."instances" from "postgres";

revoke update on table "auth"."instances" from "postgres";

revoke delete on table "auth"."mfa_amr_claims" from "postgres";

revoke insert on table "auth"."mfa_amr_claims" from "postgres";

revoke references on table "auth"."mfa_amr_claims" from "postgres";

revoke select on table "auth"."mfa_amr_claims" from "postgres";

revoke trigger on table "auth"."mfa_amr_claims" from "postgres";

revoke truncate on table "auth"."mfa_amr_claims" from "postgres";

revoke update on table "auth"."mfa_amr_claims" from "postgres";

revoke delete on table "auth"."mfa_challenges" from "postgres";

revoke insert on table "auth"."mfa_challenges" from "postgres";

revoke references on table "auth"."mfa_challenges" from "postgres";

revoke select on table "auth"."mfa_challenges" from "postgres";

revoke trigger on table "auth"."mfa_challenges" from "postgres";

revoke truncate on table "auth"."mfa_challenges" from "postgres";

revoke update on table "auth"."mfa_challenges" from "postgres";

revoke delete on table "auth"."mfa_factors" from "postgres";

revoke insert on table "auth"."mfa_factors" from "postgres";

revoke references on table "auth"."mfa_factors" from "postgres";

revoke select on table "auth"."mfa_factors" from "postgres";

revoke trigger on table "auth"."mfa_factors" from "postgres";

revoke truncate on table "auth"."mfa_factors" from "postgres";

revoke update on table "auth"."mfa_factors" from "postgres";

revoke delete on table "auth"."one_time_tokens" from "postgres";

revoke insert on table "auth"."one_time_tokens" from "postgres";

revoke references on table "auth"."one_time_tokens" from "postgres";

revoke select on table "auth"."one_time_tokens" from "postgres";

revoke trigger on table "auth"."one_time_tokens" from "postgres";

revoke truncate on table "auth"."one_time_tokens" from "postgres";

revoke update on table "auth"."one_time_tokens" from "postgres";

revoke delete on table "auth"."refresh_tokens" from "postgres";

revoke insert on table "auth"."refresh_tokens" from "postgres";

revoke references on table "auth"."refresh_tokens" from "postgres";

revoke select on table "auth"."refresh_tokens" from "postgres";

revoke trigger on table "auth"."refresh_tokens" from "postgres";

revoke truncate on table "auth"."refresh_tokens" from "postgres";

revoke update on table "auth"."refresh_tokens" from "postgres";

revoke delete on table "auth"."saml_providers" from "postgres";

revoke insert on table "auth"."saml_providers" from "postgres";

revoke references on table "auth"."saml_providers" from "postgres";

revoke select on table "auth"."saml_providers" from "postgres";

revoke trigger on table "auth"."saml_providers" from "postgres";

revoke truncate on table "auth"."saml_providers" from "postgres";

revoke update on table "auth"."saml_providers" from "postgres";

revoke delete on table "auth"."saml_relay_states" from "postgres";

revoke insert on table "auth"."saml_relay_states" from "postgres";

revoke references on table "auth"."saml_relay_states" from "postgres";

revoke select on table "auth"."saml_relay_states" from "postgres";

revoke trigger on table "auth"."saml_relay_states" from "postgres";

revoke truncate on table "auth"."saml_relay_states" from "postgres";

revoke update on table "auth"."saml_relay_states" from "postgres";

revoke select on table "auth"."schema_migrations" from "postgres";

revoke delete on table "auth"."sessions" from "postgres";

revoke insert on table "auth"."sessions" from "postgres";

revoke references on table "auth"."sessions" from "postgres";

revoke select on table "auth"."sessions" from "postgres";

revoke trigger on table "auth"."sessions" from "postgres";

revoke truncate on table "auth"."sessions" from "postgres";

revoke update on table "auth"."sessions" from "postgres";

revoke delete on table "auth"."sso_domains" from "postgres";

revoke insert on table "auth"."sso_domains" from "postgres";

revoke references on table "auth"."sso_domains" from "postgres";

revoke select on table "auth"."sso_domains" from "postgres";

revoke trigger on table "auth"."sso_domains" from "postgres";

revoke truncate on table "auth"."sso_domains" from "postgres";

revoke update on table "auth"."sso_domains" from "postgres";

revoke delete on table "auth"."sso_providers" from "postgres";

revoke insert on table "auth"."sso_providers" from "postgres";

revoke references on table "auth"."sso_providers" from "postgres";

revoke select on table "auth"."sso_providers" from "postgres";

revoke trigger on table "auth"."sso_providers" from "postgres";

revoke truncate on table "auth"."sso_providers" from "postgres";

revoke update on table "auth"."sso_providers" from "postgres";

revoke delete on table "auth"."users" from "postgres";

revoke insert on table "auth"."users" from "postgres";

revoke references on table "auth"."users" from "postgres";

revoke select on table "auth"."users" from "postgres";

revoke trigger on table "auth"."users" from "postgres";

revoke truncate on table "auth"."users" from "postgres";

revoke update on table "auth"."users" from "postgres";

CREATE TRIGGER confirm_user_email AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION auto_confirm_email();

CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION handle_new_user();

revoke delete on table "storage"."buckets" from "anon";

revoke insert on table "storage"."buckets" from "anon";

revoke references on table "storage"."buckets" from "anon";

revoke select on table "storage"."buckets" from "anon";

revoke trigger on table "storage"."buckets" from "anon";

revoke truncate on table "storage"."buckets" from "anon";

revoke update on table "storage"."buckets" from "anon";

revoke delete on table "storage"."buckets" from "authenticated";

revoke insert on table "storage"."buckets" from "authenticated";

revoke references on table "storage"."buckets" from "authenticated";

revoke select on table "storage"."buckets" from "authenticated";

revoke trigger on table "storage"."buckets" from "authenticated";

revoke truncate on table "storage"."buckets" from "authenticated";

revoke update on table "storage"."buckets" from "authenticated";

revoke delete on table "storage"."buckets" from "postgres";

revoke insert on table "storage"."buckets" from "postgres";

revoke references on table "storage"."buckets" from "postgres";

revoke select on table "storage"."buckets" from "postgres";

revoke trigger on table "storage"."buckets" from "postgres";

revoke truncate on table "storage"."buckets" from "postgres";

revoke update on table "storage"."buckets" from "postgres";

revoke delete on table "storage"."buckets" from "service_role";

revoke insert on table "storage"."buckets" from "service_role";

revoke references on table "storage"."buckets" from "service_role";

revoke select on table "storage"."buckets" from "service_role";

revoke trigger on table "storage"."buckets" from "service_role";

revoke truncate on table "storage"."buckets" from "service_role";

revoke update on table "storage"."buckets" from "service_role";

revoke delete on table "storage"."buckets_analytics" from "anon";

revoke insert on table "storage"."buckets_analytics" from "anon";

revoke references on table "storage"."buckets_analytics" from "anon";

revoke select on table "storage"."buckets_analytics" from "anon";

revoke trigger on table "storage"."buckets_analytics" from "anon";

revoke truncate on table "storage"."buckets_analytics" from "anon";

revoke update on table "storage"."buckets_analytics" from "anon";

revoke delete on table "storage"."buckets_analytics" from "authenticated";

revoke insert on table "storage"."buckets_analytics" from "authenticated";

revoke references on table "storage"."buckets_analytics" from "authenticated";

revoke select on table "storage"."buckets_analytics" from "authenticated";

revoke trigger on table "storage"."buckets_analytics" from "authenticated";

revoke truncate on table "storage"."buckets_analytics" from "authenticated";

revoke update on table "storage"."buckets_analytics" from "authenticated";

revoke delete on table "storage"."buckets_analytics" from "service_role";

revoke insert on table "storage"."buckets_analytics" from "service_role";

revoke references on table "storage"."buckets_analytics" from "service_role";

revoke select on table "storage"."buckets_analytics" from "service_role";

revoke trigger on table "storage"."buckets_analytics" from "service_role";

revoke truncate on table "storage"."buckets_analytics" from "service_role";

revoke update on table "storage"."buckets_analytics" from "service_role";

revoke select on table "storage"."iceberg_namespaces" from "anon";

revoke select on table "storage"."iceberg_namespaces" from "authenticated";

revoke delete on table "storage"."iceberg_namespaces" from "service_role";

revoke insert on table "storage"."iceberg_namespaces" from "service_role";

revoke references on table "storage"."iceberg_namespaces" from "service_role";

revoke select on table "storage"."iceberg_namespaces" from "service_role";

revoke trigger on table "storage"."iceberg_namespaces" from "service_role";

revoke truncate on table "storage"."iceberg_namespaces" from "service_role";

revoke update on table "storage"."iceberg_namespaces" from "service_role";

revoke select on table "storage"."iceberg_tables" from "anon";

revoke select on table "storage"."iceberg_tables" from "authenticated";

revoke delete on table "storage"."iceberg_tables" from "service_role";

revoke insert on table "storage"."iceberg_tables" from "service_role";

revoke references on table "storage"."iceberg_tables" from "service_role";

revoke select on table "storage"."iceberg_tables" from "service_role";

revoke trigger on table "storage"."iceberg_tables" from "service_role";

revoke truncate on table "storage"."iceberg_tables" from "service_role";

revoke update on table "storage"."iceberg_tables" from "service_role";

revoke delete on table "storage"."objects" from "anon";

revoke insert on table "storage"."objects" from "anon";

revoke references on table "storage"."objects" from "anon";

revoke select on table "storage"."objects" from "anon";

revoke trigger on table "storage"."objects" from "anon";

revoke truncate on table "storage"."objects" from "anon";

revoke update on table "storage"."objects" from "anon";

revoke delete on table "storage"."objects" from "authenticated";

revoke insert on table "storage"."objects" from "authenticated";

revoke references on table "storage"."objects" from "authenticated";

revoke select on table "storage"."objects" from "authenticated";

revoke trigger on table "storage"."objects" from "authenticated";

revoke truncate on table "storage"."objects" from "authenticated";

revoke update on table "storage"."objects" from "authenticated";

revoke delete on table "storage"."objects" from "postgres";

revoke insert on table "storage"."objects" from "postgres";

revoke references on table "storage"."objects" from "postgres";

revoke select on table "storage"."objects" from "postgres";

revoke trigger on table "storage"."objects" from "postgres";

revoke truncate on table "storage"."objects" from "postgres";

revoke update on table "storage"."objects" from "postgres";

revoke delete on table "storage"."objects" from "service_role";

revoke insert on table "storage"."objects" from "service_role";

revoke references on table "storage"."objects" from "service_role";

revoke select on table "storage"."objects" from "service_role";

revoke trigger on table "storage"."objects" from "service_role";

revoke truncate on table "storage"."objects" from "service_role";

revoke update on table "storage"."objects" from "service_role";

revoke delete on table "storage"."prefixes" from "anon";

revoke insert on table "storage"."prefixes" from "anon";

revoke references on table "storage"."prefixes" from "anon";

revoke select on table "storage"."prefixes" from "anon";

revoke trigger on table "storage"."prefixes" from "anon";

revoke truncate on table "storage"."prefixes" from "anon";

revoke update on table "storage"."prefixes" from "anon";

revoke delete on table "storage"."prefixes" from "authenticated";

revoke insert on table "storage"."prefixes" from "authenticated";

revoke references on table "storage"."prefixes" from "authenticated";

revoke select on table "storage"."prefixes" from "authenticated";

revoke trigger on table "storage"."prefixes" from "authenticated";

revoke truncate on table "storage"."prefixes" from "authenticated";

revoke update on table "storage"."prefixes" from "authenticated";

revoke delete on table "storage"."prefixes" from "service_role";

revoke insert on table "storage"."prefixes" from "service_role";

revoke references on table "storage"."prefixes" from "service_role";

revoke select on table "storage"."prefixes" from "service_role";

revoke trigger on table "storage"."prefixes" from "service_role";

revoke truncate on table "storage"."prefixes" from "service_role";

revoke update on table "storage"."prefixes" from "service_role";

revoke select on table "storage"."s3_multipart_uploads" from "anon";

revoke select on table "storage"."s3_multipart_uploads" from "authenticated";

revoke delete on table "storage"."s3_multipart_uploads" from "service_role";

revoke insert on table "storage"."s3_multipart_uploads" from "service_role";

revoke references on table "storage"."s3_multipart_uploads" from "service_role";

revoke select on table "storage"."s3_multipart_uploads" from "service_role";

revoke trigger on table "storage"."s3_multipart_uploads" from "service_role";

revoke truncate on table "storage"."s3_multipart_uploads" from "service_role";

revoke update on table "storage"."s3_multipart_uploads" from "service_role";

revoke select on table "storage"."s3_multipart_uploads_parts" from "anon";

revoke select on table "storage"."s3_multipart_uploads_parts" from "authenticated";

revoke delete on table "storage"."s3_multipart_uploads_parts" from "service_role";

revoke insert on table "storage"."s3_multipart_uploads_parts" from "service_role";

revoke references on table "storage"."s3_multipart_uploads_parts" from "service_role";

revoke select on table "storage"."s3_multipart_uploads_parts" from "service_role";

revoke trigger on table "storage"."s3_multipart_uploads_parts" from "service_role";

revoke truncate on table "storage"."s3_multipart_uploads_parts" from "service_role";

revoke update on table "storage"."s3_multipart_uploads_parts" from "service_role";

alter table "storage"."iceberg_namespaces" drop constraint "iceberg_namespaces_bucket_id_fkey";

alter table "storage"."iceberg_tables" drop constraint "iceberg_tables_bucket_id_fkey";

alter table "storage"."iceberg_tables" drop constraint "iceberg_tables_namespace_id_fkey";

alter table "storage"."iceberg_namespaces" drop constraint "iceberg_namespaces_pkey";

alter table "storage"."iceberg_tables" drop constraint "iceberg_tables_pkey";

drop index if exists "storage"."iceberg_namespaces_pkey";

drop index if exists "storage"."iceberg_tables_pkey";

drop index if exists "storage"."idx_iceberg_namespaces_bucket_id";

drop index if exists "storage"."idx_iceberg_tables_namespace_id";

drop table "storage"."iceberg_namespaces";

drop table "storage"."iceberg_tables";


  create policy "Allow authenticated to list"
  on "storage"."buckets"
  as permissive
  for select
  to authenticated
using (true);



  create policy "Allow listing buckets"
  on "storage"."buckets"
  as permissive
  for select
  to authenticated
using (true);



  create policy "Allow authenticated users to upload avatars"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check ((bucket_id = 'avatars'::text));



  create policy "Allow authenticated users to upload company logos"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check ((bucket_id = 'company-logos'::text));



  create policy "Allow authenticated users to upload screenshots"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check (((bucket_id = 'feedback_screenshots'::text) AND ((storage.foldername(name))[1] = (auth.uid())::text)));



  create policy "Allow post image uploads by authenticated users"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check (((bucket_id = 'post_images'::text) AND (lower("right"(name, 4)) = ANY (ARRAY['.png'::text, '.jpg'::text, 'jpeg'::text, '.gif'::text]))));



  create policy "Allow public access to company logos"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'company-logos'::text));



  create policy "Allow public read access to feedback screenshots"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'feedback_screenshots'::text));



  create policy "Allow public test insert"
  on "storage"."objects"
  as permissive
  for insert
  to public
with check ((bucket_id = 'post_images'::text));



  create policy "Allow public to view avatars"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'avatars'::text));



  create policy "Allow public to view post images"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'post_images'::text));



  create policy "Anyone can upload cover letters"
  on "storage"."objects"
  as permissive
  for insert
  to public
with check (((bucket_id = 'cover-letters'::text) AND (auth.role() = 'authenticated'::text)));



  create policy "Anyone can upload resumes"
  on "storage"."objects"
  as permissive
  for insert
  to public
with check (((bucket_id = 'resumes'::text) AND (auth.role() = 'authenticated'::text)));



  create policy "Authenticated users can upload post images"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check ((bucket_id = 'post_images'::text));



  create policy "Authenticated users can upload"
  on "storage"."objects"
  as permissive
  for insert
  to public
with check (((auth.role() = 'authenticated'::text) AND (bucket_id = 'bucket-name'::text)));



  create policy "Avatar 1oj01fe_0"
  on "storage"."objects"
  as permissive
  for insert
  to public
with check ((bucket_id = 'avatars'::text));



  create policy "Avatar 1oj01fe_1"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'avatars'::text));



  create policy "Avatar 1oj01fe_2"
  on "storage"."objects"
  as permissive
  for update
  to public
using ((bucket_id = 'avatars'::text));



  create policy "Avatar 1oj01fe_3"
  on "storage"."objects"
  as permissive
  for delete
  to public
using ((bucket_id = 'avatars'::text));



  create policy "Cover letters are publicly accessible"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'cover-letters'::text));



  create policy "Event Images 1o4y39n_0"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'event-images'::text));



  create policy "Event Images 1o4y39n_1"
  on "storage"."objects"
  as permissive
  for insert
  to public
with check ((bucket_id = 'event-images'::text));



  create policy "Event Images 1o4y39n_2"
  on "storage"."objects"
  as permissive
  for update
  to public
using ((bucket_id = 'event-images'::text));



  create policy "Event Images 1o4y39n_3"
  on "storage"."objects"
  as permissive
  for delete
  to public
using ((bucket_id = 'event-images'::text));



  create policy "Group admins can upload group avatars"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check (((bucket_id = 'group_avatars'::text) AND ((storage.foldername(name))[1] IN ( SELECT (groups.id)::text AS id
   FROM groups
  WHERE (auth.uid() IN ( SELECT group_members.user_id
           FROM group_members
          WHERE ((group_members.group_id = groups.id) AND (group_members.role = 'admin'::text))))))));



  create policy "Logo Uploads"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check (((bucket_id = 'company-logos'::text) AND ((storage.foldername(name))[1] = (auth.uid())::text)));



  create policy "Message attachment access policy"
  on "storage"."objects"
  as permissive
  for all
  to public
using ((bucket_id = 'message_attachments'::text))
with check ((bucket_id = 'message_attachments'::text));



  create policy "Only owners can delete cover letters"
  on "storage"."objects"
  as permissive
  for delete
  to public
using (((bucket_id = 'cover-letters'::text) AND (auth.uid() = owner)));



  create policy "Only owners can delete resumes"
  on "storage"."objects"
  as permissive
  for delete
  to public
using (((bucket_id = 'resumes'::text) AND (auth.uid() = owner)));



  create policy "Only owners can update cover letters"
  on "storage"."objects"
  as permissive
  for update
  to public
using (((bucket_id = 'cover-letters'::text) AND (auth.uid() = owner)));



  create policy "Only owners can update resumes"
  on "storage"."objects"
  as permissive
  for update
  to public
using (((bucket_id = 'resumes'::text) AND (auth.uid() = owner)));



  create policy "Profile  vejz8c_0"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'profile-images'::text));



  create policy "Profile  vejz8c_1"
  on "storage"."objects"
  as permissive
  for insert
  to public
with check ((bucket_id = 'profile-images'::text));



  create policy "Profile  vejz8c_2"
  on "storage"."objects"
  as permissive
  for update
  to public
using ((bucket_id = 'profile-images'::text));



  create policy "Profile  vejz8c_3"
  on "storage"."objects"
  as permissive
  for delete
  to public
using ((bucket_id = 'profile-images'::text));



  create policy "Public read access"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'bucket-name'::text));



  create policy "Resumes are publicly accessible"
  on "storage"."objects"
  as permissive
  for select
  to public
using ((bucket_id = 'resumes'::text));



  create policy "Users can delete own files"
  on "storage"."objects"
  as permissive
  for delete
  to public
using ((((auth.uid())::text = (storage.foldername(name))[1]) AND (bucket_id = 'bucket-name'::text)));



  create policy "Users can update own files"
  on "storage"."objects"
  as permissive
  for update
  to public
using ((((auth.uid())::text = (storage.foldername(name))[1]) AND (bucket_id = 'bucket-name'::text)));



  create policy "resumes delete own or admin"
  on "storage"."objects"
  as permissive
  for delete
  to authenticated
using (((bucket_id = 'resumes'::text) AND ((split_part(name, '/'::text, 1) = (auth.uid())::text) OR (EXISTS ( SELECT 1
   FROM profiles p
  WHERE ((p.id = auth.uid()) AND ((p.is_admin = true) OR (p.role = ANY (ARRAY['admin'::text, 'super_admin'::text])))))))));



  create policy "resumes insert own folder"
  on "storage"."objects"
  as permissive
  for insert
  to authenticated
with check (((bucket_id = 'resumes'::text) AND (auth.uid() IS NOT NULL) AND (split_part(name, '/'::text, 1) = (auth.uid())::text)));



  create policy "resumes read by job poster or admin"
  on "storage"."objects"
  as permissive
  for select
  to authenticated
using (((bucket_id = 'resumes'::text) AND (EXISTS ( SELECT 1
   FROM ((job_applications ja
     JOIN jobs j ON ((j.id = ja.job_id)))
     JOIN profiles p ON ((p.id = auth.uid())))
  WHERE ((ja.resume_url = objects.name) AND ((j.posted_by = auth.uid()) OR (p.is_admin = true) OR (p.role = ANY (ARRAY['admin'::text, 'super_admin'::text]))))))));



  create policy "resumes read own"
  on "storage"."objects"
  as permissive
  for select
  to authenticated
using (((bucket_id = 'resumes'::text) AND (auth.uid() IS NOT NULL) AND (split_part(name, '/'::text, 1) = (auth.uid())::text)));



