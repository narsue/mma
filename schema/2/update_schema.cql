CREATE TABLE IF NOT EXISTS {}.payment_plan (school_id uuid, payment_plan_id uuid, base_payment_plan_id uuid, grouping_id int, min_age int, max_age int, working boolean, title text, description text, cost decimal, duration_id int, deleted_ts timestamp, created_ts timestamp, PRIMARY KEY(school_id, base_payment_plan_id, payment_plan_id));
CREATE TABLE IF NOT EXISTS {}.user_payment (user_payment_id uuid, user_id uuid, class_id uuid, class_start_ts timestamp, base_payment_plan_id uuid, group_user_ids set<uuid>, payment_plan_id uuid, status int, stripe_payment_id text, created_ts timestamp, paid decimal, amount decimal, refunded decimal, refunded_ts timestamp, paid_ts timestamp, processing_ts timestamp, processing_node text, captured_ts timestamp, captured decimal, PRIMARY KEY (user_id, base_payment_plan_id, class_id, class_start_ts));
CREATE TABLE IF NOT EXISTS {}.user_payment_plan (user_payment_plan_id uuid, user_id uuid, base_payment_plan_id uuid, payment_plan_id uuid, group_user_ids set<uuid>, next_group_user_ids set<uuid>, created_ts timestamp, expiration_ts timestamp, subscribed boolean, PRIMARY KEY(user_id, user_payment_plan_id));
CREATE TABLE IF NOT EXISTS {}.time_span (school_id uuid, duration_id int, created_ts timestamp, end_dates SET<date>, PRIMARY KEY(school_id, duration_id));

alter table {}.user add (dependents SET<uuid>, guardians SET<uuid>, payment_provider uuid, payment_dependents SET<uuid>, active_payment_plans SET<TUPLE<uuid,timestamp>>);
alter table {}.attendance add (user_payment_id uuid, user_payment_plan_id uuid);
alter table {}.school add timezone text;

CREATE TABLE IF NOT EXISTS {}.class_attendance_locks ( class_id uuid, class_start_ts timestamp, PRIMARY KEY(class_id, class_start_ts) ) WITH default_time_to_live = 5;