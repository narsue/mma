DROP TABLE {}.user_payment;
CREATE TABLE IF NOT EXISTS {}.user_payment (user_payment_id uuid, user_id uuid, class_id uuid, class_start_ts timestamp, base_payment_plan_id uuid, group_user_ids set<uuid>, payment_plan_id uuid, status int, stripe_payment_id text, created_ts timestamp, paid decimal, amount decimal, refunded decimal, refunded_ts timestamp, paid_ts timestamp, processing_ts timestamp, processing_node text, captured_ts timestamp, captured decimal, PRIMARY KEY (user_payment_id));
CREATE TABLE IF NOT EXISTS {}.user_payment_history (user_payment_id uuid, user_id uuid, captured_ts timestamp, captured decimal, PRIMARY KEY (user_id, user_payment_id));
ALTER TABLE {}.payment_plan ADD admin_restricted boolean;
