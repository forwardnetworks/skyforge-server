--
-- PostgreSQL database dump
--


-- Dumped from database version 16.12
-- Dumped by pg_dump version 18.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: sf_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_audit_log (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_username text NOT NULL,
    actor_is_admin boolean DEFAULT false NOT NULL,
    impersonated_username text,
    action text NOT NULL,
    user_id text,
    details text
);


--
-- Name: sf_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_audit_log_id_seq OWNED BY public.sf_audit_log.id;


--
-- Name: sf_aws_device_auth_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_aws_device_auth_requests (
    request_id text NOT NULL,
    username text NOT NULL,
    region text NOT NULL,
    start_url text NOT NULL,
    device_code text NOT NULL,
    user_code text NOT NULL,
    verification_uri_complete text NOT NULL,
    interval_seconds integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_aws_sso_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_aws_sso_tokens (
    username text NOT NULL,
    start_url text NOT NULL,
    region text NOT NULL,
    client_id text,
    client_secret text,
    client_secret_expires_at timestamp with time zone,
    access_token text,
    access_token_expires_at timestamp with time zone,
    refresh_token text,
    refresh_token_expires_at timestamp with time zone,
    last_authenticated_at_utc timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_capacity_nqe_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_capacity_nqe_cache (
    id bigint NOT NULL,
    user_id text NOT NULL,
    deployment_id uuid,
    forward_network_id text NOT NULL,
    query_id text NOT NULL,
    snapshot_id text DEFAULT ''::text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_capacity_nqe_cache_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_capacity_nqe_cache_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_capacity_nqe_cache_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_capacity_nqe_cache_id_seq OWNED BY public.sf_capacity_nqe_cache.id;


--
-- Name: sf_capacity_rollups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_capacity_rollups (
    id bigint NOT NULL,
    user_id text NOT NULL,
    deployment_id uuid,
    forward_network_id text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    metric text NOT NULL,
    window_label text NOT NULL,
    period_end timestamp with time zone NOT NULL,
    samples integer DEFAULT 0 NOT NULL,
    avg double precision,
    p95 double precision,
    p99 double precision,
    max double precision,
    slope_per_day double precision,
    forecast_crossing_ts timestamp with time zone,
    threshold double precision,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_capacity_rollups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_capacity_rollups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_capacity_rollups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_capacity_rollups_id_seq OWNED BY public.sf_capacity_rollups.id;


--
-- Name: sf_cloud_credential_status; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_cloud_credential_status (
    key text NOT NULL,
    ok boolean NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_cost_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_cost_snapshots (
    id uuid NOT NULL,
    resource_id uuid,
    user_id text,
    provider text NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    cost_amount numeric NOT NULL,
    cost_currency text DEFAULT 'USD'::text NOT NULL,
    source text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_deployment_ui_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_deployment_ui_events (
    id bigint NOT NULL,
    user_id text NOT NULL,
    deployment_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    event_type text DEFAULT ''::text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: sf_deployment_ui_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_deployment_ui_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_deployment_ui_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_deployment_ui_events_id_seq OWNED BY public.sf_deployment_ui_events.id;


--
-- Name: sf_deployments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_deployments (
    id uuid NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    type text NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_task_user_id integer,
    last_task_id integer,
    last_status text,
    last_started_at timestamp with time zone,
    last_finished_at timestamp with time zone,
    CONSTRAINT sf_deployments_type_check CHECK ((type = ANY (ARRAY['terraform'::text, 'netlab'::text, 'netlab-c9s'::text, 'eve_ng'::text, 'containerlab'::text, 'clabernetes'::text])))
);


--
-- Name: sf_dns_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_dns_tokens (
    username text NOT NULL,
    token text NOT NULL,
    zone text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_forward_device_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_forward_device_types (
    device_key text NOT NULL,
    forward_type text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_ldap_password_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_ldap_password_cache (
    username text NOT NULL,
    encrypted_password text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_node_metric_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_node_metric_snapshots (
    node text NOT NULL,
    metric_name text NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    metric_json jsonb NOT NULL
);


--
-- Name: sf_notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_notifications (
    id uuid NOT NULL,
    username text NOT NULL,
    title text NOT NULL,
    message text,
    type text NOT NULL,
    category text,
    reference_id text,
    priority text,
    is_read boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_policy_report_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_policy_report_audit_log (
    id bigint NOT NULL,
    user_id text NOT NULL,
    actor_username text NOT NULL,
    action text NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_policy_report_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_policy_report_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_policy_report_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_policy_report_audit_log_id_seq OWNED BY public.sf_policy_report_audit_log.id;


--
-- Name: sf_policy_report_exceptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_policy_report_exceptions (
    id uuid NOT NULL,
    user_id text NOT NULL,
    finding_id text NOT NULL,
    check_id text NOT NULL,
    status text DEFAULT 'PROPOSED'::text NOT NULL,
    justification text NOT NULL,
    ticket_url text,
    expires_at timestamp with time zone,
    created_by text NOT NULL,
    approved_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    forward_network_id text DEFAULT ''::text NOT NULL,
    CONSTRAINT sf_policy_report_exceptions_status_check CHECK ((status = ANY (ARRAY['PROPOSED'::text, 'APPROVED'::text, 'REJECTED'::text, 'EXPIRED'::text])))
);


--
-- Name: sf_policy_report_forward_network_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_policy_report_forward_network_credentials (
    user_id text NOT NULL,
    username text NOT NULL,
    forward_network_id text NOT NULL,
    base_url_enc text NOT NULL,
    forward_username_enc text NOT NULL,
    forward_password_enc text NOT NULL,
    skip_tls_verify boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_policy_report_forward_networks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_policy_report_forward_networks (
    id uuid NOT NULL,
    user_id text NOT NULL,
    forward_network_id text NOT NULL,
    name text NOT NULL,
    description text,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    collector_config_id text
);


--
-- Name: sf_policy_report_recert_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_policy_report_recert_assignments (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    user_id text NOT NULL,
    finding_id text NOT NULL,
    check_id text NOT NULL,
    assignee_username text,
    status text DEFAULT 'PENDING'::text NOT NULL,
    justification text,
    attested_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    finding jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT sf_policy_report_recert_assignments_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'ATTESTED'::text, 'WAIVED'::text])))
);


--
-- Name: sf_policy_report_recert_campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_policy_report_recert_campaigns (
    id uuid NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    description text,
    forward_network_id text NOT NULL,
    snapshot_id text DEFAULT ''::text NOT NULL,
    pack_id text NOT NULL,
    status text DEFAULT 'OPEN'::text NOT NULL,
    due_at timestamp with time zone,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sf_policy_report_recert_campaigns_status_check CHECK ((status = ANY (ARRAY['OPEN'::text, 'CLOSED'::text])))
);


--
-- Name: sf_user_scope_eve_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_eve_servers (
    id uuid NOT NULL,
    user_scope_id text NOT NULL,
    name text NOT NULL,
    api_url text NOT NULL,
    web_url text,
    skip_tls_verify boolean DEFAULT false NOT NULL,
    ssh_host text,
    ssh_user text,
    ssh_key text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    api_user text,
    api_password text
);


--
-- Name: sf_user_scope_netlab_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_netlab_servers (
    id uuid NOT NULL,
    user_scope_id text NOT NULL,
    name text NOT NULL,
    api_url text NOT NULL,
    api_insecure boolean DEFAULT true NOT NULL,
    api_token text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    api_user text,
    api_password text
);


--
-- Name: sf_user_scope_variable_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_variable_groups (
    id bigint NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    variables jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_scope_variable_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_user_scope_variable_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_user_scope_variable_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_user_scope_variable_groups_id_seq OWNED BY public.sf_user_scope_variable_groups.id;


--
-- Name: sf_resource_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_resource_events (
    id uuid NOT NULL,
    resource_id uuid,
    event_type text NOT NULL,
    actor_username text,
    actor_is_admin boolean DEFAULT false NOT NULL,
    impersonated_username text,
    user_id text,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_resources (
    id uuid NOT NULL,
    provider text NOT NULL,
    resource_id text NOT NULL,
    resource_type text NOT NULL,
    user_id text,
    name text,
    region text,
    account_id text,
    owner_username text,
    status text,
    tags jsonb DEFAULT '{}'::jsonb NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_settings (
    key text NOT NULL,
    value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_snmp_trap_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_snmp_trap_events (
    id bigint NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    username text,
    source_ip inet,
    community text,
    oid text,
    vars_json text,
    raw_hex text
);


--
-- Name: sf_snmp_trap_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_snmp_trap_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_snmp_trap_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_snmp_trap_events_id_seq OWNED BY public.sf_snmp_trap_events.id;


--
-- Name: sf_snmp_trap_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_snmp_trap_tokens (
    username text NOT NULL,
    community text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_syslog_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_syslog_events (
    id bigint NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    source_ip inet NOT NULL,
    hostname text,
    app_name text,
    proc_id text,
    msg_id text,
    facility integer,
    severity integer,
    message text,
    raw text NOT NULL
);


--
-- Name: sf_syslog_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_syslog_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_syslog_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_syslog_events_id_seq OWNED BY public.sf_syslog_events.id;


--
-- Name: sf_syslog_routes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_syslog_routes (
    source_cidr cidr NOT NULL,
    owner_username text NOT NULL,
    label text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_task_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_task_events (
    id bigint NOT NULL,
    task_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    event_type text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: sf_task_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_task_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_task_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_task_events_id_seq OWNED BY public.sf_task_events.id;


--
-- Name: sf_task_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_task_logs (
    id bigint NOT NULL,
    task_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    stream text DEFAULT 'stdout'::text NOT NULL,
    output text NOT NULL
);


--
-- Name: sf_task_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_task_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_task_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_task_logs_id_seq OWNED BY public.sf_task_logs.id;


--
-- Name: sf_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_tasks (
    id bigint NOT NULL,
    user_id text NOT NULL,
    deployment_id uuid,
    task_type text NOT NULL,
    status text NOT NULL,
    message text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    error text,
    priority integer DEFAULT 0 NOT NULL
);


--
-- Name: sf_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_tasks_id_seq OWNED BY public.sf_tasks.id;


--
-- Name: sf_taskworker_heartbeats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_taskworker_heartbeats (
    instance text NOT NULL,
    last_seen timestamp with time zone NOT NULL
);


--
-- Name: sf_template_indexes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_template_indexes (
    kind text NOT NULL,
    owner text NOT NULL,
    repo text NOT NULL,
    branch text NOT NULL,
    dir text NOT NULL,
    head_sha text NOT NULL,
    templates jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_usage_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_usage_snapshots (
    id uuid NOT NULL,
    user_id text,
    provider text NOT NULL,
    scope_type text NOT NULL,
    scope_id text,
    metric text NOT NULL,
    value numeric NOT NULL,
    unit text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    collected_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_aws_sso_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_aws_sso_credentials (
    username text NOT NULL,
    start_url text NOT NULL,
    region text NOT NULL,
    account_id text NOT NULL,
    role_name text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_aws_static_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_aws_static_credentials (
    username text NOT NULL,
    access_key_id text NOT NULL,
    secret_access_key text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_azure_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_azure_credentials (
    username text NOT NULL,
    tenant_id text NOT NULL,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    subscription_id text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_containerlab_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_containerlab_servers (
    id uuid NOT NULL,
    username text NOT NULL,
    name text NOT NULL,
    api_url text NOT NULL,
    api_insecure boolean DEFAULT true NOT NULL,
    api_user text,
    api_password text,
    api_token text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_eve_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_eve_servers (
    id uuid NOT NULL,
    username text NOT NULL,
    name text NOT NULL,
    api_url text NOT NULL,
    web_url text,
    skip_tls_verify boolean DEFAULT false NOT NULL,
    api_user text,
    api_password text,
    ssh_host text,
    ssh_user text,
    ssh_key text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_forward_collectors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_forward_collectors (
    id text NOT NULL,
    username text NOT NULL,
    name text NOT NULL,
    base_url text NOT NULL,
    skip_tls_verify boolean DEFAULT false NOT NULL,
    forward_username text NOT NULL,
    forward_password text NOT NULL,
    collector_id text,
    collector_username text,
    authorization_key text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    is_default boolean DEFAULT false NOT NULL
);


--
-- Name: sf_user_gcp_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_gcp_credentials (
    username text NOT NULL,
    service_account_json text NOT NULL,
    project_id_override text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_git_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_git_credentials (
    username text NOT NULL,
    ssh_public_key text,
    ssh_private_key text,
    https_username text,
    https_token text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_ibm_cloud_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_ibm_cloud_credentials (
    username text NOT NULL,
    api_key text NOT NULL,
    region text NOT NULL,
    resource_group_id text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_netlab_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_netlab_servers (
    id uuid NOT NULL,
    username text NOT NULL,
    name text NOT NULL,
    api_url text NOT NULL,
    api_insecure boolean DEFAULT true NOT NULL,
    api_user text,
    api_password text,
    api_token text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_servicenow_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_servicenow_configs (
    username text NOT NULL,
    instance_url text NOT NULL,
    admin_username text NOT NULL,
    admin_password text NOT NULL,
    forward_base_url text NOT NULL,
    forward_username text NOT NULL,
    forward_password text NOT NULL,
    last_install_status text DEFAULT ''::text NOT NULL,
    last_install_error text DEFAULT ''::text NOT NULL,
    last_install_started_at timestamp with time zone,
    last_install_finished_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    forward_collector_config_id text DEFAULT ''::text NOT NULL
);


--
-- Name: sf_user_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_settings (
    user_id text NOT NULL,
    default_forward_collector_config_id text DEFAULT ''::text NOT NULL,
    default_env_json text DEFAULT '[]'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    external_template_repos_json text DEFAULT '[]'::text NOT NULL
);


--
-- Name: sf_user_variable_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_variable_groups (
    id integer NOT NULL,
    username text NOT NULL,
    name text NOT NULL,
    variables jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_variable_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_user_variable_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_user_variable_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_user_variable_groups_id_seq OWNED BY public.sf_user_variable_groups.id;


--
-- Name: sf_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_users (
    username text NOT NULL,
    display_name text,
    email text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone
);


--
-- Name: sf_webhook_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_webhook_events (
    id bigint NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    username text,
    token text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    source_ip inet,
    headers_json text,
    body text
);


--
-- Name: sf_webhook_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sf_webhook_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sf_webhook_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sf_webhook_events_id_seq OWNED BY public.sf_webhook_events.id;


--
-- Name: sf_webhook_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_webhook_tokens (
    username text NOT NULL,
    token text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_scope_aws_static_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_aws_static_credentials (
    user_id text NOT NULL,
    access_key_id text NOT NULL,
    secret_access_key text NOT NULL,
    session_token text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_scope_azure_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_azure_credentials (
    user_id text NOT NULL,
    tenant_id text NOT NULL,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    subscription_id text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_scope_forward_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_forward_credentials (
    user_id text NOT NULL,
    base_url text NOT NULL,
    username text NOT NULL,
    password text NOT NULL,
    device_username text,
    device_password text,
    jump_host text,
    jump_username text,
    jump_private_key text,
    jump_cert text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    collector_id text,
    collector_username text
);


--
-- Name: sf_user_scope_gcp_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_gcp_credentials (
    user_id text NOT NULL,
    service_account_json text NOT NULL,
    project_id_override text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sf_user_scope_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_groups (
    user_id text NOT NULL,
    group_name text NOT NULL,
    role text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sf_project_groups_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'editor'::text, 'viewer'::text])))
);


--
-- Name: sf_user_scope_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scope_members (
    user_id text NOT NULL,
    username text NOT NULL,
    role text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sf_project_members_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'editor'::text, 'viewer'::text])))
);


--
-- Name: sf_user_scopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sf_user_scopes (
    id text NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text NOT NULL,
    blueprint text,
    default_branch text,
    terraform_state_key text,
    terraform_init_template_id integer,
    terraform_plan_template_id integer,
    terraform_apply_template_id integer,
    ansible_run_template_id integer,
    netlab_run_template_id integer,
    aws_account_id text,
    aws_role_name text,
    aws_region text,
    aws_auth_method text,
    artifacts_bucket text,
    eve_server text,
    netlab_server text,
    gitea_owner text NOT NULL,
    gitea_repo text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_public boolean DEFAULT false NOT NULL,
    eve_ng_run_template_id integer,
    containerlab_run_template_id integer,
    allow_external_template_repos boolean DEFAULT false NOT NULL,
    allow_custom_eve_servers boolean DEFAULT false NOT NULL,
    allow_custom_netlab_servers boolean DEFAULT false NOT NULL,
    external_template_repos jsonb DEFAULT '[]'::jsonb NOT NULL,
    allow_custom_containerlab_servers boolean DEFAULT false NOT NULL
);


--
-- Name: sf_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_audit_log ALTER COLUMN id SET DEFAULT nextval('public.sf_audit_log_id_seq'::regclass);


--
-- Name: sf_capacity_nqe_cache id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_capacity_nqe_cache ALTER COLUMN id SET DEFAULT nextval('public.sf_capacity_nqe_cache_id_seq'::regclass);


--
-- Name: sf_capacity_rollups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_capacity_rollups ALTER COLUMN id SET DEFAULT nextval('public.sf_capacity_rollups_id_seq'::regclass);


--
-- Name: sf_deployment_ui_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_deployment_ui_events ALTER COLUMN id SET DEFAULT nextval('public.sf_deployment_ui_events_id_seq'::regclass);


--
-- Name: sf_policy_report_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_audit_log ALTER COLUMN id SET DEFAULT nextval('public.sf_policy_report_audit_log_id_seq'::regclass);


--
-- Name: sf_snmp_trap_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_snmp_trap_events ALTER COLUMN id SET DEFAULT nextval('public.sf_snmp_trap_events_id_seq'::regclass);


--
-- Name: sf_syslog_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_syslog_events ALTER COLUMN id SET DEFAULT nextval('public.sf_syslog_events_id_seq'::regclass);


--
-- Name: sf_task_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_task_events ALTER COLUMN id SET DEFAULT nextval('public.sf_task_events_id_seq'::regclass);


--
-- Name: sf_task_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_task_logs ALTER COLUMN id SET DEFAULT nextval('public.sf_task_logs_id_seq'::regclass);


--
-- Name: sf_tasks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_tasks ALTER COLUMN id SET DEFAULT nextval('public.sf_tasks_id_seq'::regclass);


--
-- Name: sf_user_variable_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_variable_groups ALTER COLUMN id SET DEFAULT nextval('public.sf_user_variable_groups_id_seq'::regclass);


--
-- Name: sf_webhook_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_webhook_events ALTER COLUMN id SET DEFAULT nextval('public.sf_webhook_events_id_seq'::regclass);


--
-- Name: sf_user_scope_variable_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_variable_groups ALTER COLUMN id SET DEFAULT nextval('public.sf_user_scope_variable_groups_id_seq'::regclass);


--
-- Name: sf_audit_log sf_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_audit_log
    ADD CONSTRAINT sf_audit_log_pkey PRIMARY KEY (id);


--
-- Name: sf_aws_device_auth_requests sf_aws_device_auth_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_aws_device_auth_requests
    ADD CONSTRAINT sf_aws_device_auth_requests_pkey PRIMARY KEY (request_id);


--
-- Name: sf_aws_sso_tokens sf_aws_sso_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_aws_sso_tokens
    ADD CONSTRAINT sf_aws_sso_tokens_pkey PRIMARY KEY (username);


--
-- Name: sf_capacity_nqe_cache sf_capacity_nqe_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_capacity_nqe_cache
    ADD CONSTRAINT sf_capacity_nqe_cache_pkey PRIMARY KEY (id);


--
-- Name: sf_capacity_rollups sf_capacity_rollups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_capacity_rollups
    ADD CONSTRAINT sf_capacity_rollups_pkey PRIMARY KEY (id);


--
-- Name: sf_cloud_credential_status sf_cloud_credential_status_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_cloud_credential_status
    ADD CONSTRAINT sf_cloud_credential_status_pkey PRIMARY KEY (key);


--
-- Name: sf_cost_snapshots sf_cost_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_cost_snapshots
    ADD CONSTRAINT sf_cost_snapshots_pkey PRIMARY KEY (id);


--
-- Name: sf_deployment_ui_events sf_deployment_ui_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_deployment_ui_events
    ADD CONSTRAINT sf_deployment_ui_events_pkey PRIMARY KEY (id);


--
-- Name: sf_deployments sf_deployments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_deployments
    ADD CONSTRAINT sf_deployments_pkey PRIMARY KEY (id);


--
-- Name: sf_dns_tokens sf_dns_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_dns_tokens
    ADD CONSTRAINT sf_dns_tokens_pkey PRIMARY KEY (username);


--
-- Name: sf_forward_device_types sf_forward_device_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_forward_device_types
    ADD CONSTRAINT sf_forward_device_types_pkey PRIMARY KEY (device_key);


--
-- Name: sf_ldap_password_cache sf_ldap_password_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_ldap_password_cache
    ADD CONSTRAINT sf_ldap_password_cache_pkey PRIMARY KEY (username);


--
-- Name: sf_node_metric_snapshots sf_node_metric_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_node_metric_snapshots
    ADD CONSTRAINT sf_node_metric_snapshots_pkey PRIMARY KEY (node, metric_name);


--
-- Name: sf_notifications sf_notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_notifications
    ADD CONSTRAINT sf_notifications_pkey PRIMARY KEY (id);


--
-- Name: sf_policy_report_audit_log sf_policy_report_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_audit_log
    ADD CONSTRAINT sf_policy_report_audit_log_pkey PRIMARY KEY (id);


--
-- Name: sf_policy_report_exceptions sf_policy_report_exceptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_exceptions
    ADD CONSTRAINT sf_policy_report_exceptions_pkey PRIMARY KEY (id);


--
-- Name: sf_policy_report_forward_networks sf_policy_report_forward_netw_user_scope_id_forward_network__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_forward_networks
    ADD CONSTRAINT sf_policy_report_forward_netw_user_scope_id_forward_network__key UNIQUE (user_id, forward_network_id);


--
-- Name: sf_policy_report_forward_network_credentials sf_policy_report_forward_network_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_forward_network_credentials
    ADD CONSTRAINT sf_policy_report_forward_network_credentials_pkey PRIMARY KEY (user_id, username, forward_network_id);


--
-- Name: sf_policy_report_forward_networks sf_policy_report_forward_networks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_forward_networks
    ADD CONSTRAINT sf_policy_report_forward_networks_pkey PRIMARY KEY (id);


--
-- Name: sf_policy_report_recert_assignments sf_policy_report_recert_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_recert_assignments
    ADD CONSTRAINT sf_policy_report_recert_assignments_pkey PRIMARY KEY (id);


--
-- Name: sf_policy_report_recert_campaigns sf_policy_report_recert_campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_recert_campaigns
    ADD CONSTRAINT sf_policy_report_recert_campaigns_pkey PRIMARY KEY (id);


--
-- Name: sf_user_scope_aws_static_credentials sf_project_aws_static_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_aws_static_credentials
    ADD CONSTRAINT sf_project_aws_static_credentials_pkey PRIMARY KEY (user_id);


--
-- Name: sf_user_scope_azure_credentials sf_project_azure_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_azure_credentials
    ADD CONSTRAINT sf_project_azure_credentials_pkey PRIMARY KEY (user_id);


--
-- Name: sf_user_scope_eve_servers sf_user_scope_eve_servers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_eve_servers
    ADD CONSTRAINT sf_user_scope_eve_servers_pkey PRIMARY KEY (id);


--
-- Name: sf_user_scope_eve_servers sf_user_scope_eve_servers_project_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_eve_servers
    ADD CONSTRAINT sf_user_scope_eve_servers_project_id_name_key UNIQUE (user_scope_id, name);


--
-- Name: sf_user_scope_forward_credentials sf_project_forward_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_forward_credentials
    ADD CONSTRAINT sf_project_forward_credentials_pkey PRIMARY KEY (user_id);


--
-- Name: sf_user_scope_gcp_credentials sf_project_gcp_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_gcp_credentials
    ADD CONSTRAINT sf_project_gcp_credentials_pkey PRIMARY KEY (user_id);


--
-- Name: sf_user_scope_groups sf_project_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_groups
    ADD CONSTRAINT sf_project_groups_pkey PRIMARY KEY (user_id, group_name);


--
-- Name: sf_user_scope_members sf_project_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_members
    ADD CONSTRAINT sf_project_members_pkey PRIMARY KEY (user_id, username);


--
-- Name: sf_user_scope_netlab_servers sf_user_scope_netlab_servers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_netlab_servers
    ADD CONSTRAINT sf_user_scope_netlab_servers_pkey PRIMARY KEY (id);


--
-- Name: sf_user_scope_netlab_servers sf_user_scope_netlab_servers_project_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_netlab_servers
    ADD CONSTRAINT sf_user_scope_netlab_servers_project_id_name_key UNIQUE (user_scope_id, name);


--
-- Name: sf_user_scope_variable_groups sf_project_variable_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_variable_groups
    ADD CONSTRAINT sf_project_variable_groups_pkey PRIMARY KEY (id);


--
-- Name: sf_user_scopes sf_projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scopes
    ADD CONSTRAINT sf_projects_pkey PRIMARY KEY (id);


--
-- Name: sf_user_scopes sf_projects_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scopes
    ADD CONSTRAINT sf_projects_slug_key UNIQUE (slug);


--
-- Name: sf_resource_events sf_resource_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_resource_events
    ADD CONSTRAINT sf_resource_events_pkey PRIMARY KEY (id);


--
-- Name: sf_resources sf_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_resources
    ADD CONSTRAINT sf_resources_pkey PRIMARY KEY (id);


--
-- Name: sf_settings sf_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_settings
    ADD CONSTRAINT sf_settings_pkey PRIMARY KEY (key);


--
-- Name: sf_snmp_trap_events sf_snmp_trap_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_snmp_trap_events
    ADD CONSTRAINT sf_snmp_trap_events_pkey PRIMARY KEY (id);


--
-- Name: sf_snmp_trap_tokens sf_snmp_trap_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_snmp_trap_tokens
    ADD CONSTRAINT sf_snmp_trap_tokens_pkey PRIMARY KEY (username);


--
-- Name: sf_syslog_events sf_syslog_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_syslog_events
    ADD CONSTRAINT sf_syslog_events_pkey PRIMARY KEY (id);


--
-- Name: sf_syslog_routes sf_syslog_routes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_syslog_routes
    ADD CONSTRAINT sf_syslog_routes_pkey PRIMARY KEY (source_cidr);


--
-- Name: sf_task_events sf_task_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_task_events
    ADD CONSTRAINT sf_task_events_pkey PRIMARY KEY (id);


--
-- Name: sf_task_logs sf_task_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_task_logs
    ADD CONSTRAINT sf_task_logs_pkey PRIMARY KEY (id);


--
-- Name: sf_tasks sf_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_tasks
    ADD CONSTRAINT sf_tasks_pkey PRIMARY KEY (id);


--
-- Name: sf_taskworker_heartbeats sf_taskworker_heartbeats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_taskworker_heartbeats
    ADD CONSTRAINT sf_taskworker_heartbeats_pkey PRIMARY KEY (instance);


--
-- Name: sf_template_indexes sf_template_indexes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_template_indexes
    ADD CONSTRAINT sf_template_indexes_pkey PRIMARY KEY (kind, owner, repo, branch, dir);


--
-- Name: sf_usage_snapshots sf_usage_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_usage_snapshots
    ADD CONSTRAINT sf_usage_snapshots_pkey PRIMARY KEY (id);


--
-- Name: sf_user_aws_sso_credentials sf_user_aws_sso_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_aws_sso_credentials
    ADD CONSTRAINT sf_user_aws_sso_credentials_pkey PRIMARY KEY (username);


--
-- Name: sf_user_aws_static_credentials sf_user_aws_static_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_aws_static_credentials
    ADD CONSTRAINT sf_user_aws_static_credentials_pkey PRIMARY KEY (username);


--
-- Name: sf_user_azure_credentials sf_user_azure_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_azure_credentials
    ADD CONSTRAINT sf_user_azure_credentials_pkey PRIMARY KEY (username);


--
-- Name: sf_user_containerlab_servers sf_user_containerlab_servers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_containerlab_servers
    ADD CONSTRAINT sf_user_containerlab_servers_pkey PRIMARY KEY (id);


--
-- Name: sf_user_containerlab_servers sf_user_containerlab_servers_username_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_containerlab_servers
    ADD CONSTRAINT sf_user_containerlab_servers_username_name_key UNIQUE (username, name);


--
-- Name: sf_user_eve_servers sf_user_eve_servers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_eve_servers
    ADD CONSTRAINT sf_user_eve_servers_pkey PRIMARY KEY (id);


--
-- Name: sf_user_eve_servers sf_user_eve_servers_username_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_eve_servers
    ADD CONSTRAINT sf_user_eve_servers_username_name_key UNIQUE (username, name);


--
-- Name: sf_user_forward_collectors sf_user_forward_collectors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_forward_collectors
    ADD CONSTRAINT sf_user_forward_collectors_pkey PRIMARY KEY (id);


--
-- Name: sf_user_gcp_credentials sf_user_gcp_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_gcp_credentials
    ADD CONSTRAINT sf_user_gcp_credentials_pkey PRIMARY KEY (username);


--
-- Name: sf_user_git_credentials sf_user_git_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_git_credentials
    ADD CONSTRAINT sf_user_git_credentials_pkey PRIMARY KEY (username);


--
-- Name: sf_user_ibm_cloud_credentials sf_user_ibm_cloud_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_ibm_cloud_credentials
    ADD CONSTRAINT sf_user_ibm_cloud_credentials_pkey PRIMARY KEY (username);


--
-- Name: sf_user_netlab_servers sf_user_netlab_servers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_netlab_servers
    ADD CONSTRAINT sf_user_netlab_servers_pkey PRIMARY KEY (id);


--
-- Name: sf_user_netlab_servers sf_user_netlab_servers_username_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_netlab_servers
    ADD CONSTRAINT sf_user_netlab_servers_username_name_key UNIQUE (username, name);


--
-- Name: sf_user_servicenow_configs sf_user_servicenow_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_servicenow_configs
    ADD CONSTRAINT sf_user_servicenow_configs_pkey PRIMARY KEY (username);


--
-- Name: sf_user_settings sf_user_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_settings
    ADD CONSTRAINT sf_user_settings_pkey PRIMARY KEY (user_id);


--
-- Name: sf_user_variable_groups sf_user_variable_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_variable_groups
    ADD CONSTRAINT sf_user_variable_groups_pkey PRIMARY KEY (id);


--
-- Name: sf_users sf_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_users
    ADD CONSTRAINT sf_users_pkey PRIMARY KEY (username);


--
-- Name: sf_webhook_events sf_webhook_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_webhook_events
    ADD CONSTRAINT sf_webhook_events_pkey PRIMARY KEY (id);


--
-- Name: sf_webhook_tokens sf_webhook_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_webhook_tokens
    ADD CONSTRAINT sf_webhook_tokens_pkey PRIMARY KEY (username);


--
-- Name: idx_sf_ldap_password_cache_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sf_ldap_password_cache_expires_at ON public.sf_ldap_password_cache USING btree (expires_at DESC);


--
-- Name: idx_sf_node_metric_snapshots_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sf_node_metric_snapshots_updated_at ON public.sf_node_metric_snapshots USING btree (updated_at DESC);


--
-- Name: idx_sf_taskworker_heartbeats_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sf_taskworker_heartbeats_last_seen ON public.sf_taskworker_heartbeats USING btree (last_seen DESC);


--
-- Name: idx_sf_template_indexes_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sf_template_indexes_updated_at ON public.sf_template_indexes USING btree (updated_at DESC);


--
-- Name: sf_audit_log_actor_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_audit_log_actor_idx ON public.sf_audit_log USING btree (actor_username);


--
-- Name: sf_audit_log_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_audit_log_created_at_idx ON public.sf_audit_log USING btree (created_at DESC);


--
-- Name: sf_aws_device_auth_requests_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_aws_device_auth_requests_user_idx ON public.sf_aws_device_auth_requests USING btree (username, expires_at DESC);


--
-- Name: sf_capacity_nqe_cache_fwd_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_capacity_nqe_cache_fwd_lookup_idx ON public.sf_capacity_nqe_cache USING btree (user_id, forward_network_id, query_id, created_at DESC) WHERE (deployment_id IS NULL);


--
-- Name: sf_capacity_nqe_cache_fwd_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_capacity_nqe_cache_fwd_uq ON public.sf_capacity_nqe_cache USING btree (user_id, forward_network_id, query_id, snapshot_id) WHERE (deployment_id IS NULL);


--
-- Name: sf_capacity_nqe_cache_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_capacity_nqe_cache_lookup_idx ON public.sf_capacity_nqe_cache USING btree (user_id, deployment_id, query_id, created_at DESC);


--
-- Name: sf_capacity_nqe_cache_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_capacity_nqe_cache_uq ON public.sf_capacity_nqe_cache USING btree (user_id, deployment_id, query_id, snapshot_id);


--
-- Name: sf_capacity_rollups_fwd_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_capacity_rollups_fwd_lookup_idx ON public.sf_capacity_rollups USING btree (user_id, forward_network_id, metric, window_label, period_end DESC) WHERE (deployment_id IS NULL);


--
-- Name: sf_capacity_rollups_fwd_object_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_capacity_rollups_fwd_object_idx ON public.sf_capacity_rollups USING btree (user_id, forward_network_id, object_type, object_id) WHERE (deployment_id IS NULL);


--
-- Name: sf_capacity_rollups_fwd_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_capacity_rollups_fwd_uq ON public.sf_capacity_rollups USING btree (user_id, forward_network_id, object_type, object_id, metric, window_label, period_end) WHERE (deployment_id IS NULL);


--
-- Name: sf_capacity_rollups_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_capacity_rollups_lookup_idx ON public.sf_capacity_rollups USING btree (user_id, deployment_id, metric, window_label, period_end DESC);


--
-- Name: sf_capacity_rollups_object_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_capacity_rollups_object_idx ON public.sf_capacity_rollups USING btree (user_id, deployment_id, object_type, object_id);


--
-- Name: sf_capacity_rollups_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_capacity_rollups_uq ON public.sf_capacity_rollups USING btree (user_id, deployment_id, object_type, object_id, metric, window_label, period_end);


--
-- Name: sf_cost_snapshots_provider_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_cost_snapshots_provider_idx ON public.sf_cost_snapshots USING btree (provider, period_end DESC);


--
-- Name: sf_cost_snapshots_user_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_cost_snapshots_user_scope_idx ON public.sf_cost_snapshots USING btree (user_id, period_end DESC);


--
-- Name: sf_deployment_ui_events_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_deployment_ui_events_lookup ON public.sf_deployment_ui_events USING btree (user_id, deployment_id, id DESC);


--
-- Name: sf_deployments_user_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_deployments_user_scope_idx ON public.sf_deployments USING btree (user_id, updated_at DESC);


--
-- Name: sf_deployments_user_scope_name_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_deployments_user_scope_name_uq ON public.sf_deployments USING btree (user_id, name);


--
-- Name: sf_notifications_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_notifications_user_idx ON public.sf_notifications USING btree (username, created_at DESC);


--
-- Name: sf_pr_audit_ws_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_audit_ws_created_idx ON public.sf_policy_report_audit_log USING btree (user_id, created_at DESC);


--
-- Name: sf_pr_exceptions_ws_finding_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_exceptions_ws_finding_idx ON public.sf_policy_report_exceptions USING btree (user_id, finding_id);


--
-- Name: sf_pr_exceptions_ws_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_exceptions_ws_idx ON public.sf_policy_report_exceptions USING btree (user_id, status, created_at DESC);


--
-- Name: sf_pr_exceptions_ws_network_finding_check_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_pr_exceptions_ws_network_finding_check_uniq ON public.sf_policy_report_exceptions USING btree (user_id, forward_network_id, finding_id, check_id);


--
-- Name: sf_pr_exceptions_ws_network_status_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_exceptions_ws_network_status_updated_idx ON public.sf_policy_report_exceptions USING btree (user_id, forward_network_id, status, updated_at DESC);


--
-- Name: sf_pr_forward_networks_ws_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_forward_networks_ws_created_idx ON public.sf_policy_report_forward_networks USING btree (user_id, created_at DESC);


--
-- Name: sf_pr_fwd_net_creds_ws_user_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_fwd_net_creds_ws_user_updated_idx ON public.sf_policy_report_forward_network_credentials USING btree (user_id, username, updated_at DESC);


--
-- Name: sf_pr_rc_assignments_campaign_finding_check_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_pr_rc_assignments_campaign_finding_check_uniq ON public.sf_policy_report_recert_assignments USING btree (campaign_id, finding_id, check_id);


--
-- Name: sf_pr_rc_assignments_campaign_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_rc_assignments_campaign_idx ON public.sf_policy_report_recert_assignments USING btree (campaign_id, status, created_at DESC);


--
-- Name: sf_pr_rc_assignments_ws_finding_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_rc_assignments_ws_finding_idx ON public.sf_policy_report_recert_assignments USING btree (user_id, finding_id);


--
-- Name: sf_pr_rc_campaigns_ws_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_pr_rc_campaigns_ws_idx ON public.sf_policy_report_recert_campaigns USING btree (user_id, created_at DESC);


--
-- Name: sf_user_scope_eve_servers_project_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_scope_eve_servers_project_idx ON public.sf_user_scope_eve_servers USING btree (user_scope_id);


--
-- Name: sf_user_scope_netlab_servers_project_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_scope_netlab_servers_project_idx ON public.sf_user_scope_netlab_servers USING btree (user_scope_id);


--
-- Name: sf_resource_events_resource_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_resource_events_resource_idx ON public.sf_resource_events USING btree (resource_id, created_at DESC);


--
-- Name: sf_resource_events_user_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_resource_events_user_scope_idx ON public.sf_resource_events USING btree (user_id, created_at DESC);


--
-- Name: sf_resources_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_resources_owner_idx ON public.sf_resources USING btree (owner_username);


--
-- Name: sf_resources_provider_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_resources_provider_uq ON public.sf_resources USING btree (provider, resource_id);


--
-- Name: sf_resources_user_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_resources_user_scope_idx ON public.sf_resources USING btree (user_id);


--
-- Name: sf_snmp_trap_events_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_snmp_trap_events_received_at_idx ON public.sf_snmp_trap_events USING btree (received_at DESC);


--
-- Name: sf_snmp_trap_events_username_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_snmp_trap_events_username_idx ON public.sf_snmp_trap_events USING btree (username, received_at DESC);


--
-- Name: sf_syslog_events_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_syslog_events_received_at_idx ON public.sf_syslog_events USING btree (received_at DESC);


--
-- Name: sf_syslog_events_source_ip_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_syslog_events_source_ip_idx ON public.sf_syslog_events USING btree (source_ip);


--
-- Name: sf_syslog_routes_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_syslog_routes_owner_idx ON public.sf_syslog_routes USING btree (owner_username);


--
-- Name: sf_task_events_task_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_task_events_task_idx ON public.sf_task_events USING btree (task_id, id);


--
-- Name: sf_task_logs_task_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_task_logs_task_idx ON public.sf_task_logs USING btree (task_id, created_at);


--
-- Name: sf_tasks_deployment_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_tasks_deployment_idx ON public.sf_tasks USING btree (deployment_id, created_at DESC);


--
-- Name: sf_tasks_queue_deployment_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_tasks_queue_deployment_idx ON public.sf_tasks USING btree (user_id, deployment_id, status, priority DESC, id);


--
-- Name: sf_tasks_queue_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_tasks_queue_idx ON public.sf_tasks USING btree (user_id, status, priority DESC, id);


--
-- Name: sf_tasks_user_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_tasks_user_scope_idx ON public.sf_tasks USING btree (user_id, created_at DESC);


--
-- Name: sf_usage_snapshots_provider_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_usage_snapshots_provider_idx ON public.sf_usage_snapshots USING btree (provider, collected_at DESC);


--
-- Name: sf_usage_snapshots_user_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_usage_snapshots_user_scope_idx ON public.sf_usage_snapshots USING btree (user_id, collected_at DESC);


--
-- Name: sf_user_containerlab_servers_username_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_containerlab_servers_username_idx ON public.sf_user_containerlab_servers USING btree (username);


--
-- Name: sf_user_eve_servers_username_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_eve_servers_username_idx ON public.sf_user_eve_servers USING btree (username);


--
-- Name: sf_user_forward_collectors_username_default; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_user_forward_collectors_username_default ON public.sf_user_forward_collectors USING btree (username) WHERE is_default;


--
-- Name: sf_user_forward_collectors_username_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_user_forward_collectors_username_name ON public.sf_user_forward_collectors USING btree (username, name);


--
-- Name: sf_user_netlab_servers_username_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_netlab_servers_username_idx ON public.sf_user_netlab_servers USING btree (username);


--
-- Name: sf_user_variable_groups_name_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_user_variable_groups_name_uq ON public.sf_user_variable_groups USING btree (username, name);


--
-- Name: sf_user_variable_groups_username_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_variable_groups_username_idx ON public.sf_user_variable_groups USING btree (username, updated_at DESC);


--
-- Name: sf_webhook_events_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_webhook_events_received_at_idx ON public.sf_webhook_events USING btree (received_at DESC);


--
-- Name: sf_webhook_events_username_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_webhook_events_username_idx ON public.sf_webhook_events USING btree (username, received_at DESC);


--
-- Name: sf_user_scope_groups_user_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_scope_groups_user_scope_idx ON public.sf_user_scope_groups USING btree (user_id);


--
-- Name: sf_user_scope_members_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_scope_members_user_idx ON public.sf_user_scope_members USING btree (username);


--
-- Name: sf_user_scope_variable_groups_name_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sf_user_scope_variable_groups_name_uq ON public.sf_user_scope_variable_groups USING btree (user_id, name);


--
-- Name: sf_user_scope_variable_groups_user_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_scope_variable_groups_user_scope_idx ON public.sf_user_scope_variable_groups USING btree (user_id, updated_at DESC);


--
-- Name: sf_user_scopes_created_by_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sf_user_scopes_created_by_idx ON public.sf_user_scopes USING btree (created_by);


--
-- Name: sf_audit_log sf_audit_log_actor_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_audit_log
    ADD CONSTRAINT sf_audit_log_actor_username_fkey FOREIGN KEY (actor_username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_audit_log sf_audit_log_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_audit_log
    ADD CONSTRAINT sf_audit_log_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE SET NULL;


--
-- Name: sf_aws_device_auth_requests sf_aws_device_auth_requests_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_aws_device_auth_requests
    ADD CONSTRAINT sf_aws_device_auth_requests_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_capacity_nqe_cache sf_capacity_nqe_cache_deployment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_capacity_nqe_cache
    ADD CONSTRAINT sf_capacity_nqe_cache_deployment_id_fkey FOREIGN KEY (deployment_id) REFERENCES public.sf_deployments(id) ON DELETE CASCADE;


--
-- Name: sf_capacity_nqe_cache sf_capacity_nqe_cache_user_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_capacity_nqe_cache
    ADD CONSTRAINT sf_capacity_nqe_cache_user_scope_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_capacity_rollups sf_capacity_rollups_deployment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_capacity_rollups
    ADD CONSTRAINT sf_capacity_rollups_deployment_id_fkey FOREIGN KEY (deployment_id) REFERENCES public.sf_deployments(id) ON DELETE CASCADE;


--
-- Name: sf_capacity_rollups sf_capacity_rollups_user_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_capacity_rollups
    ADD CONSTRAINT sf_capacity_rollups_user_scope_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_cost_snapshots sf_cost_snapshots_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_cost_snapshots
    ADD CONSTRAINT sf_cost_snapshots_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE SET NULL;


--
-- Name: sf_cost_snapshots sf_cost_snapshots_resource_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_cost_snapshots
    ADD CONSTRAINT sf_cost_snapshots_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES public.sf_resources(id) ON DELETE SET NULL;


--
-- Name: sf_deployments sf_deployments_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_deployments
    ADD CONSTRAINT sf_deployments_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_deployments sf_deployments_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_deployments
    ADD CONSTRAINT sf_deployments_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_dns_tokens sf_dns_tokens_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_dns_tokens
    ADD CONSTRAINT sf_dns_tokens_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_notifications sf_notifications_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_notifications
    ADD CONSTRAINT sf_notifications_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_policy_report_audit_log sf_policy_report_audit_log_actor_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_audit_log
    ADD CONSTRAINT sf_policy_report_audit_log_actor_username_fkey FOREIGN KEY (actor_username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_policy_report_audit_log sf_policy_report_audit_log_user_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_audit_log
    ADD CONSTRAINT sf_policy_report_audit_log_user_scope_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_policy_report_exceptions sf_policy_report_exceptions_approved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_exceptions
    ADD CONSTRAINT sf_policy_report_exceptions_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_policy_report_exceptions sf_policy_report_exceptions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_exceptions
    ADD CONSTRAINT sf_policy_report_exceptions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_policy_report_exceptions sf_policy_report_exceptions_user_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_exceptions
    ADD CONSTRAINT sf_policy_report_exceptions_user_scope_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_policy_report_forward_network_credentials sf_policy_report_forward_network_credentials_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_forward_network_credentials
    ADD CONSTRAINT sf_policy_report_forward_network_credentials_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_policy_report_forward_network_credentials sf_policy_report_forward_network_credentials_user_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_forward_network_credentials
    ADD CONSTRAINT sf_policy_report_forward_network_credentials_user_scope_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_policy_report_forward_networks sf_policy_report_forward_networks_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_forward_networks
    ADD CONSTRAINT sf_policy_report_forward_networks_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_policy_report_forward_networks sf_policy_report_forward_networks_user_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_forward_networks
    ADD CONSTRAINT sf_policy_report_forward_networks_user_scope_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_policy_report_recert_assignments sf_policy_report_recert_assignments_assignee_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_recert_assignments
    ADD CONSTRAINT sf_policy_report_recert_assignments_assignee_username_fkey FOREIGN KEY (assignee_username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_policy_report_recert_assignments sf_policy_report_recert_assignments_campaign_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_recert_assignments
    ADD CONSTRAINT sf_policy_report_recert_assignments_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.sf_policy_report_recert_campaigns(id) ON DELETE CASCADE;


--
-- Name: sf_policy_report_recert_assignments sf_policy_report_recert_assignments_user_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_recert_assignments
    ADD CONSTRAINT sf_policy_report_recert_assignments_user_scope_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_policy_report_recert_campaigns sf_policy_report_recert_campaigns_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_recert_campaigns
    ADD CONSTRAINT sf_policy_report_recert_campaigns_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_policy_report_recert_campaigns sf_policy_report_recert_campaigns_user_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_policy_report_recert_campaigns
    ADD CONSTRAINT sf_policy_report_recert_campaigns_user_scope_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_aws_static_credentials sf_project_aws_static_credentials_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_aws_static_credentials
    ADD CONSTRAINT sf_project_aws_static_credentials_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_azure_credentials sf_project_azure_credentials_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_azure_credentials
    ADD CONSTRAINT sf_project_azure_credentials_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_eve_servers sf_user_scope_eve_servers_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_eve_servers
    ADD CONSTRAINT sf_user_scope_eve_servers_project_id_fkey FOREIGN KEY (user_scope_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_forward_credentials sf_project_forward_credentials_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_forward_credentials
    ADD CONSTRAINT sf_project_forward_credentials_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_gcp_credentials sf_project_gcp_credentials_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_gcp_credentials
    ADD CONSTRAINT sf_project_gcp_credentials_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_groups sf_project_groups_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_groups
    ADD CONSTRAINT sf_project_groups_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_members sf_project_members_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_members
    ADD CONSTRAINT sf_project_members_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_members sf_project_members_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_members
    ADD CONSTRAINT sf_project_members_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_user_scope_netlab_servers sf_user_scope_netlab_servers_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_netlab_servers
    ADD CONSTRAINT sf_user_scope_netlab_servers_project_id_fkey FOREIGN KEY (user_scope_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scope_variable_groups sf_project_variable_groups_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scope_variable_groups
    ADD CONSTRAINT sf_project_variable_groups_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_user_scopes sf_projects_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_scopes
    ADD CONSTRAINT sf_projects_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_resource_events sf_resource_events_actor_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_resource_events
    ADD CONSTRAINT sf_resource_events_actor_username_fkey FOREIGN KEY (actor_username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_resource_events sf_resource_events_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_resource_events
    ADD CONSTRAINT sf_resource_events_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE SET NULL;


--
-- Name: sf_resource_events sf_resource_events_resource_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_resource_events
    ADD CONSTRAINT sf_resource_events_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES public.sf_resources(id) ON DELETE CASCADE;


--
-- Name: sf_resources sf_resources_owner_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_resources
    ADD CONSTRAINT sf_resources_owner_username_fkey FOREIGN KEY (owner_username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_resources sf_resources_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_resources
    ADD CONSTRAINT sf_resources_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE SET NULL;


--
-- Name: sf_snmp_trap_events sf_snmp_trap_events_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_snmp_trap_events
    ADD CONSTRAINT sf_snmp_trap_events_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_snmp_trap_tokens sf_snmp_trap_tokens_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_snmp_trap_tokens
    ADD CONSTRAINT sf_snmp_trap_tokens_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_syslog_routes sf_syslog_routes_owner_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_syslog_routes
    ADD CONSTRAINT sf_syslog_routes_owner_username_fkey FOREIGN KEY (owner_username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_task_events sf_task_events_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_task_events
    ADD CONSTRAINT sf_task_events_task_id_fkey FOREIGN KEY (task_id) REFERENCES public.sf_tasks(id) ON DELETE CASCADE;


--
-- Name: sf_task_logs sf_task_logs_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_task_logs
    ADD CONSTRAINT sf_task_logs_task_id_fkey FOREIGN KEY (task_id) REFERENCES public.sf_tasks(id) ON DELETE CASCADE;


--
-- Name: sf_tasks sf_tasks_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_tasks
    ADD CONSTRAINT sf_tasks_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_tasks sf_tasks_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_tasks
    ADD CONSTRAINT sf_tasks_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE CASCADE;


--
-- Name: sf_usage_snapshots sf_usage_snapshots_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_usage_snapshots
    ADD CONSTRAINT sf_usage_snapshots_project_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_user_scopes(id) ON DELETE SET NULL;


--
-- Name: sf_user_aws_sso_credentials sf_user_aws_sso_credentials_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_aws_sso_credentials
    ADD CONSTRAINT sf_user_aws_sso_credentials_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_aws_static_credentials sf_user_aws_static_credentials_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_aws_static_credentials
    ADD CONSTRAINT sf_user_aws_static_credentials_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_azure_credentials sf_user_azure_credentials_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_azure_credentials
    ADD CONSTRAINT sf_user_azure_credentials_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_containerlab_servers sf_user_containerlab_servers_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_containerlab_servers
    ADD CONSTRAINT sf_user_containerlab_servers_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_eve_servers sf_user_eve_servers_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_eve_servers
    ADD CONSTRAINT sf_user_eve_servers_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_forward_collectors sf_user_forward_collectors_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_forward_collectors
    ADD CONSTRAINT sf_user_forward_collectors_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_gcp_credentials sf_user_gcp_credentials_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_gcp_credentials
    ADD CONSTRAINT sf_user_gcp_credentials_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_netlab_servers sf_user_netlab_servers_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_netlab_servers
    ADD CONSTRAINT sf_user_netlab_servers_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_servicenow_configs sf_user_servicenow_configs_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_servicenow_configs
    ADD CONSTRAINT sf_user_servicenow_configs_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_settings sf_user_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_settings
    ADD CONSTRAINT sf_user_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.sf_users(username) ON DELETE CASCADE;


--
-- Name: sf_user_variable_groups sf_user_variable_groups_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_user_variable_groups
    ADD CONSTRAINT sf_user_variable_groups_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_webhook_events sf_webhook_events_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_webhook_events
    ADD CONSTRAINT sf_webhook_events_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- Name: sf_webhook_tokens sf_webhook_tokens_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sf_webhook_tokens
    ADD CONSTRAINT sf_webhook_tokens_username_fkey FOREIGN KEY (username) REFERENCES public.sf_users(username) ON UPDATE CASCADE;


--
-- PostgreSQL database dump complete
--
