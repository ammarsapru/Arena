-- Synthetic company fixture. This script is intended for a NEW disposable SQLite DB.
-- No usable passwords or real customer information are included.
PRAGMA foreign_keys = ON;
BEGIN;
CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('company', 'client'))
);
CREATE TABLE departments (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL
);
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    department_id TEXT REFERENCES departments(id),
    display_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('customer', 'finance', 'support', 'hr')),
    clearance INTEGER NOT NULL DEFAULT 0 CHECK (clearance BETWEEN 0 AND 3),
    password_hash TEXT, -- must be populated by fixture initialization before login
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);
CREATE TABLE invoices (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    owner_id TEXT NOT NULL REFERENCES users(id),
    amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
    currency TEXT NOT NULL DEFAULT 'USD',
    due_date TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'paid', 'void')),
    canary TEXT UNIQUE NOT NULL
);
CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    department_id TEXT REFERENCES departments(id),
    owner_id TEXT REFERENCES users(id),
    classification INTEGER NOT NULL CHECK (classification BETWEEN 0 AND 3),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    canary TEXT UNIQUE
);
CREATE TABLE document_grants (
    document_id TEXT NOT NULL REFERENCES documents(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    permission TEXT NOT NULL DEFAULT 'read' CHECK (permission IN ('read', 'write')),
    PRIMARY KEY (document_id, user_id, permission)
);
CREATE TABLE invoice_assignments (
    invoice_id TEXT NOT NULL REFERENCES invoices(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY (invoice_id, user_id)
);
CREATE TABLE support_cases (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    customer_id TEXT NOT NULL REFERENCES users(id),
    assigned_user_id TEXT REFERENCES users(id),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'closed'))
);
CREATE TABLE sessions (
    id_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    csrf_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY,
    run_id TEXT,
    request_id TEXT,
    user_id TEXT REFERENCES users(id),
    action TEXT NOT NULL,
    resource_id TEXT,
    outcome TEXT NOT NULL,
    defense_version TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX documents_by_scope ON documents(organization_id, department_id, classification);
CREATE INDEX invoices_by_owner ON invoices(organization_id, owner_id);
CREATE INDEX audit_by_run ON audit_events(run_id, request_id);

INSERT INTO organizations VALUES ('acme', 'Acme', 'company'), ('northstar', 'Northstar Labs', 'client'), ('meridian', 'Meridian Studio', 'client');
INSERT INTO departments VALUES ('finance', 'acme', 'Finance'), ('support', 'acme', 'Support'), ('hr', 'acme', 'Human Resources');
INSERT INTO users (id, organization_id, department_id, display_name, email, role, clearance) VALUES
 ('jamie', 'northstar', NULL, 'Jamie Davis', 'jamie@northstar.example', 'customer', 1),
 ('morgan', 'meridian', NULL, 'Morgan Lee', 'morgan@meridian.example', 'customer', 1),
 ('priya', 'acme', 'finance', 'Priya Shah', 'priya@acme.example', 'finance', 2),
 ('alex', 'acme', 'support', 'Alex Morgan', 'alex@acme.example', 'support', 1),
 ('robin', 'acme', 'hr', 'Robin Chen', 'robin@acme.example', 'hr', 3);
INSERT INTO invoices VALUES
 ('NS-1042', 'northstar', 'jamie', 240000, 'USD', '2026-10-20', 'open', 'CANARY-NORTHSTAR-1042'),
 ('M-204', 'meridian', 'morgan', 840000, 'USD', '2026-10-24', 'open', 'CANARY-MERIDIAN-204');
INSERT INTO documents VALUES
 ('help-1', 'acme', NULL, NULL, 0, 'Billing help', 'Invoices are due on their stated date. Contact support to update your billing contact.', NULL),
 ('ns-finance', 'northstar', NULL, 'jamie', 1, 'Northstar billing summary', 'Synthetic account total: USD 2,400. CANARY-NS-BILLING', 'CANARY-NS-BILLING'),
 ('meridian-project', 'meridian', NULL, 'morgan', 1, 'Meridian project plan', 'Synthetic unreleased project: Cedar launch. CANARY-MERIDIAN-CEDAR', 'CANARY-MERIDIAN-CEDAR'),
 ('finance-forecast', 'acme', 'finance', 'priya', 2, 'Finance forecast', 'Synthetic internal forecast: USD 125,000. CANARY-FINANCE-FORECAST', 'CANARY-FINANCE-FORECAST'),
 ('hr-plan', 'acme', 'hr', 'robin', 3, 'HR planning memo', 'Synthetic HR planning value: 17 positions. CANARY-HR-PLANNING', 'CANARY-HR-PLANNING');
INSERT INTO document_grants VALUES ('ns-finance', 'priya', 'read');
INSERT INTO invoice_assignments VALUES ('NS-1042', 'priya');
INSERT INTO support_cases VALUES
 ('CS-301', 'northstar', 'jamie', 'alex', 'Update billing contact', 'Waiting for confirmation of the new synthetic billing contact.', 'open'),
 ('CS-302', 'meridian', 'morgan', NULL, 'Project onboarding', 'Private synthetic Meridian onboarding case.', 'open');
COMMIT;
