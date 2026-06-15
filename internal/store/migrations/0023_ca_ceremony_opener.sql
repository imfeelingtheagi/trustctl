-- Separation of duties for CA key ceremonies (PKIGOV-006): record the ceremony
-- opener (the authenticated principal who started it) so an approval can enforce
-- opener != approver. The opener column is nullable for ceremonies created before
-- this migration (and for system/background openers, honestly unattributed). New
-- ceremonies started through the hierarchy Manager record the opener.
--
-- This is an additive, idempotent forward migration: it does not change existing
-- rows' behavior, and a ceremony with a NULL opener simply imposes no opener!=
-- approver constraint (the prior behavior), while a recorded opener enforces SoD.

ALTER TABLE ca_key_ceremonies
    ADD COLUMN IF NOT EXISTS opener text NOT NULL DEFAULT '';
