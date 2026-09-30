-- v16: Primary device metadata and resumable registration attempts.
ALTER TABLE whatsmeow_device ADD COLUMN mobile BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE whatsmeow_device ADD COLUMN mobile_version TEXT NOT NULL DEFAULT '';
ALTER TABLE whatsmeow_device ADD COLUMN mobile_phone_id TEXT NOT NULL DEFAULT '';
ALTER TABLE whatsmeow_device ADD COLUMN mobile_os_version TEXT NOT NULL DEFAULT '';
ALTER TABLE whatsmeow_device ADD COLUMN mobile_model TEXT NOT NULL DEFAULT '';

CREATE TABLE whatsmeow_mobile_pending (
    phone TEXT PRIMARY KEY,
    snapshot bytea NOT NULL
);
