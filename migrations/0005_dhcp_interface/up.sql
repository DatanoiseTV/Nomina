-- Bind a scope to a specific network interface for directly-connected
-- (non-relayed) clients, e.g. VLAN sub-interfaces. NULL = any interface
-- (relay/giaddr selection or single-LAN fallback).
ALTER TABLE dhcp_scopes ADD COLUMN interface TEXT;
