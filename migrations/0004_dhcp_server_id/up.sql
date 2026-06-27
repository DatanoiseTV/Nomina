-- DHCPv4 server identifier (option 54): the server's own IPv4 on the served
-- subnet. Used in OFFER/ACK so clients know which server to direct REQUESTs to.
ALTER TABLE dhcp_scopes ADD COLUMN server_id TEXT;
