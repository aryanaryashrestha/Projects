-- sql/create_tables.sql
-- This script creates the main alerts table for our NIDS.

-- Connect to your database first using: psql -h localhost -d nids_db -U nids_user -W
-- Then run: \i sql/create_tables.sql

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,                  -- Auto-incrementing primary key
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Time of the alert
    src_ip VARCHAR(45) NOT NULL,            -- Source IP address (long enough for IPv6)
    dst_ip VARCHAR(45) NOT NULL,            -- Destination IP address
    protocol VARCHAR(10),                   -- TCP, UDP, ICMP, etc.
    alert_type VARCHAR(100) NOT NULL,       -- e.g., 'Port Scan', 'SYN Flood'
    severity VARCHAR(20) DEFAULT 'MEDIUM',  -- LOW, MEDIUM, HIGH, CRITICAL
    details TEXT                            -- Detailed description of the alert
);

-- Create indexes to speed up common queries (e.g., finding alerts by IP or time)
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);

-- Print a success message (only visible in psql)
SELECT 'Table alerts created successfully.' AS status;
