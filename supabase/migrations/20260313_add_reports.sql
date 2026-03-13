-- Migration: Add report exports tracking
-- Run in Supabase SQL Editor

-- Create table to track report exports
CREATE TABLE IF NOT EXISTS report_exports (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  format text NOT NULL CHECK (format IN ('pdf', 'html', 'email')), -- Export format
  subscription_tier text NOT NULL CHECK (subscription_tier IN ('free', 'pro', 'team', 'enterprise')),
  generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  file_size_bytes INTEGER, -- Track PDF size for optimization
  generation_time_ms INTEGER, -- Track generation performance
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for analytics
CREATE INDEX idx_report_exports_user ON report_exports(user_id);
CREATE INDEX idx_report_exports_scan ON report_exports(scan_id);
CREATE INDEX idx_report_exports_date ON report_exports(generated_at DESC);
CREATE INDEX idx_report_exports_tier ON report_exports(subscription_tier);

-- Optional: Add column to scans table to track if report has been generated
ALTER TABLE scans ADD COLUMN IF NOT EXISTS last_report_generated TIMESTAMP WITH TIME ZONE;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS report_exports_count INTEGER DEFAULT 0;

-- Create view for analytics
CREATE OR REPLACE VIEW report_export_analytics AS
SELECT 
  DATE(generated_at) as export_date,
  format,
  subscription_tier,
  COUNT(*) as export_count,
  AVG(file_size_bytes)::INTEGER as avg_file_size,
  AVG(generation_time_ms)::INTEGER as avg_generation_time
FROM report_exports
GROUP BY DATE(generated_at), format, subscription_tier
ORDER BY export_date DESC;

-- Grant appropriate permissions
GRANT SELECT ON report_exports TO authenticated;
GRANT INSERT ON report_exports TO authenticated;
GRANT SELECT ON report_export_analytics TO authenticated;

-- Add row-level security
ALTER TABLE report_exports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own report exports"
  ON report_exports FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own report exports"
  ON report_exports FOR INSERT
  WITH CHECK (auth.uid() = user_id);
