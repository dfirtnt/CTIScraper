-- Migration: Remove summary column from articles table
-- Date: 2025-01-27
-- Description: Remove the summary column as it's redundant with content

-- Drop the summary column
ALTER TABLE articles DROP COLUMN IF EXISTS summary;

-- Add a comment to document the change
COMMENT ON TABLE articles IS 'Articles table - summary column removed as it was redundant with content';
