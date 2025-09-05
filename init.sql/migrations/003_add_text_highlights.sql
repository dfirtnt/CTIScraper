-- Migration: Add text highlights table for user-selected text categorization
-- This table stores user-selected text snippets from articles and their categorization

-- Create text_highlights table
CREATE TABLE IF NOT EXISTS text_highlights (
    id SERIAL PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    selected_text TEXT NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    is_huntable BOOLEAN NOT NULL DEFAULT FALSE,
    categorized_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes for performance
    INDEX idx_text_highlights_article_id (article_id),
    INDEX idx_text_highlights_huntable (is_huntable),
    INDEX idx_text_highlights_categorized_at (categorized_at),
    INDEX idx_text_highlights_created_at (created_at)
);

-- Add comments for documentation
COMMENT ON TABLE text_highlights IS 'Stores user-selected text snippets from articles and their huntable categorization';
COMMENT ON COLUMN text_highlights.selected_text IS 'The actual text that was highlighted/selected by the user';
COMMENT ON COLUMN text_highlights.start_offset IS 'Starting character position in the article content';
COMMENT ON COLUMN text_highlights.end_offset IS 'Ending character position in the article content';
COMMENT ON COLUMN text_highlights.is_huntable IS 'Whether the user categorized this text as huntable (yes/no)';
COMMENT ON COLUMN text_highlights.categorized_at IS 'When the user made the categorization decision';

-- Create trigger to update updated_at timestamp
CREATE TRIGGER update_text_highlights_updated_at 
    BEFORE UPDATE ON text_highlights 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
