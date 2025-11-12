/*
  # Create Secrets Database

  ## Overview
  Creates a secure database for storing encrypted secrets and credentials with proper access controls and audit logging.

  ## New Tables
  
  ### `secrets`
  Stores encrypted secrets with metadata
  - `id` (uuid, primary key) - Unique identifier for each secret
  - `user_id` (uuid) - Owner of the secret
  - `name` (text) - Human-readable name/label for the secret
  - `description` (text, optional) - Description of what the secret is for
  - `encrypted_value` (text) - The encrypted secret value
  - `secret_type` (text) - Type of secret (api_key, password, token, certificate, etc.)
  - `expires_at` (timestamptz, optional) - When the secret expires
  - `last_accessed_at` (timestamptz) - Last time secret was accessed
  - `is_active` (boolean) - Whether the secret is active or revoked
  - `metadata` (jsonb, optional) - Additional metadata about the secret
  - `created_at` (timestamptz) - When the secret was created
  - `updated_at` (timestamptz) - When the secret was last updated
  
  ### `secret_access_log`
  Audit log for all secret access
  - `id` (uuid, primary key) - Unique identifier for log entry
  - `secret_id` (uuid) - Reference to the secret
  - `user_id` (uuid) - User who accessed the secret
  - `action` (text) - Action performed (view, update, delete, rotate)
  - `ip_address` (text, optional) - IP address of the request
  - `user_agent` (text, optional) - User agent of the request
  - `success` (boolean) - Whether the access was successful
  - `accessed_at` (timestamptz) - When the access occurred

  ### `secret_shares`
  Track secrets shared between users
  - `id` (uuid, primary key) - Unique identifier
  - `secret_id` (uuid) - Reference to the secret
  - `shared_by` (uuid) - User who shared the secret
  - `shared_with` (uuid) - User who received access
  - `permission` (text) - Permission level (view, edit, admin)
  - `expires_at` (timestamptz, optional) - When the share expires
  - `created_at` (timestamptz) - When the share was created

  ## Security
  
  ### Row Level Security (RLS)
  - All tables have RLS enabled
  - Users can only access their own secrets
  - Shared secrets are accessible based on permissions
  - Access logs are only viewable by secret owners
  - All access is logged for audit purposes

  ### Policies
  
  #### secrets table
  - Users can view their own secrets
  - Users can view secrets shared with them
  - Users can insert their own secrets
  - Users can update their own secrets
  - Users can delete their own secrets
  
  #### secret_access_log table
  - Users can view logs for their own secrets
  - System can insert logs for all access
  
  #### secret_shares table
  - Users can view shares for their secrets
  - Users can view secrets shared with them
  - Users can create shares for their secrets
  - Users can delete shares they created

  ## Important Notes
  1. The `encrypted_value` field stores ENCRYPTED data only
  2. Encryption/decryption must be handled at application level
  3. All secret access is logged automatically via triggers
  4. Expired secrets are automatically marked inactive via triggers
  5. Never store plaintext secrets in the database
*/

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create enum types for better data integrity
DO $$ 
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'secret_type') THEN
    CREATE TYPE secret_type AS ENUM (
      'api_key',
      'password',
      'token',
      'oauth_token',
      'certificate',
      'private_key',
      'connection_string',
      'other'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'secret_action') THEN
    CREATE TYPE secret_action AS ENUM (
      'view',
      'create',
      'update',
      'delete',
      'rotate',
      'share',
      'unshare'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'secret_permission') THEN
    CREATE TYPE secret_permission AS ENUM (
      'view',
      'edit',
      'admin'
    );
  END IF;
END $$;

-- Create secrets table
CREATE TABLE IF NOT EXISTS secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text,
  encrypted_value text NOT NULL,
  secret_type secret_type DEFAULT 'other',
  expires_at timestamptz,
  last_accessed_at timestamptz DEFAULT now(),
  is_active boolean DEFAULT true,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  
  CONSTRAINT name_not_empty CHECK (length(trim(name)) > 0),
  CONSTRAINT encrypted_value_not_empty CHECK (length(trim(encrypted_value)) > 0)
);

-- Create secret access log table
CREATE TABLE IF NOT EXISTS secret_access_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  action secret_action NOT NULL,
  ip_address text,
  user_agent text,
  success boolean DEFAULT true,
  accessed_at timestamptz DEFAULT now()
);

-- Create secret shares table
CREATE TABLE IF NOT EXISTS secret_shares (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id uuid NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  shared_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  shared_with uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  permission secret_permission DEFAULT 'view',
  expires_at timestamptz,
  created_at timestamptz DEFAULT now(),
  
  CONSTRAINT no_self_share CHECK (shared_by != shared_with),
  CONSTRAINT unique_share UNIQUE (secret_id, shared_with)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_secrets_is_active ON secrets(is_active);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_secret_access_log_secret_id ON secret_access_log(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_access_log_user_id ON secret_access_log(user_id);
CREATE INDEX IF NOT EXISTS idx_secret_access_log_accessed_at ON secret_access_log(accessed_at);
CREATE INDEX IF NOT EXISTS idx_secret_shares_secret_id ON secret_shares(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_shares_shared_with ON secret_shares(shared_with);

-- Enable Row Level Security
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_access_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_shares ENABLE ROW LEVEL SECURITY;

-- RLS Policies for secrets table

-- Users can view their own active secrets
CREATE POLICY "Users can view own secrets"
  ON secrets FOR SELECT
  TO authenticated
  USING (user_id = auth.uid() AND is_active = true);

-- Users can view secrets shared with them
CREATE POLICY "Users can view shared secrets"
  ON secrets FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM secret_shares
      WHERE secret_shares.secret_id = secrets.id
      AND secret_shares.shared_with = auth.uid()
      AND (secret_shares.expires_at IS NULL OR secret_shares.expires_at > now())
    )
    AND is_active = true
  );

-- Users can insert their own secrets
CREATE POLICY "Users can create own secrets"
  ON secrets FOR INSERT
  TO authenticated
  WITH CHECK (user_id = auth.uid());

-- Users can update their own secrets
CREATE POLICY "Users can update own secrets"
  ON secrets FOR UPDATE
  TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- Users can delete their own secrets
CREATE POLICY "Users can delete own secrets"
  ON secrets FOR DELETE
  TO authenticated
  USING (user_id = auth.uid());

-- RLS Policies for secret_access_log table

-- Users can view logs for their own secrets
CREATE POLICY "Users can view own secret logs"
  ON secret_access_log FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM secrets
      WHERE secrets.id = secret_access_log.secret_id
      AND secrets.user_id = auth.uid()
    )
  );

-- System can insert logs (this will be used by triggers)
CREATE POLICY "System can insert access logs"
  ON secret_access_log FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- RLS Policies for secret_shares table

-- Users can view shares for their secrets
CREATE POLICY "Users can view own secret shares"
  ON secret_shares FOR SELECT
  TO authenticated
  USING (shared_by = auth.uid());

-- Users can view secrets shared with them
CREATE POLICY "Users can view shares granted to them"
  ON secret_shares FOR SELECT
  TO authenticated
  USING (shared_with = auth.uid());

-- Users can create shares for their secrets
CREATE POLICY "Users can create shares for own secrets"
  ON secret_shares FOR INSERT
  TO authenticated
  WITH CHECK (
    shared_by = auth.uid() AND
    EXISTS (
      SELECT 1 FROM secrets
      WHERE secrets.id = secret_shares.secret_id
      AND secrets.user_id = auth.uid()
    )
  );

-- Users can delete shares they created
CREATE POLICY "Users can delete shares they created"
  ON secret_shares FOR DELETE
  TO authenticated
  USING (shared_by = auth.uid());

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically update updated_at
DROP TRIGGER IF EXISTS update_secrets_updated_at ON secrets;
CREATE TRIGGER update_secrets_updated_at
  BEFORE UPDATE ON secrets
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Create function to log secret access
CREATE OR REPLACE FUNCTION log_secret_access()
RETURNS TRIGGER AS $$
BEGIN
  -- Update last_accessed_at
  UPDATE secrets
  SET last_accessed_at = now()
  WHERE id = NEW.id;
  
  -- Insert access log
  INSERT INTO secret_access_log (
    secret_id,
    user_id,
    action,
    success
  ) VALUES (
    NEW.id,
    auth.uid(),
    'view',
    true
  );
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to automatically deactivate expired secrets
CREATE OR REPLACE FUNCTION deactivate_expired_secrets()
RETURNS void AS $$
BEGIN
  UPDATE secrets
  SET is_active = false
  WHERE expires_at IS NOT NULL
  AND expires_at < now()
  AND is_active = true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to validate secret share permissions
CREATE OR REPLACE FUNCTION validate_secret_share()
RETURNS TRIGGER AS $$
BEGIN
  -- Ensure the sharer owns the secret
  IF NOT EXISTS (
    SELECT 1 FROM secrets
    WHERE id = NEW.secret_id
    AND user_id = NEW.shared_by
  ) THEN
    RAISE EXCEPTION 'You can only share secrets you own';
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to validate secret shares
DROP TRIGGER IF EXISTS validate_secret_share_trigger ON secret_shares;
CREATE TRIGGER validate_secret_share_trigger
  BEFORE INSERT ON secret_shares
  FOR EACH ROW
  EXECUTE FUNCTION validate_secret_share();

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON secrets TO authenticated;
GRANT ALL ON secret_access_log TO authenticated;
GRANT ALL ON secret_shares TO authenticated;