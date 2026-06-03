-- Table déjà créée dans Neon — migration de référence uniquement
CREATE TABLE IF NOT EXISTS temoignages (
  id         SERIAL PRIMARY KEY,
  nom        VARCHAR(100) NOT NULL,
  prenom     VARCHAR(100) NOT NULL,
  message    TEXT NOT NULL,
  photo_data TEXT,
  photo_name VARCHAR(255),
  photo_mime VARCHAR(50),
  visible    BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_temoignages_visible    ON temoignages(visible);
CREATE INDEX IF NOT EXISTS idx_temoignages_created_at ON temoignages(created_at DESC);
