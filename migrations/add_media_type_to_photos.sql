-- Migration : ajout du support vidéo dans la table photos
-- À exécuter une seule fois dans Neon PostgreSQL

ALTER TABLE photos
  ADD COLUMN IF NOT EXISTS media_type VARCHAR(10) NOT NULL DEFAULT 'image';

-- Contrainte optionnelle pour garantir l'intégrité
ALTER TABLE photos
  ADD CONSTRAINT IF NOT EXISTS photos_media_type_check
  CHECK (media_type IN ('image', 'video'));

-- Pour les vidéos, l'URL peut dépasser 500 caractères (YouTube, Vimeo…)
ALTER TABLE photos
  ALTER COLUMN url TYPE VARCHAR(1000);
