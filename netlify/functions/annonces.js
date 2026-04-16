/**
 * Netlify Function : annonces.js
 * Module "Petites Annonces" - Rucher-École du VAR
 *
 * SQL à exécuter UNE SEULE FOIS dans Neon pour créer les tables :
 *
 * CREATE TABLE IF NOT EXISTS annonces (
 *   id              SERIAL PRIMARY KEY,
 *   titre           VARCHAR(200) NOT NULL,
 *   description     TEXT NOT NULL,
 *   ville           VARCHAR(100) NOT NULL,
 *   email_contact   VARCHAR(254),
 *   telephone_contact VARCHAR(20),
 *   statut          VARCHAR(20) NOT NULL DEFAULT 'publiee'
 *                     CHECK (statut IN ('brouillon', 'publiee', 'supprimee')),
 *   user_email      VARCHAR(254) NOT NULL,
 *   photos          JSONB NOT NULL DEFAULT '[]',
 *   created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 *   updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
 * );
 *
 * CREATE INDEX IF NOT EXISTS idx_annonces_statut     ON annonces(statut);
 * CREATE INDEX IF NOT EXISTS idx_annonces_ville      ON annonces(LOWER(ville));
 * CREATE INDEX IF NOT EXISTS idx_annonces_user_email ON annonces(user_email);
 * CREATE INDEX IF NOT EXISTS idx_annonces_created_at ON annonces(created_at DESC);
 */

const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ─── Constantes ────────────────────────────────────────────────────────────────

const MAX_BODY_SIZE    = 20 * 1024 * 1024; // 20 MB (photos base64)
const MAX_PHOTOS       = 10;
const VALID_STATUTS    = ['brouillon', 'publiee'];
const ALLOWED_MIMETYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
const PAGE_SIZE        = 12;

// ─── Helpers ───────────────────────────────────────────────────────────────────

const verifyAuth = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
};

const validateId = (id) => Number.isInteger(Number(id)) && Number(id) > 0;

const sanitize = (str, maxLen) => {
  if (typeof str !== 'string') return null;
  return str.trim().slice(0, maxLen);
};

const isValidEmail = (email) => {
  if (!email) return true;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
};

const isValidPhone = (phone) => {
  if (!phone) return true;
  return /^[\d\s+\-.()/]{6,20}$/.test(phone.trim());
};

const validateAnnonce = (data) => {
  const { titre, description, ville, emailContact, telephoneContact, photos } = data;

  if (!titre || typeof titre !== 'string' || titre.trim().length < 3 || titre.trim().length > 200)
    return { valid: false, error: 'Titre invalide (3 à 200 caractères requis)' };

  if (!description || typeof description !== 'string' || description.trim().length < 10 || description.trim().length > 5000)
    return { valid: false, error: 'Description invalide (10 à 5000 caractères requis)' };

  if (!ville || typeof ville !== 'string' || ville.trim().length < 2 || ville.trim().length > 100)
    return { valid: false, error: 'Ville invalide (2 à 100 caractères requis)' };

  if (emailContact && !isValidEmail(emailContact))
    return { valid: false, error: 'Email de contact invalide' };

  if (telephoneContact && !isValidPhone(telephoneContact))
    return { valid: false, error: 'Numéro de téléphone invalide' };

  if (photos !== undefined) {
    if (!Array.isArray(photos))
      return { valid: false, error: 'Format des photos invalide' };
    if (photos.length > MAX_PHOTOS)
      return { valid: false, error: `Maximum ${MAX_PHOTOS} photos autorisées` };
    for (const photo of photos) {
      if (!photo.data || typeof photo.data !== 'string')
        return { valid: false, error: 'Données de photo invalides' };
      if (!ALLOWED_MIMETYPES.includes(photo.mimeType))
        return { valid: false, error: 'Type de fichier non supporté (jpeg, png, webp uniquement)' };
    }
  }

  return { valid: true };
};

// ─── Handler principal ─────────────────────────────────────────────────────────

exports.handler = async (event) => {
  const clientIP = event.headers['client-ip'] || event.headers['x-forwarded-for'] || 'unknown';

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store, no-cache, must-revalidate'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Parse body
  let parsedBody = {};
  if (event.body) {
    if (event.body.length > MAX_BODY_SIZE) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Requête trop volumineuse' }) };
    }
    try {
      parsedBody = JSON.parse(event.body);
    } catch {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'JSON invalide' }) };
    }
  }

  // Auth (optionnel selon la route)
  const authHeader = event.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  const authUser = token ? verifyAuth(token) : null;

  const params = event.queryStringParameters || {};

  try {
    switch (event.httpMethod) {

      // ══════════════════════════════════════════════
      // GET  — Lecture publique + lecture privée (mine)
      // ══════════════════════════════════════════════
      case 'GET': {

        // ── Mes annonces (tableau de bord) ─────────
        if (params.action === 'mine') {
          if (!authUser) {
            return { statusCode: 401, headers, body: JSON.stringify({ error: 'Non autorisé' }) };
          }

          const result = await pool.query(
            `SELECT id, titre, ville, statut, created_at, updated_at,
                    jsonb_array_length(photos) AS photos_count
             FROM annonces
             WHERE user_email = $1 AND statut != 'supprimee'
             ORDER BY created_at DESC`,
            [authUser.email]
          );

          return { statusCode: 200, headers, body: JSON.stringify(result.rows) };
        }

        // ── Détail d'une annonce ───────────────────
        if (params.id) {
          if (!validateId(params.id)) {
            return { statusCode: 400, headers, body: JSON.stringify({ error: 'ID invalide' }) };
          }

          const result = await pool.query(
            `SELECT id, titre, description, ville, email_contact, telephone_contact,
                    statut, user_email, photos, created_at, updated_at
             FROM annonces
             WHERE id = $1 AND statut != 'supprimee'`,
            [Number(params.id)]
          );

          if (!result.rows.length) {
            return { statusCode: 404, headers, body: JSON.stringify({ error: 'Annonce introuvable' }) };
          }

          const annonce = result.rows[0];

          // Masquer les coordonnées si non connecté
          if (!authUser) {
            annonce.email_contact = null;
            annonce.telephone_contact = null;
            annonce._contact_hidden = true;
          }

          return { statusCode: 200, headers, body: JSON.stringify(annonce) };
        }

        // ── Liste publique avec filtres ────────────
        const q       = params.q    ? params.q.trim().slice(0, 200)    : '';
        const ville   = params.ville ? params.ville.trim().slice(0, 100) : '';
        const sort    = params.sort === 'old' ? 'ASC' : 'DESC';
        const page    = Math.max(1, parseInt(params.page) || 1);
        const offset  = (page - 1) * PAGE_SIZE;

        // Construction dynamique de la clause WHERE
        const conditions = [`a.statut = 'publiee'`];
        const qParams = [];

        if (q) {
          qParams.push(`%${q}%`);
          conditions.push(`(a.titre ILIKE $${qParams.length} OR a.description ILIKE $${qParams.length})`);
        }

        if (ville) {
          qParams.push(`%${ville}%`);
          conditions.push(`a.ville ILIKE $${qParams.length}`);
        }

        const whereSQL = conditions.join(' AND ');

        const countResult = await pool.query(
          `SELECT COUNT(*) FROM annonces a WHERE ${whereSQL}`,
          qParams
        );

        qParams.push(PAGE_SIZE, offset);

        const dataResult = await pool.query(
          `SELECT a.id,
                  a.titre,
                  a.ville,
                  a.created_at,
                  LEFT(a.description, 200) AS description_preview,
                  CASE WHEN jsonb_array_length(a.photos) > 0 THEN a.photos->0 ELSE NULL END AS first_photo,
                  jsonb_array_length(a.photos) AS photos_count
           FROM annonces a
           WHERE ${whereSQL}
           ORDER BY a.created_at ${sort}
           LIMIT $${qParams.length - 1} OFFSET $${qParams.length}`,
          qParams
        );

        // Lister les villes distinctes pour le filtre
        const villesResult = await pool.query(
          `SELECT DISTINCT ville FROM annonces WHERE statut = 'publiee' ORDER BY ville`
        );

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            annonces: dataResult.rows,
            total: Number(countResult.rows[0].count),
            page,
            totalPages: Math.ceil(Number(countResult.rows[0].count) / PAGE_SIZE),
            villes: villesResult.rows.map(r => r.ville)
          })
        };
      }

      // ══════════════════════════════════════════════
      // POST  — Créer une annonce
      // ══════════════════════════════════════════════
      case 'POST': {
        if (!authUser) {
          return { statusCode: 401, headers, body: JSON.stringify({ error: 'Non autorisé — connectez-vous pour publier une annonce' }) };
        }

        const validation = validateAnnonce(parsedBody);
        if (!validation.valid) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: validation.error }) };
        }

        const {
          titre, description, ville,
          emailContact, telephoneContact,
          photos = [],
          statut = 'publiee'
        } = parsedBody;

        const finalStatut = VALID_STATUTS.includes(statut) ? statut : 'publiee';

        const result = await pool.query(
          `INSERT INTO annonces
             (titre, description, ville, email_contact, telephone_contact, statut, user_email, photos)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id, titre, ville, statut, created_at`,
          [
            sanitize(titre, 200),
            sanitize(description, 5000),
            sanitize(ville, 100),
            emailContact    ? sanitize(emailContact, 254)    : null,
            telephoneContact ? sanitize(telephoneContact, 20) : null,
            finalStatut,
            authUser.email,
            JSON.stringify(photos)
          ]
        );

        console.log(`[ANNONCES_CREATE] ${new Date().toISOString()} - Créée par ${authUser.email} depuis ${clientIP}`);
        return { statusCode: 201, headers, body: JSON.stringify(result.rows[0]) };
      }

      // ══════════════════════════════════════════════
      // PUT  — Modifier ou basculer le statut
      // ══════════════════════════════════════════════
      case 'PUT': {
        if (!authUser) {
          return { statusCode: 401, headers, body: JSON.stringify({ error: 'Non autorisé' }) };
        }

        if (!validateId(parsedBody.id)) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'ID invalide' }) };
        }

        // Vérifier l'existence et la propriété
        const ownerCheck = await pool.query(
          `SELECT user_email, statut FROM annonces WHERE id = $1 AND statut != 'supprimee'`,
          [Number(parsedBody.id)]
        );

        if (!ownerCheck.rows.length) {
          return { statusCode: 404, headers, body: JSON.stringify({ error: 'Annonce introuvable' }) };
        }

        if (ownerCheck.rows[0].user_email !== authUser.email) {
          console.log(`[ANNONCES_FORBIDDEN] ${new Date().toISOString()} - ${authUser.email} a tenté de modifier l'annonce #${parsedBody.id}`);
          return { statusCode: 403, headers, body: JSON.stringify({ error: 'Accès refusé — cette annonce ne vous appartient pas' }) };
        }

        // Basculer le statut (Publier / Mettre en pause)
        if (parsedBody.action === 'toggle') {
          const currentStatut = ownerCheck.rows[0].statut;
          const newStatut = currentStatut === 'publiee' ? 'brouillon' : 'publiee';

          const result = await pool.query(
            `UPDATE annonces SET statut = $1, updated_at = NOW() WHERE id = $2 RETURNING id, statut`,
            [newStatut, Number(parsedBody.id)]
          );

          console.log(`[ANNONCES_TOGGLE] ${new Date().toISOString()} - Annonce #${parsedBody.id} → ${newStatut} par ${authUser.email}`);
          return { statusCode: 200, headers, body: JSON.stringify(result.rows[0]) };
        }

        // Mise à jour complète
        const validation = validateAnnonce(parsedBody);
        if (!validation.valid) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: validation.error }) };
        }

        const {
          titre, description, ville,
          emailContact, telephoneContact,
          photos = [],
          statut = 'publiee'
        } = parsedBody;

        const finalStatut = VALID_STATUTS.includes(statut) ? statut : 'publiee';

        const result = await pool.query(
          `UPDATE annonces
           SET titre = $1, description = $2, ville = $3,
               email_contact = $4, telephone_contact = $5,
               statut = $6, photos = $7, updated_at = NOW()
           WHERE id = $8
           RETURNING id, titre, ville, statut, updated_at`,
          [
            sanitize(titre, 200),
            sanitize(description, 5000),
            sanitize(ville, 100),
            emailContact    ? sanitize(emailContact, 254)    : null,
            telephoneContact ? sanitize(telephoneContact, 20) : null,
            finalStatut,
            JSON.stringify(photos),
            Number(parsedBody.id)
          ]
        );

        console.log(`[ANNONCES_UPDATE] ${new Date().toISOString()} - Annonce #${parsedBody.id} modifiée par ${authUser.email}`);
        return { statusCode: 200, headers, body: JSON.stringify(result.rows[0]) };
      }

      // ══════════════════════════════════════════════
      // DELETE  — Suppression logique
      // ══════════════════════════════════════════════
      case 'DELETE': {
        if (!authUser) {
          return { statusCode: 401, headers, body: JSON.stringify({ error: 'Non autorisé' }) };
        }

        if (!validateId(parsedBody.id)) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'ID invalide' }) };
        }

        const ownerCheck = await pool.query(
          `SELECT user_email FROM annonces WHERE id = $1 AND statut != 'supprimee'`,
          [Number(parsedBody.id)]
        );

        if (!ownerCheck.rows.length) {
          return { statusCode: 404, headers, body: JSON.stringify({ error: 'Annonce introuvable' }) };
        }

        if (ownerCheck.rows[0].user_email !== authUser.email) {
          console.log(`[ANNONCES_FORBIDDEN] ${new Date().toISOString()} - ${authUser.email} a tenté de supprimer l'annonce #${parsedBody.id}`);
          return { statusCode: 403, headers, body: JSON.stringify({ error: 'Accès refusé — cette annonce ne vous appartient pas' }) };
        }

        await pool.query(
          `UPDATE annonces SET statut = 'supprimee', updated_at = NOW() WHERE id = $1`,
          [Number(parsedBody.id)]
        );

        console.log(`[ANNONCES_DELETE] ${new Date().toISOString()} - Annonce #${parsedBody.id} supprimée par ${authUser.email}`);
        return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
      }

      default:
        return { statusCode: 405, headers, body: JSON.stringify({ error: 'Méthode non autorisée' }) };
    }

  } catch (error) {
    console.error(`[ANNONCES_ERROR] ${new Date().toISOString()} - ${error.message}`);
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Erreur serveur interne' }) };
  }
};
