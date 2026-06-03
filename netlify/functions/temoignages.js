/**
 * Netlify Function : temoignages.js
 * Livre d'or public — Rucher-École du VAR
 *
 * Table existante dans Neon :
 *
 * CREATE TABLE IF NOT EXISTS temoignages (
 *   id         SERIAL PRIMARY KEY,
 *   nom        VARCHAR(100) NOT NULL,
 *   prenom     VARCHAR(100) NOT NULL,
 *   message    TEXT NOT NULL,
 *   photo_data TEXT,
 *   photo_name VARCHAR(255),
 *   photo_mime VARCHAR(50),
 *   visible    BOOLEAN NOT NULL DEFAULT true,
 *   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 * );
 *
 * GET    — public, retourne les témoignages visible=true
 * POST   — public, crée un témoignage
 * DELETE — admin seulement, suppression définitive
 * PATCH  — admin seulement, bascule visible (masquer/afficher)
 */

const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const pool = new Pool({
  connectionString: process.env.NETLIFY_DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const verifyAuth = (token, clientIP) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    console.log(`[TEMOIGNAGES_AUTH] ${new Date().toISOString()} - Unauthorized from ${clientIP}`);
    return null;
  }
};

const validateId = (id) => Number.isInteger(Number(id)) && Number(id) > 0;

const sanitize = (str, maxLen) => {
  if (!str || typeof str !== 'string') return null;
  return str.trim().slice(0, maxLen);
};

const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const MAX_PHOTO_B64 = 3 * 1024 * 1024; // ~2.2 MB image réelle

exports.handler = async (event) => {
  const clientIP = event.headers['client-ip'] || event.headers['x-forwarded-for'] || 'unknown';

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, PATCH, OPTIONS',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store, no-cache, must-revalidate'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  try {
    const { httpMethod, body, headers: reqHeaders } = event;

    let parsedBody = {};
    if (body) {
      if (body.length > 4 * 1024 * 1024) {
        return { statusCode: 413, headers, body: JSON.stringify({ error: 'Requête trop volumineuse' }) };
      }
      try {
        parsedBody = JSON.parse(body);
      } catch {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'JSON invalide' }) };
      }
    }

    switch (httpMethod) {
      // ── GET : liste publique (visible uniquement) ─────────────
      case 'GET': {
        const result = await pool.query(
          `SELECT id, nom, prenom, message, photo_data, photo_name, photo_mime, created_at
           FROM temoignages
           WHERE visible = true
           ORDER BY created_at DESC`
        );
        return { statusCode: 200, headers, body: JSON.stringify(result.rows) };
      }

      // ── POST : créer un témoignage (public) ───────────────────
      case 'POST': {
        const nom    = sanitize(parsedBody.nom,    100);
        const prenom = sanitize(parsedBody.prenom, 100);
        const message = sanitize(parsedBody.message, 2000);

        if (!nom || nom.length < 2) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Nom invalide (2 caractères minimum)' }) };
        }
        if (!prenom || prenom.length < 2) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Prénom invalide (2 caractères minimum)' }) };
        }
        if (!message || message.length < 10) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Message trop court (10 caractères minimum)' }) };
        }

        let photoData = null, photoName = null, photoMime = null;

        if (parsedBody.photo_data) {
          if (typeof parsedBody.photo_data !== 'string' || parsedBody.photo_data.length > MAX_PHOTO_B64) {
            return { statusCode: 400, headers, body: JSON.stringify({ error: 'Photo trop volumineuse (max 2 Mo)' }) };
          }
          if (!parsedBody.photo_mime || !ALLOWED_MIME.includes(parsedBody.photo_mime)) {
            return { statusCode: 400, headers, body: JSON.stringify({ error: 'Format photo non supporté (JPEG, PNG, WebP, GIF)' }) };
          }
          photoData = parsedBody.photo_data;
          photoMime = parsedBody.photo_mime;
          photoName = sanitize(parsedBody.photo_name, 255) || 'photo';
        }

        const result = await pool.query(
          `INSERT INTO temoignages (nom, prenom, message, photo_data, photo_name, photo_mime)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, nom, prenom, message, photo_data, photo_name, photo_mime, created_at`,
          [nom, prenom, message, photoData, photoName, photoMime]
        );

        console.log(`[TEMOIGNAGES_CREATE] ${new Date().toISOString()} - Témoignage de "${prenom} ${nom}" depuis ${clientIP}`);
        return { statusCode: 201, headers, body: JSON.stringify(result.rows[0]) };
      }

      // ── DELETE : suppression définitive (admin) ───────────────
      case 'DELETE': {
        const token = reqHeaders.authorization?.replace('Bearer ', '');
        const authUser = verifyAuth(token, clientIP);
        if (!authUser) return { statusCode: 401, headers, body: JSON.stringify({ error: 'Non authentifié' }) };
        if (authUser.role !== 'admin') return { statusCode: 403, headers, body: JSON.stringify({ error: 'Accès refusé' }) };

        if (!validateId(parsedBody.id)) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'ID invalide' }) };
        }

        const del = await pool.query('DELETE FROM temoignages WHERE id = $1', [parsedBody.id]);
        if (del.rowCount === 0) {
          return { statusCode: 404, headers, body: JSON.stringify({ error: 'Témoignage introuvable' }) };
        }

        console.log(`[TEMOIGNAGES_DELETE] ${new Date().toISOString()} - ID ${parsedBody.id} supprimé par ${authUser.email}`);
        return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
      }

      // ── PATCH : basculer visibilité (admin) ───────────────────
      case 'PATCH': {
        const token = reqHeaders.authorization?.replace('Bearer ', '');
        const authUser = verifyAuth(token, clientIP);
        if (!authUser) return { statusCode: 401, headers, body: JSON.stringify({ error: 'Non authentifié' }) };
        if (authUser.role !== 'admin') return { statusCode: 403, headers, body: JSON.stringify({ error: 'Accès refusé' }) };

        if (!validateId(parsedBody.id) || typeof parsedBody.visible !== 'boolean') {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Paramètres invalides' }) };
        }

        const upd = await pool.query(
          'UPDATE temoignages SET visible = $1 WHERE id = $2 RETURNING id, visible',
          [parsedBody.visible, parsedBody.id]
        );
        if (upd.rowCount === 0) {
          return { statusCode: 404, headers, body: JSON.stringify({ error: 'Témoignage introuvable' }) };
        }

        console.log(`[TEMOIGNAGES_VISIBILITY] ${new Date().toISOString()} - ID ${parsedBody.id} visible=${parsedBody.visible} par ${authUser.email}`);
        return { statusCode: 200, headers, body: JSON.stringify(upd.rows[0]) };
      }

      default:
        return { statusCode: 405, headers, body: JSON.stringify({ error: 'Méthode non autorisée' }) };
    }
  } catch (error) {
    console.error(`[TEMOIGNAGES_ERROR] ${new Date().toISOString()} - ${error.message}`);
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Erreur serveur' }) };
  }
};
