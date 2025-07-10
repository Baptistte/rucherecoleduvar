const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Configuration Neon PostgreSQL
const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL || 'postgresql://neondb_owner:npg_n51StIYyoKkV@ep-lingering-snowflake-ae815a6g-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require',
  ssl: { rejectUnauthorized: false }
});

// Vérifier l'authentification pour les opérations d'écriture
const verifyAuth = (token, clientIP) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log(`[DOCUMENTS_AUTH] ${new Date().toISOString()} - Authorized access from ${clientIP} for ${decoded.email}`);
    return decoded;
  } catch (err) {
    console.log(`[DOCUMENTS_AUTH] ${new Date().toISOString()} - Unauthorized access attempt from ${clientIP}: ${err.message}`);
    return null;
  }
};

// Validation des données de document
const validateDocumentData = (data) => {
  const { title, url, category } = data;
  
  // Validation du titre
  if (!title || typeof title !== 'string' || title.length < 1 || title.length > 200) {
    return { valid: false, error: 'Invalid title format' };
  }
  
  // Validation de l'URL
  if (!url || typeof url !== 'string' || url.length > 500) {
    return { valid: false, error: 'Invalid URL format' };
  }
  
  // Validation de la catégorie
  const validCategories = ['admin', 'technique'];
  if (!category || !validCategories.includes(category)) {
    return { valid: false, error: 'Invalid category' };
  }
  
  return { valid: true };
};

// Validation de l'ID
const validateId = (id) => {
  return Number.isInteger(Number(id)) && Number(id) > 0;
};

exports.handler = async (event, context) => {
  const clientIP = event.headers['client-ip'] || event.headers['x-forwarded-for'] || 'unknown';
  
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store, no-cache, must-revalidate'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  try {
    const { httpMethod, body, headers: requestHeaders } = event;
    
    // Validation de la taille du body
    if (body && body.length > 2048) {
      console.log(`[DOCUMENTS_SECURITY] ${new Date().toISOString()} - Oversized request from ${clientIP}`);
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Request too large' })
      };
    }
    
    let parsedBody = {};
    if (body) {
      try {
        parsedBody = JSON.parse(body);
      } catch (e) {
        console.log(`[DOCUMENTS_SECURITY] ${new Date().toISOString()} - Invalid JSON from ${clientIP}`);
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Invalid JSON' })
        };
      }
    }

    switch (httpMethod) {
      case 'GET':
        // Récupérer tous les documents (public)
        try {
          const result = await pool.query(
            'SELECT * FROM documents ORDER BY category, title ASC'
          );
          
          console.log(`[DOCUMENTS_ACCESS] ${new Date().toISOString()} - Public documents access from ${clientIP}`);
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(result.rows)
          };
        } catch (dbError) {
          console.error(`[DOCUMENTS_DB_ERROR] ${new Date().toISOString()} - Database error: ${dbError.message}`);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Database error' })
          };
        }

      case 'POST':
        // Créer un nouveau document (admin seulement)
        const token = requestHeaders.authorization?.replace('Bearer ', '');
        const authUser = verifyAuth(token, clientIP);
        if (!authUser) {
          return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ error: 'Unauthorized' })
          };
        }

        // Validation des données
        const validation = validateDocumentData(parsedBody);
        if (!validation.valid) {
          console.log(`[DOCUMENTS_VALIDATION] ${new Date().toISOString()} - Invalid data from ${clientIP}: ${validation.error}`);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: validation.error })
          };
        }

        const { title, url, category } = parsedBody;
        try {
          const insertResult = await pool.query(
            'INSERT INTO documents (title, url, category) VALUES ($1, $2, $3) RETURNING *',
            [title, url, category]
          );

          console.log(`[DOCUMENTS_CREATE] ${new Date().toISOString()} - Document created by ${authUser.email} from ${clientIP}`);
          return {
            statusCode: 201,
            headers,
            body: JSON.stringify(insertResult.rows[0])
          };
        } catch (dbError) {
          console.error(`[DOCUMENTS_DB_ERROR] ${new Date().toISOString()} - Insert error: ${dbError.message}`);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Database error' })
          };
        }

      case 'PUT':
        // Modifier un document (admin seulement)
        const putToken = requestHeaders.authorization?.replace('Bearer ', '');
        const putAuthUser = verifyAuth(putToken, clientIP);
        if (!putAuthUser) {
          return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ error: 'Unauthorized' })
          };
        }

        // Validation de l'ID
        if (!validateId(parsedBody.id)) {
          console.log(`[DOCUMENTS_VALIDATION] ${new Date().toISOString()} - Invalid ID from ${clientIP}: ${parsedBody.id}`);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid ID' })
          };
        }

        // Validation des données
        const putValidation = validateDocumentData({
          title: parsedBody.title,
          url: parsedBody.url,
          category: parsedBody.category
        });
        if (!putValidation.valid) {
          console.log(`[DOCUMENTS_VALIDATION] ${new Date().toISOString()} - Invalid update data from ${clientIP}: ${putValidation.error}`);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: putValidation.error })
          };
        }

        const { id, title: newTitle, url: newUrl, category: newCategory } = parsedBody;
        try {
          const updateResult = await pool.query(
            'UPDATE documents SET title = $1, url = $2, category = $3 WHERE id = $4 RETURNING *',
            [newTitle, newUrl, newCategory, id]
          );

          if (updateResult.rows.length === 0) {
            console.log(`[DOCUMENTS_WARNING] ${new Date().toISOString()} - Update attempt on non-existent document ${id} by ${putAuthUser.email}`);
            return {
              statusCode: 404,
              headers,
              body: JSON.stringify({ error: 'Document not found' })
            };
          }

          console.log(`[DOCUMENTS_UPDATE] ${new Date().toISOString()} - Document ${id} updated by ${putAuthUser.email} from ${clientIP}`);
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(updateResult.rows[0])
          };
        } catch (dbError) {
          console.error(`[DOCUMENTS_DB_ERROR] ${new Date().toISOString()} - Update error: ${dbError.message}`);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Database error' })
          };
        }

      case 'DELETE':
        // Supprimer un document (admin seulement)
        const deleteToken = requestHeaders.authorization?.replace('Bearer ', '');
        const deleteAuthUser = verifyAuth(deleteToken, clientIP);
        if (!deleteAuthUser) {
          return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ error: 'Unauthorized' })
          };
        }

        // Validation de l'ID
        if (!validateId(parsedBody.id)) {
          console.log(`[DOCUMENTS_VALIDATION] ${new Date().toISOString()} - Invalid delete ID from ${clientIP}: ${parsedBody.id}`);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid ID' })
          };
        }

        const { id: deleteId } = parsedBody;
        try {
          const deleteResult = await pool.query('DELETE FROM documents WHERE id = $1', [deleteId]);
          
          if (deleteResult.rowCount === 0) {
            console.log(`[DOCUMENTS_WARNING] ${new Date().toISOString()} - Delete attempt on non-existent document ${deleteId} by ${deleteAuthUser.email}`);
            return {
              statusCode: 404,
              headers,
              body: JSON.stringify({ error: 'Document not found' })
            };
          }

          console.log(`[DOCUMENTS_DELETE] ${new Date().toISOString()} - Document ${deleteId} deleted by ${deleteAuthUser.email} from ${clientIP}`);
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
          };
        } catch (dbError) {
          console.error(`[DOCUMENTS_DB_ERROR] ${new Date().toISOString()} - Delete error: ${dbError.message}`);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Database error' })
          };
        }

      default:
        console.log(`[DOCUMENTS_SECURITY] ${new Date().toISOString()} - Invalid method ${httpMethod} from ${clientIP}`);
        return {
          statusCode: 405,
          headers,
          body: JSON.stringify({ error: 'Method not allowed' })
        };
    }
  } catch (error) {
    console.error(`[DOCUMENTS_ERROR] ${new Date().toISOString()} - Server error: ${error.message}`);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Server error' })
    };
  }
}; 