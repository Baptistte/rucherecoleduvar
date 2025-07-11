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
    console.log(`[PHOTOS_AUTH] ${new Date().toISOString()} - Authorized access from ${clientIP} for ${decoded.email}`);
    return decoded;
  } catch (err) {
    console.log(`[PHOTOS_AUTH] ${new Date().toISOString()} - Unauthorized access attempt from ${clientIP}: ${err.message}`);
    return null;
  }
};

// Helper pour générer une data URL à partir des données de l'image
const getImageDataUrl = (photo) => {
  if (photo.image_data && photo.mime_type) {
    return `data:${photo.mime_type};base64,${photo.image_data}`;
  }
  return photo.url || '';
};

// Validation des types MIME autorisés pour les images
const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/jpg', 
  'image/png',
  'image/gif',
  'image/webp'
];

// Taille maximale des fichiers (5 MB)
const MAX_FILE_SIZE = 5 * 1024 * 1024;

// Validation des données de photo
const validatePhotoData = (data) => {
  const { title, description, url, imageData, fileName, fileSize, mimeType, category } = data;
  
  // Validation du titre
  if (!title || typeof title !== 'string' || title.length < 1 || title.length > 200) {
    return { valid: false, error: 'Invalid title format' };
  }
  
  // Validation de la description (optionnelle)
  if (description && (typeof description !== 'string' || description.length > 1000)) {
    return { valid: false, error: 'Invalid description format' };
  }
  
  // Validation de la catégorie
  const validCategories = ['apiculture', 'formation', 'evenements', 'rucher'];
  if (!category || !validCategories.includes(category)) {
    return { valid: false, error: 'Invalid category' };
  }
  
  // Validation : soit URL soit imageData requis
  if (!url && !imageData) {
    return { valid: false, error: 'URL ou données d\'image requises' };
  }
  
  // Validation de l'URL si fournie
  if (url && (typeof url !== 'string' || url.length > 500)) {
    return { valid: false, error: 'Invalid URL format' };
  }
  
  // Validation des données d'image si fournies
  if (imageData) {
    // Validation Base64
    if (typeof imageData !== 'string' || !isValidBase64(imageData)) {
      return { valid: false, error: 'Invalid image data format' };
    }
    
    // Validation du type MIME
    if (!mimeType || !ALLOWED_MIME_TYPES.includes(mimeType)) {
      return { valid: false, error: 'Invalid or unsupported image type' };
    }
    
    // Validation de la taille de fichier
    if (fileSize && (typeof fileSize !== 'number' || fileSize > MAX_FILE_SIZE || fileSize < 1)) {
      return { valid: false, error: 'File size too large or invalid' };
    }
    
    // Validation du nom de fichier
    if (fileName && (typeof fileName !== 'string' || fileName.length > 255)) {
      return { valid: false, error: 'Invalid file name' };
    }
  }
  
  return { valid: true };
};

// Validation Base64
const isValidBase64 = (str) => {
  try {
    // Vérifie si c'est un Base64 valide et pas trop long (5MB max)
    if (str.length > MAX_FILE_SIZE * 1.4) { // Base64 ajoute ~33% de taille
      return false;
    }
    
    // Validation basique du format Base64
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(str)) {
      return false;
    }
    
    // Utiliser Buffer pour valider le Base64 dans Node.js
    const buffer = Buffer.from(str, 'base64');
    return buffer.length > 0;
  } catch (err) {
    return false;
  }
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
    
    // Validation de la taille du body (plus large pour les images)
    if (body && body.length > 8 * 1024 * 1024) { // 8MB pour les images en Base64
      console.log(`[PHOTOS_SECURITY] ${new Date().toISOString()} - Oversized request from ${clientIP}`);
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
        console.log(`[PHOTOS_SECURITY] ${new Date().toISOString()} - Invalid JSON from ${clientIP}`);
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Invalid JSON' })
        };
      }
    }

    switch (httpMethod) {
      case 'GET':
        // Récupérer toutes les photos (public)
        try {
          const result = await pool.query(
            'SELECT * FROM photos ORDER BY category, created_at DESC'
          );
          
          // Convertir les données pour l'affichage
          const photos = result.rows.map(photo => ({
            ...photo,
            displayUrl: getImageDataUrl(photo)
          }));
          
          console.log(`[PHOTOS_ACCESS] ${new Date().toISOString()} - Public photos access from ${clientIP} (${photos.length} photos)`);
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(photos)
          };
        } catch (dbError) {
          console.error(`[PHOTOS_DB_ERROR] ${new Date().toISOString()} - Database error: ${dbError.message}`);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Database error' })
          };
        }

      case 'POST':
        // Créer une nouvelle photo (admin seulement)
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
        const validation = validatePhotoData(parsedBody);
        if (!validation.valid) {
          console.log(`[PHOTOS_VALIDATION] ${new Date().toISOString()} - Invalid data from ${clientIP}: ${validation.error}`);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: validation.error })
          };
        }

        const { 
          title, 
          description, 
          url, 
          imageData, 
          fileName, 
          fileSize, 
          mimeType, 
          category 
        } = parsedBody;

        try {
          const insertResult = await pool.query(
            `INSERT INTO photos (title, description, url, image_data, file_name, file_size, mime_type, category) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [title, description || '', url || null, imageData || null, fileName || null, fileSize || null, mimeType || null, category]
          );

          const newPhoto = {
            ...insertResult.rows[0],
            displayUrl: getImageDataUrl(insertResult.rows[0])
          };

          console.log(`[PHOTOS_CREATE] ${new Date().toISOString()} - Photo created by ${authUser.email} from ${clientIP} (${fileSize ? Math.round(fileSize/1024) + 'KB' : 'URL'})`);
          return {
            statusCode: 201,
            headers,
            body: JSON.stringify(newPhoto)
          };
        } catch (dbError) {
          console.error(`[PHOTOS_DB_ERROR] ${new Date().toISOString()} - Insert error: ${dbError.message}`);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Database error' })
          };
        }

      case 'PUT':
        // Modifier une photo (admin seulement)
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
          console.log(`[PHOTOS_VALIDATION] ${new Date().toISOString()} - Invalid ID from ${clientIP}: ${parsedBody.id}`);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid ID' })
          };
        }

        // Validation des données
        const putValidation = validatePhotoData({
          title: parsedBody.title,
          description: parsedBody.description,
          url: parsedBody.url,
          imageData: parsedBody.imageData,
          fileName: parsedBody.fileName,
          fileSize: parsedBody.fileSize,
          mimeType: parsedBody.mimeType,
          category: parsedBody.category
        });
        if (!putValidation.valid) {
          console.log(`[PHOTOS_VALIDATION] ${new Date().toISOString()} - Invalid update data from ${clientIP}: ${putValidation.error}`);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: putValidation.error })
          };
        }

        const { 
          id, 
          title: newTitle, 
          description: newDescription, 
          url: newUrl, 
          imageData: newImageData,
          fileName: newFileName,
          fileSize: newFileSize,
          mimeType: newMimeType,
          category: newCategory 
        } = parsedBody;

        try {
          const updateResult = await pool.query(
            `UPDATE photos SET 
             title = $1, description = $2, url = $3, image_data = $4, 
             file_name = $5, file_size = $6, mime_type = $7, category = $8, 
             updated_at = CURRENT_TIMESTAMP 
             WHERE id = $9 RETURNING *`,
            [
              newTitle, 
              newDescription || '', 
              newUrl || null, 
              newImageData || null,
              newFileName || null,
              newFileSize || null,
              newMimeType || null,
              newCategory, 
              id
            ]
          );

          if (updateResult.rows.length === 0) {
            console.log(`[PHOTOS_WARNING] ${new Date().toISOString()} - Update attempt on non-existent photo ${id} by ${putAuthUser.email}`);
            return {
              statusCode: 404,
              headers,
              body: JSON.stringify({ error: 'Photo not found' })
            };
          }

          const updatedPhoto = {
            ...updateResult.rows[0],
            displayUrl: getImageDataUrl(updateResult.rows[0])
          };

          console.log(`[PHOTOS_UPDATE] ${new Date().toISOString()} - Photo ${id} updated by ${putAuthUser.email} from ${clientIP}`);
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(updatedPhoto)
          };
        } catch (dbError) {
          console.error(`[PHOTOS_DB_ERROR] ${new Date().toISOString()} - Update error: ${dbError.message}`);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Database error' })
          };
        }

      case 'DELETE':
        // Supprimer une photo (admin seulement)
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
          console.log(`[PHOTOS_VALIDATION] ${new Date().toISOString()} - Invalid delete ID from ${clientIP}: ${parsedBody.id}`);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid ID' })
          };
        }

        const { id: deleteId } = parsedBody;
        try {
          const deleteResult = await pool.query('DELETE FROM photos WHERE id = $1', [deleteId]);
          
          if (deleteResult.rowCount === 0) {
            console.log(`[PHOTOS_WARNING] ${new Date().toISOString()} - Delete attempt on non-existent photo ${deleteId} by ${deleteAuthUser.email}`);
            return {
              statusCode: 404,
              headers,
              body: JSON.stringify({ error: 'Photo not found' })
            };
          }

          console.log(`[PHOTOS_DELETE] ${new Date().toISOString()} - Photo ${deleteId} deleted by ${deleteAuthUser.email} from ${clientIP}`);
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true })
          };
        } catch (dbError) {
          console.error(`[PHOTOS_DB_ERROR] ${new Date().toISOString()} - Delete error: ${dbError.message}`);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Database error' })
          };
        }

      default:
        console.log(`[PHOTOS_SECURITY] ${new Date().toISOString()} - Invalid method ${httpMethod} from ${clientIP}`);
        return {
          statusCode: 405,
          headers,
          body: JSON.stringify({ error: 'Method not allowed' })
        };
    }
  } catch (error) {
    console.error(`[PHOTOS_ERROR] ${new Date().toISOString()} - Server error: ${error.message}`);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Server error' })
    };
  }
}; 