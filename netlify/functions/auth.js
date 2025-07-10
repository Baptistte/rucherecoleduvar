const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Configuration Neon PostgreSQL
const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL || 'postgresql://neondb_owner:npg_n51StIYyoKkV@ep-lingering-snowflake-ae815a6g-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require',
  ssl: { rejectUnauthorized: false }
});

// Fonction pour récupérer un utilisateur depuis la base de données
async function getUserByEmail(email) {
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return result.rows[0] || null;
  } catch (error) {
    console.error('Database error:', error);
    return null;
  }
}

// Protection contre les attaques par force brute
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

// Validation d'email sécurisée
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

// Validation de mot de passe (longueur et caractères)
function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 1 && password.length <= 128;
}

// Validation de token JWT
function isValidToken(token) {
  return typeof token === 'string' && token.length > 0 && token.length <= 2048;
}

// Fonction de logging sécurisé
function logSecurityEvent(type, ip, details = '') {
  const timestamp = new Date().toISOString();
  console.log(`[SECURITY] ${timestamp} - ${type} from ${ip} - ${details}`);
}

exports.handler = async (event, context) => {
  const clientIP = event.headers['client-ip'] || event.headers['x-forwarded-for'] || 'unknown';
  
  // Headers de sécurité renforcés
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    logSecurityEvent('INVALID_METHOD', clientIP, event.httpMethod);
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    // Validation de la taille du body
    if (!event.body || event.body.length > 1024) {
      logSecurityEvent('INVALID_BODY_SIZE', clientIP);
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid request' })
      };
    }

    let parsedBody;
    try {
      parsedBody = JSON.parse(event.body);
    } catch (e) {
      logSecurityEvent('INVALID_JSON', clientIP);
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid JSON' })
      };
    }

    const { action, email, password, token } = parsedBody;

    // Validation de l'action
    if (!action || typeof action !== 'string' || !['login', 'verify'].includes(action)) {
      logSecurityEvent('INVALID_ACTION', clientIP, action);
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid action' })
      };
    }

    switch (action) {
      case 'login':
        // Vérification du rate limiting
        const attemptKey = `${clientIP}:${email}`;
        const attempts = loginAttempts.get(attemptKey) || { count: 0, lastAttempt: 0 };
        
        if (attempts.count >= MAX_ATTEMPTS) {
          const timeSinceLastAttempt = Date.now() - attempts.lastAttempt;
          if (timeSinceLastAttempt < LOCKOUT_TIME) {
            logSecurityEvent('RATE_LIMITED', clientIP, email);
            return {
              statusCode: 429,
              headers,
              body: JSON.stringify({ error: 'Too many attempts. Try again later.' })
            };
          } else {
            // Reset attempts après la période de lockout
            loginAttempts.delete(attemptKey);
          }
        }

        // Validation des entrées
        if (!isValidEmail(email) || !isValidPassword(password)) {
          logSecurityEvent('INVALID_CREDENTIALS_FORMAT', clientIP, email);
          attempts.count++;
          attempts.lastAttempt = Date.now();
          loginAttempts.set(attemptKey, attempts);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid credentials format' })
          };
        }

        // Vérification des identifiants via la base de données
        const user = await getUserByEmail(email);
        
        if (user) {
          const isValid = await bcrypt.compare(password, user.password_hash);
          
          if (isValid) {
            // Reset attempts on successful login
            loginAttempts.delete(attemptKey);
            
            const token = jwt.sign(
              { 
                email, 
                role: user.role || 'admin',
                iat: Math.floor(Date.now() / 1000),
                ip: clientIP 
              },
              JWT_SECRET,
              { expiresIn: '8h' } // Réduit de 24h à 8h pour plus de sécurité
            );
            
            logSecurityEvent('LOGIN_SUCCESS', clientIP, email);
            return {
              statusCode: 200,
              headers,
              body: JSON.stringify({ token, email })
            };
          }
        }
        
        // Échec de connexion
        attempts.count++;
        attempts.lastAttempt = Date.now();
        loginAttempts.set(attemptKey, attempts);
        
        logSecurityEvent('LOGIN_FAILURE', clientIP, email);
        return {
          statusCode: 401,
          headers,
          body: JSON.stringify({ error: 'Invalid credentials' })
        };

      case 'verify':
        if (!isValidToken(token)) {
          logSecurityEvent('INVALID_TOKEN_FORMAT', clientIP);
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid token format' })
          };
        }

        try {
          const decoded = jwt.verify(token, JWT_SECRET);
          
          // Vérification supplémentaire de l'IP (optionnel mais recommandé)
          if (decoded.ip && decoded.ip !== clientIP) {
            logSecurityEvent('IP_MISMATCH', clientIP, `Expected: ${decoded.ip}`);
            return {
              statusCode: 401,
              headers,
              body: JSON.stringify({ valid: false, error: 'Token invalid' })
            };
          }
          
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ valid: true, user: { email: decoded.email, role: decoded.role } })
          };
        } catch (err) {
          logSecurityEvent('TOKEN_VERIFICATION_FAILED', clientIP, err.message);
          return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ valid: false })
          };
        }

      default:
        logSecurityEvent('UNKNOWN_ACTION', clientIP, action);
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Invalid action' })
        };
    }
  } catch (error) {
    logSecurityEvent('SERVER_ERROR', clientIP, error.message);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Server error' })
    };
  }
}; 