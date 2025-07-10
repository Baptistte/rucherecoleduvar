# Rucher École du Var

Site web moderne et responsive pour le Rucher École du Var, construit avec HTML, CSS (Tailwind), JavaScript et backend Netlify + Neon PostgreSQL.

## Fonctionnalités

- **Design moderne** : Interface élégante avec palette de couleurs personnalisée
- **Police personnalisée** : Utilisation de la police Gotham-Medium sur tout le site
- **Responsive** : Adaptation parfaite à tous les écrans
- **Animations** : Effets visuels fluides pour une expérience utilisateur engageante
- **Navigation intuitive** : Menu sticky avec indicateurs visuels
- **Galerie photo** : Présentation des activités du rucher avec upload d'images
- **Formulaires** : Section dédiée aux documents administratifs
- **Planning dynamique** : Calendrier des activités géré en base de données
- **Administration sécurisée** : Panel d'admin avec authentification renforcée
- **Sécurité avancée** : Protection contre les attaques par force brute, injections SQL, etc.
- **Base de données** : PostgreSQL hébergé sur Neon
- **Contact** : Informations de contact et localisation

## Technologies utilisées

### Frontend
- HTML5 sémantique
- Tailwind CSS pour le styling
- JavaScript ES6+ pour les interactions
- Police personnalisée Gotham-Medium
- Design responsive mobile-first

### Backend
- **Netlify Functions** : API serverless
- **Neon PostgreSQL** : Base de données cloud
- **JWT** : Authentification sécurisée avec protection IP
- **bcrypt** : Hashage des mots de passe
- **Validation d'entrée** : Protection contre les injections SQL
- **Rate limiting** : Protection contre les attaques par force brute
- **Logs de sécurité** : Monitoring complet des accès

## Sécurité

### Authentification
- Tokens JWT avec expiration courte (8h)
- Protection contre les attaques par force brute (5 tentatives max)
- Lockout automatique de 15 minutes
- Validation IP dans les tokens
- Hashage bcrypt des mots de passe
- Chemin d'administration sécurisé (non-prévisible)

### API Security
- Validation stricte des entrées
- Requêtes SQL paramétrées (protection anti-injection)
- Headers de sécurité (CSP, XSS protection, etc.)
- Limitation de taille des requêtes
- Logs de sécurité complets
- Validation des types MIME pour les images
- Limitation de taille des fichiers (5MB)

### Monitoring
- Logs détaillés de tous les accès admin
- Alertes sur les tentatives d'intrusion
- Tracking des modifications de contenu
- Audit trail complet

## Structure du projet

```
/
├── index.html                     # Page d'accueil principale
├── formulaires.html              # Page des documents et formulaires
├── planning.html                 # Page du calendrier des activités
├── urgence.html                  # Page de signalement d'essaims
├── galerie.html                  # Page galerie photo
├── gestion-[random].html         # Panel d'administration (chemin sécurisé)
├── fonts/                        # Police personnalisée
│   └── Gotham-Medium.otf
├── package.json                  # Dépendances Node.js
├── netlify.toml                 # Configuration Netlify
├── db-setup.sql                 # Script de création des tables
├── env.example                  # Variables d'environnement exemple
├── README.md                    # Documentation du projet
├── netlify/functions/           # Fonctions serverless
│   ├── auth.js                 # Authentification sécurisée
│   ├── calendar.js             # Gestion du calendrier
│   ├── documents.js            # Gestion des documents
│   └── photos.js               # Gestion de la galerie
└── assets/                     # Images et ressources
    ├── Sans-titrelogo-seul-removebg-preview.png
    ├── saintraphphoto.jpg
    ├── saintraphresize.jpg
    ├── imagebackground.png
    ├── atelierpedago.jpg
    ├── recoltemiel.jpg
    ├── viedurucher.jpg
    └── environnement.jpg
```

## Installation et configuration

### 1. Prérequis
- Compte [Netlify](https://netlify.com)
- Compte [Neon](https://neon.tech) pour PostgreSQL
- Node.js (pour le développement local)

### 2. Configuration de la base de données
1. Créez une base de données sur Neon.tech
2. Exécutez le script `db-setup.sql` dans votre console Neon
3. Notez l'URL de connexion PostgreSQL

### 3. Configuration des variables d'environnement
Dans les settings Netlify, ajoutez :
```
NEON_DATABASE_URL=postgresql://username:password@hostname/database?sslmode=require
JWT_SECRET=votre-secret-key-ultra-securise-256-bits-minimum
ADMIN_EMAIL=rucher.ecole83700@gmail.com
ADMIN_PASSWORD_HASH=$2a$10$votrehashbcryptdumotdepasseadmin
```

### 4. Génération du hash du mot de passe admin
```bash
npm install bcryptjs
node -e "console.log(require('bcryptjs').hashSync('votre-mot-de-passe-fort', 10))"
```

**⚠️ IMPORTANT** : Utilisez un mot de passe fort (minimum 12 caractères, majuscules, minuscules, chiffres, symboles)

### 5. Déploiement
1. Connectez votre repo GitHub à Netlify
2. Configurez les variables d'environnement
3. Déployez le site

## Développement local

```bash
# Installer les dépendances
npm install

# Démarrer le serveur de développement Netlify
npm run dev

# Accéder au site sur http://localhost:8888
```

## Utilisation du panel d'administration

### ⚠️ Accès sécurisé
Le panel d'administration n'est **PAS** accessible via `/admin.html`. Le chemin sécurisé est généré aléatoirement et doit être communiqué séparément. Ceci protège contre :
- Les attaques par dictionnaire
- Le scanning automatisé
- Les tentatives d'accès non autorisées

### Fonctionnalités admin
- **Calendrier** : Ajouter, modifier, supprimer des événements
- **Documents** : Gérer les fichiers administratifs et techniques
- **Galerie** : Upload et gestion des photos (URL ou fichiers)
- **Authentification** : Connexion sécurisée avec token JWT

### Sécurité admin
- Session limitée à 8 heures
- Protection contre les attaques par force brute
- Logs de toutes les actions
- Validation stricte des données

## API Endpoints

### Publics (lecture seule)
- `GET /.netlify/functions/calendar` : Récupérer les événements
- `GET /.netlify/functions/documents` : Récupérer les documents
- `GET /.netlify/functions/photos` : Récupérer les photos

### Sécurisés (admin uniquement)
- `POST /.netlify/functions/auth` : Authentification
- `POST/PUT/DELETE /.netlify/functions/calendar` : Gestion du calendrier
- `POST/PUT/DELETE /.netlify/functions/documents` : Gestion des documents
- `POST/PUT/DELETE /.netlify/functions/photos` : Gestion de la galerie

## Personnalisation

### Couleurs
Les couleurs sont définies dans la configuration Tailwind :
- **wheat** (#E8D7A8) : Fond doux
- **raw** (#816557) : Texte secondaire
- **seal** (#561F04) : Texte principal
- **gamboge** (#F6A01F) : Accent principal
- **tigers** (#BA6E1F) : Accent secondaire
- **fond-clair** (#F5F5F5) : Fond principal

### Polices
- **Gotham-Medium** : Police principale du site
- Configuration via `@font-face` et classes Tailwind personnalisées

### Contenu
- **Statique** : Modifiez directement le HTML
- **Dynamique** : Utilisez le panel d'administration

## Sécurité et maintenance

### Bonnes pratiques
1. **Mots de passe** : Utilisez des mots de passe forts et uniques
2. **Tokens JWT** : Configurez une clé secrète forte (256 bits minimum)
3. **Monitoring** : Surveillez les logs Netlify régulièrement
4. **Backups** : Exportez les données Neon mensuellement
5. **Updates** : Maintenez les dépendances à jour

### Surveillance
- Consultez les logs Netlify pour détecter des activités suspectes
- Surveillez les tentatives de connexion échouées
- Vérifiez l'intégrité des données régulièrement

### Incident Response
En cas d'intrusion suspectée :
1. Changez immédiatement le mot de passe admin
2. Régénérez la clé JWT
3. Analysez les logs pour identifier l'origine
4. Changez le chemin d'administration si nécessaire

## Support

Pour toute question technique :
1. Vérifiez les logs Netlify en cas d'erreur
2. Vérifiez la connexion à la base de données Neon
3. Validez les variables d'environnement
4. Consultez la documentation des APIs

## Auteur

Développé pour le Rucher École du Var  
Architecture : Netlify + Neon PostgreSQL  
Sécurité renforcée avec authentification JWT et protection contre les attaques

## Licence

Projet sous licence libre pour usage associatif. 