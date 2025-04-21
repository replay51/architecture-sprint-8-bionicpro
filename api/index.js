const express = require('express');
const session = require('express-session');
const Keycloak = require('keycloak-connect');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const axios = require('axios');

let keycloakPublicKeys = null;

const app = express();
const port = 8000;

const corsOptions = {
    origin: true,
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    allowedHeaders: ['Authorization', 'Content-Type'],
};
app.use(cors(corsOptions));

const memoryStore = new session.MemoryStore();
app.use(session({
    secret: 'oNwoLQdvJAvRcL89SydqCWCe5ry1jMgq',
    resave: false,
    saveUninitialized: true,
    store: memoryStore
}));
const keycloakConfig = {
    "realm": "reports-realm",
    "auth-server-url": process.env.KEYCLOAK_SERVER_URL || "http://localhost:8080/",
    "resource": "reports-api",
    // "resource": "reports-frontend",
    "confidential-port": 0,
    "ssl-required": "none",
    "bearer-only": true,
    "verify-token-audience": false,
    "credentials": {
        "secret": "oNwoLQdvJAvRcL89SydqCWCe5ry1jMgq"
    },
}
const keycloak = new Keycloak({ store: memoryStore }, keycloakConfig);
app.use(keycloak.middleware());

function requireRole(role) {
    return (req, res, next) => {
        const token = req.user;
        console.log('token:', token);
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const roles = token.realm_access?.roles || [];
        console.log('roles:', roles);
        if (!roles.includes(role)) {
            return res.status(403).json({ error: `Forbidden: missing required role (${role})` });
        }

        next();
    };
}

app.use((req, res, next) => {
    console.log("Authorization header:", req.headers.authorization);
    next();
});

async function loadKeycloakPublicKeys() {
    if (!keycloakPublicKeys) {
        const res = await axios.get('http://keycloak:8080/realms/reports-realm/protocol/openid-connect/certs');
        keycloakPublicKeys = res.data.keys;
    }
}
function formatCert(cert) {
    return cert.match(/.{1,64}/g).join('\n');
}

function getSigningKey(kid) {
    const key = keycloakPublicKeys.find(key => key.kid === kid);
    if (!key) throw new Error('Unable to find a signing key');
    const cert = key.x5c[0];
    const pem = `-----BEGIN CERTIFICATE-----\n${formatCert(cert)}\n-----END CERTIFICATE-----\n`;
    return pem;
}

async function manualProtect(req, res, next) {
    try {
        await loadKeycloakPublicKeys();
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing Authorization header' });
        }

        const tokenString = authHeader.substring(7);
        const decodedHeader = jwt.decode(tokenString, { complete: true });
        const kid = decodedHeader.header.kid;
        const publicKey = getSigningKey(kid);

        const payload = jwt.verify(tokenString, publicKey, {
            algorithms: ['RS256'],
            issuer: 'http://localhost:8080/realms/reports-realm',
        });
        console.log('Token payload:', payload);
        req.user = payload;
        next();
    } catch (err) {
        console.error('Auth error:', err.message);
        return res.status(403).json({ error: 'Forbidden' });
    }
}

app.get('/reports', manualProtect, requireRole('prothetic_user'), (req, res) => {
    res.json({
        'payload': 'lorem ipsum dolor sit amet consectetur adipisicing elit.'
    });
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});