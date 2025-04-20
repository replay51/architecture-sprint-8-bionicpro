const express = require('express');
const session = require('express-session');
const Keycloak = require('keycloak-connect');
const cors = require('cors');

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
        console.log(req.kauth)
        const token = req.kauth?.grant?.access_token;
        if (!token) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const roles = token.content?.realm_access?.roles || [];
        if (!roles.includes(role)) {
            return res.status(403).json({ error: `Forbidden: missing required role (${role})` });
        }

        next();
    };
}

app.get('/reports', keycloak.protect(), requireRole('prothetic_user'), (req, res) => {
    res.json({
        'payload': 'lorem ipsum dolor sit amet consectetur adipisicing elit.'
    });
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});