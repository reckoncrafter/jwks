import express from "express";
import { subtle, KeyObject } from "crypto";
import pkg from 'jsonwebtoken';
import { Sequelize, DataTypes, Op } from 'sequelize';
import { hash as argon2 } from 'argon2';
import { v4 as uuid } from 'uuid';
const { sign } = pkg;
const port = 8080;
let db = new Sequelize('database', 'username', undefined, {
    dialect: "sqlite",
    storage: "./totally_not_my_privateKeys.db",
});
// "secant"
const ENV_KEY_KEY = process.env.NOT_MY_KEY ?? "1290690F78CD5B71242F1F6975BAAD23";
const envKeyObj = await subtle.importKey("raw", Buffer.from(ENV_KEY_KEY, 'utf8'), { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
const keys = db.define('keys', {
    kid: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    key: {
        type: DataTypes.BLOB,
        allowNull: false,
    },
    exp: {
        type: DataTypes.INTEGER,
        allowNull: false,
    }
}, { timestamps: false });
const users = db.define('users', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    username: {
        type: DataTypes.TEXT,
        allowNull: false,
        unique: true,
    },
    password_hash: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    email: {
        type: DataTypes.TEXT,
        unique: true,
    },
    date_registered: {
        type: 'TIMESTAMP',
        defaultValue: Sequelize.literal("CURRENT_TIMESTAMP"),
    },
    last_login: {
        type: 'TIMESTAMP'
    }
}, { timestamps: false });
const auth_logs = db.define('auth_logs', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    request_ip: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    request_timestamp: {
        type: 'TIMESTAMP',
        defaultValue: Sequelize.literal("CURRENT_TIMESTAMP"),
    },
}, { timestamps: false });
// FOREIGN KEY(user_id) REFERENCES users(id)
users.hasOne(auth_logs, {
    foreignKey: "user_id"
});
await db.sync({ force: true });
// CREATE TABLE IF NOT EXISTS auth_logs(
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     request_ip TEXT NOT NULL,
//     request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//     user_id INTEGER,  
//     FOREIGN KEY(user_id) REFERENCES users(id)
// );
// db.exec(`CREATE TABLE IF NOT EXISTS keys(
//     kid INTEGER PRIMARY KEY AUTOINCREMENT,
//     key BLOB NOT NULL,
//     exp INTEGER NOT NULL
// );`);
// db.exec(`CREATE TABLE IF NOT EXISTS users(
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     username TEXT NOT NULL UNIQUE,
//     password_hash TEXT NOT NULL,
//     email TEXT UNIQUE,
//     date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//     last_login TIMESTAMP
// );`);
async function generateJWT(expired = false) {
    const lifespan = expired ? 0 : 3600000; // One hour
    const signOpts = { expiresIn: (expired ? "0s" : "1h") };
    // Generate new key
    let key = await subtle.generateKey({
        name: "HMAC",
        hash: { name: "SHA-256" },
    }, true, ["sign", "verify"]);
    // Insert into Database
    // This needs to be encrypted!
    let keyExportBuffer = await subtle.exportKey("raw", key);
    let encryptedKeyExportBuffer = Buffer.from(await subtle.encrypt({ name: "AES-CBC" }, envKeyObj, keyExportBuffer));
    // INSERT INTO keys (key, exp) VALUES(@key, @exp)
    keys.create({
        key: encryptedKeyExportBuffer,
        exp: Date.now() + lifespan // One hour
    });
    let token = sign({ data: "Hello, World!" }, KeyObject.from(key), signOpts); // SECRET KEY GOES HERE!
    return token;
}
async function generateJWKS() {
    /*
    Take all (unexpired) from the database and package them into a JWKS
    */
    let jwks = { keys: [] };
    // SELECT * FROM keys WHERE exp > @date
    let allKeys = await keys.findAll({
        where: {
            exp: {
                [Op.gt]: Date.now()
            }
        }
    });
    for (const k of allKeys) {
        let keyBuf = k.dataValues.key;
        let keyObj = await subtle.importKey("raw", keyBuf, { name: "HMAC", "hash": { name: "SHA-256" } }, true, ["sign", "verify"]);
        let jwk = await subtle.exportKey("jwk", keyObj);
        let modJWK = Object(jwk); // decompose JsonKeyObject -> any
        modJWK.kid = String(k.dataValues.kid);
        jwks.keys.push(modJWK);
    }
    return jwks;
}
await generateJWT();
await generateJWKS();
const app = express();
app.use(function (req, res, next) {
    console.log(req.url);
    next();
});
app.use(express.json());
app.get('/', (req, res, err) => {
    res.sendStatus(200);
});
app.get('/.well-known/jwks.json', async (req, res, err) => {
    res.set('Content-Type', 'application/json');
    res.send(JSON.stringify(await generateJWKS()));
});
var rateLimiter = 0;
app.all('/auth', async (req, res, err) => {
    if (rateLimiter > 10) {
        console.log("RATE LIMITER TRIGGERED " + rateLimiter);
        res.status(429).send();
        return;
    }
    rateLimiter++;
    setTimeout(() => {
        rateLimiter = 0;
    }, 10000);
    res.set('Content-Type', 'application/json');
    let username = req.body.username;
    console.log(username);
    let user_id = await users.findOne({
        where: {
            username: {
                [Op.eq]: username
            }
        }
    });
    console.log(user_id?.dataValues.id);
    auth_logs.create({
        request_ip: req.ip,
        user_id: user_id?.dataValues.id
    });
    if (req.query.expired != undefined) {
        res.send(await generateJWT(true));
    }
    else {
        res.send(await generateJWT());
    }
});
app.all('/register', async (req, res, err) => {
    res.set('Content-Type', 'application/json');
    let reg = req.body;
    let new_password = uuid();
    users.create({
        username: reg.username ?? "none",
        password_hash: await argon2(new_password),
        email: reg.email ?? "none",
        last_login: Date.now(),
    });
    let pswd = {
        password: new_password
    };
    // 201
    res.status(201).send(JSON.stringify(pswd));
});
app.listen(port, () => {
    console.log(`Server listening on ${port}`);
});
