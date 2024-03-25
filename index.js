// JWST Server
const express = require('express');
const { generateKeyPair, createPublicKey } = require('crypto');
var jwt = require('jsonwebtoken');
const exp = require('constants');

const sqlite3 = require('sqlite3');
let db = new sqlite3.Database('totally_not_my_private_keys.db');

db.exec(`DROP TABLE IF EXISTS keys;`);

db.exec(`CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);`);

const port = 8080;
const keyGenOpts = {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
    }
}

function setExpiredKey(auth){
    let encoded = btoa(JSON.stringify(auth));
    //console.log(encoded);
    db.exec(`INSERT INTO keys (kid, key, exp)
    VALUES (0, "${encoded}", ${Date.now()});`)
}

async function getExpiredKey(){
    let out = new Promise((resolve, reject)=>{
        db.get(`SELECT * FROM keys WHERE kid=;`, [], (err, row)=> {
            if (err){
                reject(console.error(err.message));
            }
            resolve(JSON.parse(atob(row.key)));
        });
    });
    return await out;
}

function setKey(auth){
    let encoded = btoa(JSON.stringify(auth));
    db.exec(`INSERT INTO keys (key, exp)
    VALUES ("${encoded}", ${Date.now()+3.6e6});`)
}

async function getKey(kid){
    let out = new Promise((resolve, reject)=>{
        db.get(`SELECT * FROM keys WHERE kid=${kid}`, [], (err, row)=>{
            console.log(row)
            if(err){
                reject(console.error(err.message));
            }
            resolve(JSON.parse(atob(row.key)));
        })
    })
    return await out;
}

var serverAuth = {};
var expiredServerAuth = {};

generateKeyPair('rsa',keyGenOpts,(err, publicKey, privateKey) => {
    if (err) throw err;
    setExpiredKey({publicKey, privateKey});
});

generateKeyPair('rsa',keyGenOpts,(err, publicKey, privateKey) => {
    if (err) throw err;
    setKey({publicKey, privateKey});
});

const app = express();
app.use(function(req, res, next){
    console.log(req.url);
    next();
})

app.get('/', (req, res, err) => {
    res.sendStatus(200);
});

app.get('/.well-known/jwks.json', async (req, res, err)=>{
    res.set('Content-Type', 'application/json');
    let k = createPublicKey((await getKey(1)).publicKey);
    let jwk = k.export({format:"jwk"});
    jwk.kid = String(Date.now());
    let payload = {"jwks":[
        jwk,
    ]}
    console.log(payload);
    res.status(200).send(JSON.stringify( payload ));    
})

app.post('/auth', async (req, res, err) => {

    res.set('Content-Type', 'application/json');

    if (req.query.expired != undefined){
        return res.status(200).send(JSON.stringify({
            token: jwt.sign({
                data: 'Hello, World'
            }, (await getKey(0)).privateKey, {algorithm: 'RS256', expiresIn: '0'}),
        }));
    }

    return res.status(200).send(JSON.stringify({
        token: jwt.sign({
            data: 'Hello, World'
        }, (await getKey(0)).privateKey, {algorithm:'RS256', expiresIn: '1h'}),
    }))

});

app.listen(port, ()=>{
    console.log(`Server listening on ${port}`);
});