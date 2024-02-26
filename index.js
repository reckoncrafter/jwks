// JWST Server
const express = require('express');
const { generateKeyPair, createPublicKey } = require('crypto');
var jwt = require('jsonwebtoken');
const exp = require('constants');

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

var serverAuth = {};
var expiredServerAuth = {};

generateKeyPair('rsa',keyGenOpts,(err, publicKey, privateKey) => {
    if (err) throw err;
    serverAuth = {publicKey, privateKey};
});
generateKeyPair('rsa',keyGenOpts,(err, publicKey, privateKey) => {
    if (err) throw err;
    expiredServerAuth = {publicKey, privateKey};
});

// Expire and refresh
setInterval(()=>{
    expiredServerAuth = serverAuth;
    generateKeyPair('rsa',keyGenOpts,(err, publicKey, privateKey) => {
        if (err) throw err;
        serverAuth = {publicKey, privateKey};
    });
}, 60000);


const app = express();
app.use(function(req, res, next){
    console.log(req.url);
    next();
})

app.get('/', (req, res, err) => {
    res.sendStatus(200);
});

app.get('/.well-known/jwks.json', (req, res, err)=>{
    res.set('Content-Type', 'application/json');
    let k = createPublicKey(serverAuth.publicKey);
    let jwk = k.export({format:"jwk"});
    jwk.kid = String(Date.now());
    let payload = {"jwks":[
        jwk,
    ]}
    console.log(payload);
    res.status(200).send(JSON.stringify( payload ));    
})

app.post('/auth', (req, res, err) => {
    res.set('Content-Type', 'application/json');

    if (req.query.expired != undefined){
        return res.status(200).send(JSON.stringify({
            token: jwt.sign({
                data: 'Hello, World'
            }, expiredServerAuth.privateKey, {algorithm: 'RS256', expiresIn: '0'}),
        }));
    }

    return res.status(200).send(JSON.stringify({
        token: jwt.sign({
            data: 'Hello, World'
        }, serverAuth.privateKey, {algorithm:'RS256', expiresIn: '1h'}),
    }))

});

app.listen(port, ()=>{
    console.log(`Server listening on ${port}`);
});