# JSON Web Tokens Keyset Server

This project is written and Typescript, and thus requires the Typescript Compiler `tsc`.

This project uses the Sequelize ORM to interface with a sqlite database, and has the following dependencies.

```json
"dependencies": {
    "argon2": "^0.40.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "sequelize": "^6.37.2",
    "sqlite3": "^5.1.7",
    "uuid": "^9.0.1"
}
```

To run this project, first install `tsc`, then run `npm install` to install the dependencies.
Run tsc to compile the `index.ts` file, or just run `node .` to run the existsing `index.js`.


