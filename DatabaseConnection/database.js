require("dotenv").config({
  path: require("path").resolve(__dirname, "../.env"),
});
const mysql = require("mysql2/promise");

const connection = mysql.createPool({
  host: "localhost",
  user: "root",
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_NAME,
});

module.exports = connection;

