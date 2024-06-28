import dotenv from "dotenv";
dotenv.config();
const { DB_HOST, DB_PASSWORD, DB_NAME, DB_USERNAME, DB_PORT } = process.env;
export const knex = require("knex")({
  client: "mysql",
  connection: {
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USERNAME,
    password: DB_PASSWORD,
    database: DB_NAME,
  },
});
knex
  .raw("SELECT 1+1 AS result")
  .then(() => {
    console.log("Database connected successfully");
  })
  .catch((err: any) => {
    console.error("Database connection failed", err);
  });
