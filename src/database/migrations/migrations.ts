import * as Knex from "knex";

export async function up(knex: any): Promise<void> {
  return knex.schema.createTableIfNotExists("users", (table: any) => {
    table.increments("id").primary();
    table.string("username").notNullable();
    table.string("password").notNullable();
    table.string("email").notNullable();
    table.string("phone");
    table.boolean("two_fa").defaultTo(false);
    table.string("otp_secret");
    table.string("auth_url");
    // Add any other columns as needed
  });
}

// to run the  migration file use ' npx knex migrate:latest '
