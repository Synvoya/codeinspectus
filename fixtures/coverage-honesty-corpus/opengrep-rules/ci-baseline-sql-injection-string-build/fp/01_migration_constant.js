// A migration that interpolates a constant, as in the field: no request input reaches the query.
exports.up = async (knex) => {
  const ifNotExists = knex.client.config.client === "pg" ? "IF NOT EXISTS" : "";
  await knex.raw(`CREATE INDEX ${ifNotExists} links_user_id_index ON links (user_id);`);
};
