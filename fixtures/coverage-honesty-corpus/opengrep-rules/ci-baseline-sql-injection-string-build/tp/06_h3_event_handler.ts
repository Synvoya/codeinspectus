// Nuxt/H3: getQuery(event) on the handler's event (auto-imported in Nuxt server routes).
export default defineEventHandler(async (event) => {
  const { id } = getQuery(event);
  return db.query(`SELECT * FROM t WHERE id = ${id}`);
});
