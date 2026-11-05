// A function that merely shares an H3 name, outside an H3 handler and without the h3 import.
function getQuery(store: Map<string, string>): string { return store.get("q") ?? ""; }
export const run = (db: any, store: Map<string, string>) => db.query("SELECT * FROM t WHERE q = '" + getQuery(store) + "'");
