const yaml = require("js-yaml");
exports.load = (text) => yaml.load(text, { schema: yaml.DEFAULT_FULL_SCHEMA });
exports.loadAll = (text) => yaml.loadAll(text, { schema: yaml.DEFAULT_FULL_SCHEMA });
