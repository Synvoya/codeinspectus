const yaml = require("js-yaml");
exports.load = (text) => yaml.load(text);
exports.json = (text) => JSON.parse(text);
exports.core = (text) => yaml.load(text, { schema: yaml.CORE_SCHEMA });
