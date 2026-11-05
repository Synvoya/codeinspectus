import { unserialize } from "node-serialize";
export const load = (text) => unserialize(text);
