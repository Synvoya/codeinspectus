import { unserialize as revive } from "node-serialize";
export const load = (text) => revive(text);
