import { exec as run } from "child_process";
export const list = (dir) => run(`ls ${dir}`);
