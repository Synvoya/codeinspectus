import { exec } from "child_process";
export const list = (dir) => exec("ls " + dir);
