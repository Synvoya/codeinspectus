import { execSync } from "node:child_process";
export const size = (dir: string) => execSync(`du -sh ${dir}`);
