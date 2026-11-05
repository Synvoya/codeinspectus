import { execSync } from "child_process";
export function version() {
  const cmd = "git rev-parse HEAD";
  return execSync(cmd).toString();
}
