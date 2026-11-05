export function deepEqual(a: any, b: any): boolean {
  for (const key in a) {
    if (!deepEqual(a[key], b[key])) return false;
  }
  return true;
}
