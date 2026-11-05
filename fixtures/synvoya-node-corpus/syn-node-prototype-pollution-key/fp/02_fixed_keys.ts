const grid: number[][] = [[0, 0], [0, 0]];
export function mark(req: any, row: number, col: number) {
  grid[row][col] = 1;
  const flags: Record<string, Record<string, boolean>> = { a: {} };
  flags.a[req.query.flag] = true;
}
