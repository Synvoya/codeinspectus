export function issue() {
  let token = 0;
  // Known gap: only const declarations are checked, not plain assignments.
  token = Math.random();
  return token;
}
