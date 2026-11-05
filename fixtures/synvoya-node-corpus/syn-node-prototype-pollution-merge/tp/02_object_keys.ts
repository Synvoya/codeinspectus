export function assignDeep(dest: any, src: any): any {
  Object.keys(src).forEach((k) => {
    if (typeof src[k] === "object") {
      dest[k] = dest[k] || {};
      assignDeep(dest[k], src[k]);
    } else {
      dest[k] = src[k];
    }
  });
  return dest;
}
