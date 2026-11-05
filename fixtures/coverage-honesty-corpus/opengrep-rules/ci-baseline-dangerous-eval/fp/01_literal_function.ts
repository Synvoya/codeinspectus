// A Function built only from string literals runs author-written code (an ESM import shim).
export const dynamicImport = new Function("s", "return import(s)") as (s: string) => Promise<unknown>;
