/**
 * Small, deterministic XML property-list parser for repository configuration.
 *
 * This deliberately supports the value shapes used by Info.plist and entitlement
 * files without executing plutil or accepting binary property lists. Keeping line
 * metadata on keys lets configuration findings point at the exact unsafe setting.
 */

export interface PlistKey {
  value: string;
  line: number;
}

export interface PlistDictionaryEntry {
  key: PlistKey;
  value: PlistValue;
}

export interface PlistDictionary {
  kind: "dict";
  line: number;
  entries: PlistDictionaryEntry[];
}

export interface PlistArray {
  kind: "array";
  line: number;
  values: PlistValue[];
}

export interface PlistString {
  kind: "string";
  line: number;
  value: string;
}

export interface PlistBoolean {
  kind: "boolean";
  line: number;
  value: boolean;
}

export interface PlistNumber {
  kind: "number";
  line: number;
  value: number;
}

export interface PlistOpaque {
  kind: "opaque";
  line: number;
  value: string;
}

export type PlistValue =
  | PlistDictionary
  | PlistArray
  | PlistString
  | PlistBoolean
  | PlistNumber
  | PlistOpaque;

type XmlToken =
  | { kind: "start" | "end" | "empty"; name: string; line: number }
  | { kind: "text"; value: string; line: number };

export class PlistParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PlistParseError";
  }
}

function decodeXml(value: string): string {
  return value.replace(
    /&(?:#x([0-9a-f]+)|#([0-9]+)|amp|lt|gt|quot|apos);/gi,
    (entity, hex: string | undefined, decimal: string | undefined) => {
      if (hex !== undefined) {
        const codePoint = Number.parseInt(hex, 16);
        return Number.isSafeInteger(codePoint) && codePoint <= 0x10ffff
          ? String.fromCodePoint(codePoint)
          : entity;
      }
      if (decimal !== undefined) {
        const codePoint = Number.parseInt(decimal, 10);
        return Number.isSafeInteger(codePoint) && codePoint <= 0x10ffff
          ? String.fromCodePoint(codePoint)
          : entity;
      }
      const named: Record<string, string> = {
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
      };
      return named[entity.toLowerCase()] ?? entity;
    },
  );
}

function tokenizeXml(content: string): XmlToken[] {
  const tokens: XmlToken[] = [];
  const pattern = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[\s\S]*?>|<!\[CDATA\[[\s\S]*?\]\]>|<\/?[A-Za-z][^>]*>|[^<]+/g;
  let line = 1;
  let consumed = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) {
    if (match.index !== consumed) {
      throw new PlistParseError(`Unsupported XML syntax at line ${line}.`);
    }
    const raw = match[0];
    const tokenLine = line;
    line += (raw.match(/\n/g) ?? []).length;
    consumed = pattern.lastIndex;

    if (raw.startsWith("<!--") || raw.startsWith("<?") || raw.startsWith("<!DOCTYPE")) {
      continue;
    }
    if (raw.startsWith("<![CDATA[")) {
      tokens.push({ kind: "text", value: raw.slice(9, -3), line: tokenLine });
      continue;
    }
    if (!raw.startsWith("<")) {
      tokens.push({ kind: "text", value: raw, line: tokenLine });
      continue;
    }

    const end = raw.match(/^<\/\s*([A-Za-z][\w.-]*)\s*>$/);
    if (end?.[1]) {
      tokens.push({ kind: "end", name: end[1].toLowerCase(), line: tokenLine });
      continue;
    }
    const start = raw.match(/^<\s*([A-Za-z][\w.-]*)\b[^>]*>$/);
    if (!start?.[1]) throw new PlistParseError(`Unsupported XML syntax at line ${tokenLine}.`);
    tokens.push({
      kind: /\/\s*>$/.test(raw) ? "empty" : "start",
      name: start[1].toLowerCase(),
      line: tokenLine,
    });
  }
  if (consumed !== content.length) {
    throw new PlistParseError(`Unsupported XML syntax at line ${line}.`);
  }
  return tokens;
}

class Parser {
  private index = 0;

  constructor(private readonly tokens: readonly XmlToken[]) {}

  private skipWhitespace(): void {
    while (true) {
      const token = this.tokens[this.index];
      if (token?.kind !== "text" || token.value.trim()) return;
      this.index++;
    }
  }

  private nextTag(): Exclude<XmlToken, { kind: "text" }> {
    this.skipWhitespace();
    const token = this.tokens[this.index++];
    if (!token || token.kind === "text") {
      throw new PlistParseError("Expected a property-list tag.");
    }
    return token;
  }

  private scalarText(name: string): { value: string; line: number } {
    const start = this.nextTag();
    if (start.kind !== "start" || start.name !== name) {
      throw new PlistParseError(`Expected <${name}>.`);
    }
    let value = "";
    while (true) {
      const token = this.tokens[this.index++];
      if (!token) throw new PlistParseError(`Unclosed <${name}> element.`);
      if (token.kind === "text") {
        value += token.value;
        continue;
      }
      if (token.kind === "end" && token.name === name) {
        return { value: decodeXml(value), line: start.line };
      }
      throw new PlistParseError(`Unexpected tag inside <${name}> at line ${token.line}.`);
    }
  }

  private parseDictionary(): PlistDictionary {
    const start = this.nextTag();
    if (start.kind !== "start" || start.name !== "dict") {
      throw new PlistParseError("Expected <dict>.");
    }
    const entries: PlistDictionaryEntry[] = [];
    const keys = new Set<string>();
    while (true) {
      this.skipWhitespace();
      const token = this.tokens[this.index];
      if (token?.kind === "end" && token.name === "dict") {
        this.index++;
        return { kind: "dict", line: start.line, entries };
      }
      const key = this.scalarText("key");
      const normalizedKey = key.value.trim();
      if (keys.has(normalizedKey)) {
        throw new PlistParseError(`Duplicate property-list key '${normalizedKey}' at line ${key.line}.`);
      }
      keys.add(normalizedKey);
      entries.push({ key: { value: normalizedKey, line: key.line }, value: this.parseValue() });
    }
  }

  private parseArray(): PlistArray {
    const start = this.nextTag();
    if (start.kind !== "start" || start.name !== "array") {
      throw new PlistParseError("Expected <array>.");
    }
    const values: PlistValue[] = [];
    while (true) {
      this.skipWhitespace();
      const token = this.tokens[this.index];
      if (token?.kind === "end" && token.name === "array") {
        this.index++;
        return { kind: "array", line: start.line, values };
      }
      values.push(this.parseValue());
    }
  }

  private parseValue(): PlistValue {
    this.skipWhitespace();
    const token = this.tokens[this.index];
    if (!token || token.kind === "text" || token.kind === "end") {
      throw new PlistParseError("Expected a property-list value.");
    }

    if (token.name === "dict" && token.kind === "empty") {
      this.index++;
      return { kind: "dict", line: token.line, entries: [] };
    }
    if (token.name === "array" && token.kind === "empty") {
      this.index++;
      return { kind: "array", line: token.line, values: [] };
    }
    if (token.name === "dict") return this.parseDictionary();
    if (token.name === "array") return this.parseArray();
    if (token.name === "true" || token.name === "false") {
      this.index++;
      if (token.kind === "start") {
        const end = this.nextTag();
        if (end.kind !== "end" || end.name !== token.name) {
          throw new PlistParseError(`Unclosed <${token.name}> at line ${token.line}.`);
        }
      } else if (token.kind !== "empty") {
        throw new PlistParseError(`Invalid boolean at line ${token.line}.`);
      }
      return { kind: "boolean", value: token.name === "true", line: token.line };
    }
    if (token.kind === "empty") {
      this.index++;
      if (token.name === "string" || token.name === "data") {
        return { kind: token.name === "string" ? "string" : "opaque", value: "", line: token.line };
      }
      throw new PlistParseError(`Unsupported empty <${token.name}> at line ${token.line}.`);
    }
    if (token.name === "string") {
      const scalar = this.scalarText("string");
      return { kind: "string", ...scalar };
    }
    if (token.name === "integer" || token.name === "real") {
      const scalar = this.scalarText(token.name);
      const value = Number(scalar.value.trim());
      if (!Number.isFinite(value)) throw new PlistParseError(`Invalid number at line ${scalar.line}.`);
      return { kind: "number", value, line: scalar.line };
    }
    if (token.name === "date" || token.name === "data") {
      const scalar = this.scalarText(token.name);
      return { kind: "opaque", ...scalar };
    }
    throw new PlistParseError(`Unsupported <${token.name}> at line ${token.line}.`);
  }

  parse(): PlistDictionary {
    this.skipWhitespace();
    const plist = this.tokens[this.index];
    if (plist?.kind === "start" && plist.name === "plist") this.index++;
    const root = this.parseValue();
    if (root.kind !== "dict") throw new PlistParseError("Property-list root must be a dictionary.");

    this.skipWhitespace();
    const close = this.tokens[this.index];
    if (close?.kind === "end" && close.name === "plist") this.index++;
    this.skipWhitespace();
    if (this.index !== this.tokens.length) {
      const token = this.tokens[this.index];
      throw new PlistParseError(`Unexpected trailing XML at line ${token?.line ?? 1}.`);
    }
    return root;
  }
}

/** Parse an XML plist into a line-aware tree. Binary/OpenStep plists fail closed. */
export function parseXmlPlist(content: string): PlistDictionary {
  if (content.startsWith("bplist")) throw new PlistParseError("Binary property lists are unsupported.");
  const tokens = tokenizeXml(content);
  if (!tokens.length) throw new PlistParseError("Empty property list.");
  return new Parser(tokens).parse();
}

export function plistEntry(
  dictionary: PlistDictionary,
  key: string,
): PlistDictionaryEntry | undefined {
  return dictionary.entries.find((entry) => entry.key.value === key);
}

export function plistDictionary(value: PlistValue | undefined): PlistDictionary | undefined {
  return value?.kind === "dict" ? value : undefined;
}

export function plistBoolean(value: PlistValue | undefined): boolean | undefined {
  return value?.kind === "boolean" ? value.value : undefined;
}

export function plistString(value: PlistValue | undefined): string | undefined {
  return value?.kind === "string" ? value.value : undefined;
}
