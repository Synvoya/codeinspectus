/**
 * Human-readable output interpolates repository-controlled text (file names, metadata fields,
 * validator messages). Render C0/C1 control characters (except tab, newline, and the CR of a CRLF
 * pair) as visible `\uXXXX` escapes so that text can never drive a terminal (cursor moves, OSC-8
 * links, screen clears). `\uXXXX` is also a valid JSON escape, so JSON viewed on a terminal stays
 * valid JSON with the same data.
 */
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]|\r(?!\n)/g;

export function terminalSafe(text: string): string {
  return text.replace(CONTROL_CHARACTERS, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/**
 * CLI output. Escape unconditionally: output piped through `tee` or `less -R` still reaches a
 * terminal. `\uXXXX` escapes keep JSON/SARIF valid with identical parsed data; `--output <file>`
 * writes exact bytes.
 */
export function forStream(text: string): string {
  return terminalSafe(text);
}

/**
 * A single-line field inside human-readable output (a file name, a note, a warning). Line breaks
 * (CR, LF, NEL, U+2028/U+2029) and bidirectional controls are rendered as `\uXXXX`, so a crafted
 * file name can neither start a fake output line nor visually reorder the text around it.
 */
const INLINE_BREAKING = /[\n\r\u0085\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

export function inlineField(text: string): string {
  return text.replace(INLINE_BREAKING, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
