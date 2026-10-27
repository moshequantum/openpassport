/**
 * Normalizes string line endings to canonical Unix LF (\n) with a trailing newline.
 */
export function toLF(str: string): string {
  return str.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim() + "\n";
}

/**
 * Checks if a string or buffer contains Carriage Return (CR / 0x0D), indicating CRLF corruption.
 */
export function hasCRLF(content: Buffer | string): boolean {
  if (Buffer.isBuffer(content)) {
    return content.includes(0x0d);
  }
  return content.includes("\r");
}

/**
 * Heuristic to detect if a file is binary (e.g. PNG, PDF, ZIP) vs text.
 */
export function isBinaryBuffer(buf: Buffer): boolean {
  // Check for common binary magic bytes or null bytes in the first 8000 bytes
  const limit = Math.min(buf.length, 8000);
  for (let i = 0; i < limit; i++) {
    if (buf[i] === 0x00) {
      return true;
    }
  }
  return false;
}

export const CANONICAL_GITATTRIBUTES = `* text=auto eol=lf
*.md text eol=lf
*.json text eol=lf
`;
