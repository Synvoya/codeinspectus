import { access, lstat, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";

export type ScanTargetType = "file" | "directory";

export interface TargetPathInspection {
  input: string;
  resolved_path: string;
  canonical_path?: string;
  exists: boolean;
  supported: boolean;
  type?: ScanTargetType;
  symlink_safe: boolean;
  /** The canonical file/directory itself is the root boundary handed to every scanner. */
  containment?: "canonical_target_root";
  /** Enclosing Git worktree root when one can be identified without invoking Git. */
  repository_root?: string;
  filesystem_identity?: { device: string; inode: string };
  error?: string;
}

export interface OutputPathInspection {
  mode: "stdout" | "directory" | "file";
  input?: string;
  resolved_path?: string;
  canonical_path?: string;
  exists: boolean;
  writable: boolean;
  symlink_safe: boolean;
  inside_target: boolean;
  approved_inside_target: boolean;
  safe: boolean;
  error?: string;
}

/** Inspect an exact output file without following symlinks or creating parents. */
export async function inspectOutputFile(
  input: string,
  canonicalTarget: string | undefined,
  approveInsideTarget: boolean,
): Promise<OutputPathInspection> {
  const resolvedPath = resolve(input);
  const insideTarget = canonicalTarget ? pathIsWithin(canonicalTarget, resolvedPath) : false;
  const base = {
    mode: "file" as const,
    input,
    resolved_path: resolvedPath,
    inside_target: insideTarget,
    approved_inside_target: approveInsideTarget,
  };
  if (containsTraversalSegment(input)) {
    return { ...base, exists: false, writable: false, symlink_safe: false, safe: false,
      error: "Output file must not contain '..' traversal segments; pass a canonical path." };
  }
  const segments = await inspectSegments(resolvedPath);
  if (!segments.safe) {
    return { ...base, exists: false, writable: false, symlink_safe: false, safe: false, error: segments.error };
  }
  const parent = dirname(resolvedPath);
  let parentMetadata;
  try {
    parentMetadata = await lstat(parent);
  } catch {
    return { ...base, exists: false, writable: false, symlink_safe: true, safe: false,
      error: `Output file parent directory does not exist: ${parent}` };
  }
  if (!parentMetadata.isDirectory()) {
    return { ...base, exists: false, writable: false, symlink_safe: true, safe: false,
      error: `Output file parent is not a directory: ${parent}` };
  }
  let exists = false;
  try {
    const metadata = await lstat(resolvedPath);
    exists = true;
    if (!metadata.isFile()) {
      return { ...base, exists, writable: false, symlink_safe: !metadata.isSymbolicLink(), safe: false,
        error: `Output path is not a regular file: ${resolvedPath}` };
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      return { ...base, exists: false, writable: false, symlink_safe: true, safe: false,
        error: `Could not inspect output file: ${resolvedPath}` };
    }
  }
  let writable = true;
  try {
    await access(exists ? resolvedPath : parent, constants.W_OK);
  } catch {
    writable = false;
  }
  const approved = !insideTarget || approveInsideTarget;
  const safe = writable && approved;
  return {
    ...base,
    canonical_path: resolvedPath,
    exists,
    writable,
    symlink_safe: true,
    safe,
    ...(!writable ? { error: `Output file is not writable: ${exists ? resolvedPath : parent}` }
      : !approved ? { error: "Output file is inside the scan target. Pass --allow-output-in-target to explicitly approve this repository write." }
        : {}),
  };
}

/** True only for an actual path segment named `..`; names merely containing dots are safe. */
export function containsTraversalSegment(path: string): boolean {
  return path.split(/[\\/]+/).some((segment) => segment === "..");
}

export function pathIsWithin(parent: string, candidate: string): boolean {
  const rel = relative(parent, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

/** A direct-file scan still belongs to its containing repository/directory for write safety. */
export function outputContainmentRoot(target: TargetPathInspection): string | undefined {
  if (!target.canonical_path || !target.type) return undefined;
  return target.repository_root ?? (target.type === "file" ? dirname(target.canonical_path) : target.canonical_path);
}

async function findRepositoryRoot(targetPath: string, type: ScanTargetType): Promise<string | undefined> {
  let current = type === "file" ? dirname(targetPath) : targetPath;
  const root = parse(current).root;
  while (true) {
    try {
      const marker = await lstat(resolve(current, ".git"));
      if (marker.isDirectory() || marker.isFile()) return current;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return undefined;
    }
    if (current === root) return undefined;
    current = dirname(current);
  }
}

async function inspectSegments(absolutePath: string): Promise<{
  safe: boolean;
  existing_path: string;
  error?: string;
}> {
  const root = parse(absolutePath).root;
  const remainder = absolutePath.slice(root.length);
  const parts = remainder.split(sep).filter(Boolean);
  let current = root;
  let existing = root;

  for (const part of parts) {
    current = resolve(current, part);
    let metadata;
    try {
      metadata = await lstat(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { safe: true, existing_path: existing };
      }
      return {
        safe: false,
        existing_path: existing,
        error: `Could not inspect path component '${current}'.`,
      };
    }
    if (metadata.isSymbolicLink()) {
      return {
        safe: false,
        existing_path: existing,
        error: `Symbolic-link path component is not allowed: ${current}`,
      };
    }
    existing = current;
  }
  return { safe: true, existing_path: existing };
}

export async function inspectTargetPath(input: string): Promise<TargetPathInspection> {
  const resolvedPath = resolve(input);
  let metadata;
  try {
    metadata = await lstat(resolvedPath);
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return {
      input,
      resolved_path: resolvedPath,
      exists: false,
      supported: false,
      symlink_safe: true,
      error: missing ? `Path not found: ${resolvedPath}` : `Could not inspect target: ${resolvedPath}`,
    };
  }

  if (metadata.isSymbolicLink()) {
    return {
      input,
      resolved_path: resolvedPath,
      exists: true,
      supported: false,
      symlink_safe: false,
      error: `Symbolic-link scan targets are not allowed: ${resolvedPath}`,
    };
  }

  const type = metadata.isDirectory() ? "directory" : metadata.isFile() ? "file" : undefined;
  if (!type) {
    return {
      input,
      resolved_path: resolvedPath,
      exists: true,
      supported: false,
      symlink_safe: true,
      error: `Unsupported target type at ${resolvedPath}; expected a regular file or directory.`,
    };
  }

  let canonicalPath: string;
  try {
    canonicalPath = await realpath(resolvedPath);
  } catch {
    return {
      input,
      resolved_path: resolvedPath,
      exists: true,
      supported: false,
      type,
      symlink_safe: false,
      error: `Target could not be resolved to a stable canonical path: ${resolvedPath}`,
    };
  }

  // Ancestor links such as macOS /var -> /private/var are safe once collapsed: every engine
  // receives only canonicalPath. The leaf itself remains forbidden above so a user cannot point
  // the scanner at a replaceable link. Re-inspect the canonical leaf to catch concurrent swaps.
  const canonicalSegments = await inspectSegments(canonicalPath);
  let canonicalMetadata;
  try {
    canonicalMetadata = await lstat(canonicalPath);
  } catch {
    canonicalMetadata = undefined;
  }
  if (
    !canonicalSegments.safe ||
    !canonicalMetadata ||
    canonicalMetadata.isSymbolicLink() ||
    canonicalMetadata.dev !== metadata.dev ||
    canonicalMetadata.ino !== metadata.ino
  ) {
    return {
      input,
      resolved_path: resolvedPath,
      canonical_path: canonicalPath,
      exists: true,
      supported: false,
      type,
      symlink_safe: false,
      error: `Target identity changed or remained symbolic while canonicalizing: ${resolvedPath}`,
    };
  }

  const repositoryRoot = await findRepositoryRoot(canonicalPath, type);
  return {
    input,
    resolved_path: resolvedPath,
    canonical_path: canonicalPath,
    exists: true,
    supported: true,
    type,
    symlink_safe: true,
    containment: "canonical_target_root",
    ...(repositoryRoot ? { repository_root: repositoryRoot } : {}),
    filesystem_identity: {
      device: String(canonicalMetadata.dev),
      inode: String(canonicalMetadata.ino),
    },
  };
}

export async function requireSafeScanTarget(input: string): Promise<TargetPathInspection & {
  canonical_path: string;
  type: ScanTargetType;
}> {
  const inspection = await inspectTargetPath(input);
  if (!inspection.exists || !inspection.supported || !inspection.symlink_safe || !inspection.canonical_path || !inspection.type) {
    throw new Error(inspection.error ?? `Unsafe or unsupported scan target: ${inspection.resolved_path}`);
  }
  return inspection as TargetPathInspection & { canonical_path: string; type: ScanTargetType };
}

export async function inspectOutputDirectory(
  input: string | undefined,
  canonicalTarget: string | undefined,
  approveInsideTarget: boolean,
): Promise<OutputPathInspection> {
  if (!input) {
    return {
      mode: "stdout",
      exists: true,
      writable: true,
      symlink_safe: true,
      inside_target: false,
      approved_inside_target: false,
      safe: true,
    };
  }

  const resolvedPath = resolve(input);
  if (containsTraversalSegment(input)) {
    return {
      mode: "directory",
      input,
      resolved_path: resolvedPath,
      exists: false,
      writable: false,
      symlink_safe: false,
      inside_target: false,
      approved_inside_target: approveInsideTarget,
      safe: false,
      error: "Output directory must not contain '..' traversal segments; pass a canonical path.",
    };
  }

  const segments = await inspectSegments(resolvedPath);
  if (!segments.safe) {
    return {
      mode: "directory",
      input,
      resolved_path: resolvedPath,
      exists: false,
      writable: false,
      symlink_safe: false,
      inside_target: canonicalTarget ? pathIsWithin(canonicalTarget, resolvedPath) : false,
      approved_inside_target: approveInsideTarget,
      safe: false,
      error: segments.error,
    };
  }

  let exists = false;
  let isDirectory = false;
  try {
    const metadata = await lstat(resolvedPath);
    exists = true;
    isDirectory = metadata.isDirectory();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      return {
        mode: "directory",
        input,
        resolved_path: resolvedPath,
        exists: false,
        writable: false,
        symlink_safe: true,
        inside_target: canonicalTarget ? pathIsWithin(canonicalTarget, resolvedPath) : false,
        approved_inside_target: approveInsideTarget,
        safe: false,
        error: `Could not inspect output directory: ${resolvedPath}`,
      };
    }
  }

  if (exists && !isDirectory) {
    return {
      mode: "directory",
      input,
      resolved_path: resolvedPath,
      exists,
      writable: false,
      symlink_safe: true,
      inside_target: canonicalTarget ? pathIsWithin(canonicalTarget, resolvedPath) : false,
      approved_inside_target: approveInsideTarget,
      safe: false,
      error: `Output path is not a directory: ${resolvedPath}`,
    };
  }

  let writable = true;
  try {
    await access(exists ? resolvedPath : segments.existing_path, constants.W_OK);
  } catch {
    writable = false;
  }
  const canonicalPath = exists ? await realpath(resolvedPath) : resolvedPath;
  const insideTarget = canonicalTarget ? pathIsWithin(canonicalTarget, canonicalPath) : false;
  const approved = !insideTarget || approveInsideTarget;
  const safe = writable && approved;
  const error = !writable
    ? `Output directory is not writable: ${exists ? resolvedPath : segments.existing_path}`
    : !approved
      ? "Output directory is inside the scan target. Pass --allow-output-in-target to explicitly approve this repository write."
      : undefined;

  return {
    mode: "directory",
    input,
    resolved_path: resolvedPath,
    canonical_path: canonicalPath,
    exists,
    writable,
    symlink_safe: true,
    inside_target: insideTarget,
    approved_inside_target: approveInsideTarget,
    safe,
    ...(error ? { error } : {}),
  };
}
