/**
 * provenance-protocol/check — compare a declaration with its project, locally.
 * Node-only. Makes no network connections.
 */

export interface CheckFinding {
  key: string;
  field: 'version' | 'model.provider' | 'model.model_id' | 'dependencies' | 'capabilities';
  change: 'added' | 'modified';
  value: unknown;
  from?: unknown;
  reason: string;
}

export interface PromiseConflict {
  key: string;
  promise: string;
  capability: string;
  reason: string;
}

export interface CheckResult {
  inSync: boolean;
  /** Facts the project states outright — safe to apply automatically. */
  certain: CheckFinding[];
  /** Inferences — for a person to confirm. */
  likely: CheckFinding[];
  /** Code that clashes with a promise — never resolved automatically. */
  conflicts: PromiseConflict[];
  ignored: number;
}

export const IGNORE_FILE: '.provenance-ignore';
export function readIgnore(dir: string): Set<string>;
export function checkProject(dir: string, declaration: object, options?: { ignore?: Iterable<string> }): CheckResult;
/** Apply findings; returns an unsigned copy to sign. */
export function applyFindings(declaration: object, findings: CheckFinding[]): object;
