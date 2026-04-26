/* tslint:disable */
/* eslint-disable */

/**
 * Decrypt an armored PGP MESSAGE using the TSK.
 */
export function decrypt_message(tsk_armored: string, ciphertext_armored: string): string;

/**
 * Encrypt `message` to the recipient's public cert.
 * Returns an armored PGP MESSAGE block.
 */
export function encrypt_to_cert(cert_armored: string, message: string): string;

/**
 * Extract the public certificate from a TSK. Returns ASCII-armored public cert.
 */
export function extract_public_cert(tsk_armored: string): string;

/**
 * Generate a PQC certificate (SLH-DSA-256s + ML-KEM-1024+X448).
 * Returns the ASCII-armored secret key (Transferable Secret Key).
 */
export function generate_pqc_key(user_id: string): string;

export function init(): void;

/**
 * Walk a cert or TSK and produce a JSON structural dump.
 * Keeps JSON hand-formatted so we don't pull in serde_json.
 */
export function inspect_cert(input_armored: string): string;

/**
 * Produce an ASCII-armored detached signature over `message` using the TSK.
 */
export function sign_detached(tsk_armored: string, message: string): string;

/**
 * Verify a detached signature against a message and public cert.
 */
export function verify_detached(cert_armored: string, message: string, signature_armored: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly decrypt_message: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encrypt_to_cert: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly extract_public_cert: (a: number, b: number) => [number, number, number, number];
    readonly generate_pqc_key: (a: number, b: number) => [number, number, number, number];
    readonly init: () => void;
    readonly inspect_cert: (a: number, b: number) => [number, number, number, number];
    readonly sign_detached: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly verify_detached: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
