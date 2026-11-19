// Package verify exposes the public OpenPassport v1.0 cryptographic verifier
// (Contract C1) for external Go consumers such as Velo Framework and mvlab.
//
// Verify validates the manifest self-hash seal, rejects path-traversal attempts
// via SafeJoin, enforces pure LF on text files, and verifies raw-byte SHA-256
// digests concurrently across a bounded worker pool.
package verify
