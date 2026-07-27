/**
 * Hash algorithm constants and validation utilities
 *
 * SECURITY: Hash algorithm is hardcoded server-side to SHA-256 and NOT user-controllable.
 * This prevents algorithm confusion attacks where an attacker supplies a weak algorithm
 * (MD5, SHA1) to match a forged document.
 */

// The ONLY supported hash algorithm for document integrity verification
const HASH_ALGORITHM = 'sha256';

// SHA-256 produces a 64-character hexadecimal string
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/i;

/**
 * Validates that a string is a valid SHA-256 hash (64 hex characters).
 * Rejects anything that could be MD5 (32 hex chars), SHA1 (40 hex chars), etc.
 *
 * @param {string} hash - The hash string to validate
 * @returns {boolean} True if valid SHA-256 hex string, false otherwise
 */
function isValidSha256Hash(hash) {
    if (!hash || typeof hash !== 'string') return false;
    return SHA256_HEX_PATTERN.test(hash);
}

/**
 * Express middleware to validate hash format in route parameters or body.
 * Rejects hashes that don't match SHA-256 format.
 *
 * Usage:
 *   router.get('/:hash', validateHashFormat, (req, res) => { ... });
 *   router.post('/', validateHashFormat, (req, res) => { ... });
 *
 * Will check req.params.hash and req.body.hash
 */
function validateHashFormat(req, res, next) {
    const hash = req.params.hash || req.body.hash;

    if (!hash) {
        return res.status(400).json({
            success: false,
            error: 'Missing hash parameter',
            expected_format: 'SHA-256 (64 hexadecimal characters)'
        });
    }

    if (!isValidSha256Hash(hash)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid hash format',
            details: `Hashes must be exactly 64 hexadecimal characters (SHA-256). Received: ${hash.length} characters.`,
            algorithm: HASH_ALGORITHM
        });
    }

    next();
}

/**
 * Middleware to reject any user-supplied algorithm parameter.
 * If an attacker tries to override the algorithm via request body/query,
 * this middleware blocks it explicitly.
 *
 * Usage:
 *   router.post('/', rejectAlgorithmParameter, (req, res) => { ... });
 */
function rejectAlgorithmParameter(req, res, next) {
    if (req.body?.algorithm || req.query?.algorithm) {
        return res.status(400).json({
            success: false,
            error: 'Algorithm parameter is not accepted',
            details: 'Hash algorithm is hardcoded to SHA-256 server-side and cannot be overridden.',
            algorithm: HASH_ALGORITHM
        });
    }
    next();
}

module.exports = {
    HASH_ALGORITHM,
    SHA256_HEX_PATTERN,
    isValidSha256Hash,
    validateHashFormat,
    rejectAlgorithmParameter
};
