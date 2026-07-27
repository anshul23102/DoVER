/**
 * Input validation and sanitization middleware
 * Prevents XSS, NoSQL injection, and other input-based attacks
 */

const { body, validationResult } = require('express-validator');

/**
 * Validation rules for document metadata.
 * All string fields are trimmed, length-limited, and HTML-escaped.
 * Tags are limited to an array of max 10 strings, each max 50 characters.
 *
 * Usage:
 *   router.post('/register', ...validateMetadata, async (req, res) => {
 *     const errors = validationResult(req);
 *     if (!errors.isEmpty()) {
 *       return res.status(400).json({ errors: errors.array() });
 *     }
 *     // metadata is now validated and safe
 *   });
 */
const validateMetadata = [
  body('metadata').optional().isObject(),
  body('metadata.title')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 200 })
    .escape()
    .withMessage('Title must be a string up to 200 characters'),
  body('metadata.description')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 1000 })
    .escape()
    .withMessage('Description must be a string up to 1000 characters'),
  body('metadata.author')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 100 })
    .escape()
    .withMessage('Author must be a string up to 100 characters'),
  body('metadata.tags')
    .optional()
    .isArray({ max: 10 })
    .withMessage('Tags must be an array with at most 10 items'),
  body('metadata.tags.*')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 50 })
    .escape()
    .withMessage('Each tag must be a string up to 50 characters'),
];

/**
 * Validation rules for document version notes.
 * Version notes are optional, trimmed, and length-limited.
 */
const validateVersionNote = [
  body('version_note')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 500 })
    .escape()
    .withMessage('Version note must be a string up to 500 characters'),
];

/**
 * Middleware to handle validation errors.
 * Returns 400 Bad Request if validation fails.
 *
 * Usage:
 *   router.post('/register', ...validateMetadata, handleValidationErrors, async (req, res) => {
 *     // Proceed with request; all validated inputs are sanitized
 *   });
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg,
        value: err.value
      }))
    });
  }
  next();
}

/**
 * Sanitizes a string by trimming and limiting length.
 * Use this for backend sanitization outside of route handlers.
 */
function sanitizeString(value, maxLength = 200) {
  if (!value || typeof value !== 'string') return '';
  return value.trim().substring(0, maxLength).replace(/[<>"'&]/g, (c) => {
    const htmlEscape = {
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '&': '&amp;'
    };
    return htmlEscape[c];
  });
}

module.exports = {
  validateMetadata,
  validateVersionNote,
  handleValidationErrors,
  sanitizeString
};
