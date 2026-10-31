const { body, validationResult } = require("express-validator");

async function validateResult(req, res, next) {
  const error = validationResult(req);

  if (!error.isEmpty()) {
    return res.status(400).json({
      error: error.array(),
    });
  }

  next();
}

const validatePassword = [
  body("password")
    .isString()
    .withMessage("Password must be string")
    .isLength({ min: 8 })
    .withMessage("Password must contain 8 or more characters"),

  validateResult,
];

const validateId = [
  body("id")
    .isNumeric()
    .withMessage("ID must only contains digits")
    .isLength({ min: 10, max: 10 })
    .withMessage("ID contains only 10 characters"),

  validateResult,
];

const validateOTP = [
  body("otp")
    .isNumeric()
    .withMessage("OTP must only contains digits")
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP contains only 6 characters"),

  validateResult,
];

module.exports = { validateId, validateOTP, validatePassword };
