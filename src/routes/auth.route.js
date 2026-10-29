const express = require("express");
const {
  findUser,
  blackListToken,
  authMiddleware,
} = require("../middlewares/auth.middleware");

const {
  sendOTP,
  verifyOTP,
  createUser,
  loginUser,
} = require("../controller/auth.controller");

const {
  validateOTP,
  validateId,
  validatePassword,
} = require("../middlewares/validator.middleware");

const router = express.Router();

/**
 * @route   POST /send-otp
 * @desc    Generate and send an OTP code to user's email for registration verification
 * @access  Public
 * @middleware
 *   - validateId: Ensures the ID format in req.body is valid
 *   - findUser: Fetches user record from local data and checks against existing DB registrations
 *   - sendOTP: Generates OTP, hashes it in Redis with TTL, and fires verification email
 */
router.post("/send-otp", validateId, findUser, sendOTP);

/**
 * @route   POST /verify-otp
 * @desc    Validate incoming OTP against hashed Redis entry and issue temporary registration token
 * @access  Public
 * @middleware
 *   - validateId: Validates requested user ID structure
 *   - validateOTP: Ensures OTP payload is present and formatted properly
 *   - findUser: Checks user eligibility and email uniqueness
 *   - verifyOTP: Compares hashed OTP, sets temporary verification state in Redis, and sets auth cookie
 */
router.post("/verify-otp", validateId, validateOTP, findUser, verifyOTP);

/**
 * @route   POST /create-user
 * @desc    Complete account registration and persist user credentials to MongoDB
 * @access  Private (Requires valid registration token cookie)
 * @middleware
 *   - validatePassword: Ensures password meets complexity requirements
 *   - blackListToken: Validates active JWT cookie and revokes/blacklists token post-use
 *   - createUser: Hashes password, creates permanent document in DB, and clears temp auth state
 */
router.post("/create-user", validatePassword, blackListToken, createUser);

/**
 * @route   POST /login
 * @desc    Authenticate registered user, issue access/refresh JWTs, and initialize Redis session
 * @access  Public
 * @middleware
 *   - validateId: Validates ID input format
 *   - validatePassword: Checks if password payload exists
 *   - loginUser: Verifies password hash against DB, generates JWTs, and stores active session in Redis
 */
router.post("/login", validateId, validatePassword, loginUser);

module.exports = router;
