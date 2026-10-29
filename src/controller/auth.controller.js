const userModel = require("../models/user.model");
const sendEmail = require("../services/email.service");
const { getHTML, getOTP } = require("../utils/utils");
const bcrypt = require("bcryptjs");
const redis = require("../middlewares/redis.middleware");
const jwt = require("jsonwebtoken");
const config = require("../config/config");
const userData = require("../data/userData.json");

const COOLDOWN_SECONDS = 60;
const MAX_ATTEMPTS = 5;

async function sendOTP(req, res) {
  try {
    const user = req.user;

    const id = user.id;

    const isUserAlreadyRegistered = await userModel.findOne({
      id: id,
      role: user.role,
    });

    if (isUserAlreadyRegistered) {
      return res.status(404).json({
        message: "User already registered. Please login.",
      });
    }

    const cooldownKey = `otp:cooldown:${id}`;
    const ratelimitKey = `otp:ratelimit:${id}`;

    const isCooldownActive = await redis.get(cooldownKey);

    if (isCooldownActive) {
      const ttl = await redis.ttl(cooldownKey);
      return res.status(429).json({
        message: `Please wait ${ttl} seconds before sending another OTP`,
        retryAfter: ttl,
      });
    }

    const hourlyCount = await redis.get(ratelimitKey);

    if (hourlyCount && parseInt(hourlyCount, 10) >= MAX_ATTEMPTS) {
      return res.status(429).json({
        message: "Too many OTP request try again in an hour",
      });
    }

    const otp = getOTP();
    const html = getHTML(otp);

    const otpHash = await bcrypt.hash(String(otp), 10);

    await redis.set(`otp:${id}:${user.role}`, otpHash, "EX", 300);

    await sendEmail(
      user.email,
      "OTP Verification",
      `Your verification code is ${otp}`,
      html,
    );

    await redis.set(cooldownKey, "true", "EX", COOLDOWN_SECONDS);

    const currentRequest = await redis.incr(ratelimitKey);

    if (currentRequest === 1) {
      await redis.expire(ratelimitKey, 3600);
    }

    res.status(200).json({
      message: "OTP has been sent to the registered email",
      cooldown: COOLDOWN_SECONDS,
    });
  } catch (err) {
    res.status(500).json({
      message: "Failed to send OTP",
      error: err.message,
    });
  }
}

async function verifyOTP(req, res) {
  try {
    const user = req.user;

    const id = user.id;

    const { inputOtp } = req.body;

    const storedOtp = await redis.get(`otp:${id}:${user.role}`);

    if (!storedOtp) {
      return res.status(400).json({
        message: "OTP not found or expired",
      });
    }

    const matchOtp = await bcrypt.compare(String(inputOtp), storedOtp);

    if (!matchOtp) {
      return res.status(400).json({
        message: "OTP invalid",
      });
    }

    const token = jwt.sign(
      {
        id: id,
        role: user.role,
      },
      config.JWT_SECRET,
      {
        expiresIn: "10m",
      },
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 1000 * 60 * 10,
    });
    
    await redis.set(`verified:${id}:${user.role}`, true, "EX", 600);

    await redis.del(`otp:${id}:${user.role}`);

    res.status(200).json({
      message: "OTP verified successfully",
    });
  } catch (err) {
    res.status(500).json({
      message: "Something went wrong",
      error: err.message,
    });
  }
}

async function createUser(req, res) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({
      message: "Unauthorized",
    });
  }

  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);

    const isUserAlreadyExists = await userModel.findOne({
      id: decoded.id,
      role: decoded.role,
    });

    if (isUserAlreadyExists) {
      return res.status(400).json({
        message: "User already exists",
      });
    }

    const isUserVerifiedInRedis = await redis.get(
      `verified:${decoded.id}:${decoded.role}`,
    );

    if (!isUserVerifiedInRedis) {
      return res.status(400).json({
        message: "Verification session expired. Please resend OTP",
      });
    }

    const { password } = req.body;

    const user = userData.find(
      (s) => s.id === decoded.id && s.role === decoded.role,
    );

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await userModel.create({
      username: user.username,
      id: user.id,
      role: user.role,
      email: user.email,
      password: passwordHash,
    });

    res.clearCookie("token");

    redis.del(`verified:${decoded.id}:${decoded.role}`,)

    return res.status(201).json({
      message: "User created successfully",
    });
  } catch (err) {
    res.status(404).json({
      message: "Unauthorized",
      error: err.message,
    });
  }
}

module.exports = { sendOTP, verifyOTP, createUser };
