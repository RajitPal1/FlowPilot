const userModel = require("../models/user.model");
const sendEmail = require("../services/email.service");
const { getHTML, getOTP, getRemainingTime } = require("../utils/utils");
const bcrypt = require("bcryptjs");
const redis = require("../middlewares/redis.middleware");
const jwt = require("jsonwebtoken");
const config = require("../config/config");
const userData = require("../data/userData.json");
const crypto = require("crypto");

const COOLDOWN_SECONDS = 60;
const MAX_ATTEMPTS = 5;

async function sendOTP(req, res) {
  try {
    const user = req.user;

    const id = user.id;

    const isUserAlreadyRegistered = await userModel.findOne({
      id: id,
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

    await redis.set(`otp:${id}`, otpHash, "EX", 300);

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

    const invalidOtpKey = `invalidOtp:${id}`;

    const currentAttempts = await redis.get(invalidOtpKey);

    if (currentAttempts && parseInt(currentAttempts, 10) >= 3) {
      return res.status(429).json({
        message: "Too many failed OTP attempts. Please try again after 1 hour.",
      });
    }

    const storedOtp = await redis.get(`otp:${id}`);

    if (!storedOtp) {
      return res.status(400).json({
        message: "OTP not found or expired",
      });
    }

    const matchOtp = await bcrypt.compare(String(inputOtp), storedOtp);

    if (!matchOtp) {
      const attempts = await redis.incr(invalidOtpKey);

      if (attempts === 1) {
        await redis.expire(invalidOtpKey, 3600);
      }

      return res.status(400).json({
        message: `OTP is invalid. ${3 - attempts} attempt(s) remaining.`,
      });
    }

    const token = jwt.sign(
      {
        id: id,
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

    await redis.set(`verified:${id}`, true, "EX", 600);

    await redis.del(`otp:${id}`);
    await redis.del(invalidOtpKey);

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
    });

    if (isUserAlreadyExists) {
      return res.status(400).json({
        message: "User already exists",
      });
    }

    const isUserVerifiedInRedis = await redis.get(`verified:${decoded.id}`);

    if (!isUserVerifiedInRedis) {
      return res.status(400).json({
        message: "Verification session expired. Please resend OTP",
      });
    }

    const { password } = req.body;

    const user = userData.find((s) => s.id === decoded.id);

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

    const remainingTime = getRemainingTime(decoded.exp);

    if (remainingTime > 0) {
      await redis.set(`bl:${token}`, true, "EX", remainingTime);
    }

    res.clearCookie("token");

    await redis.del(`verified:${decoded.id}`);

    return res.status(201).json({
      message: "User created successfully",
    });
  } catch (err) {
    res.status(500).json({
      message: "Failed to create user",
      error: err.message,
    });
  }
}

async function loginUser(req, res) {
  try {
    const { id, password } = req.body;

    const user = await userModel.findOne({ id: id });

    if (!user) {
      return res.status(401).json({
        message: "Unauthorized User",
      });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res.status(400).json({
        message: "Password is incorrect",
      });
    }

    const sessionId = crypto.randomUUID();

    const accessToken = jwt.sign(
      {
        id: user.id,
        role: user.role,
        sessionId,
      },
      config.JWT_SECRET,
      {
        expiresIn: "15m",
      },
    );

    const refreshToken = jwt.sign(
      {
        id: user.id,
        role: user.role,
        sessionId,
      },
      config.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    const sessionKey = `session:${user.id}:${sessionId}`;
    const userSessionsKey = `user:sessions:${user.id}`;

    await redis.set(
      sessionKey,
      JSON.stringify({
        userAgent: req.headers["user-agent"],
        ip: req.ip,
        createdAt: Date.now().toString(),
      }),
      "EX",
      60 * 60 * 24 * 7,
    );

    await redis.sadd(userSessionsKey, sessionKey);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    res.status(200).json({
      message: "User logged in successfully",
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
      accessToken,
    });
  } catch (err) {
    res.status(500).json({
      message: "Internet server error during login",
      error: err.message,
    });
  }
}

async function logOutUser(req, res) {
  try {
    const decoded = req.decoded;

    await redis.del(`session:${decoded.id}:${decoded.sessionId}`);

    const accessToken = req.accessToken;

    const remainingTime = getRemainingTime(decoded.exp);

    if (remainingTime > 0) {
      await redis.set(`bl:${accessToken}`, true, "EX", remainingTime);
    }

    res.clearCookie("refreshToken");

    res.status(200).json({
      message: "User logged out successfully",
    });
  } catch (err) {
    res.status(500).json({
      message: "Something went wrong",
      error: err.message,
    });
  }
}

async function getMe(req, res) {
  try {
    const decoded = req.decoded;

    const user = await userModel.findOne({
      id: decoded.id,
    });

    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }

    res.status(200).json({
      message: "User found successfully",
      user: {
        username: user.username,
        id: user.id,
        role: user.role,
      },
    });
  } catch (err) {
    return res.status(500).json({
      message: "Can't get user",
      error: err.message,
    });
  }
}

async function logOutUserFromAll(req, res) {
  try {
    const decoded = req.decoded;

    const userSessionsKey = `user:sessions:${decoded.id}`;

    const sessionsKey = await redis.smembers(userSessionsKey);

    if (sessionsKey.length > 1) {
      await redis.del(...sessionsKey);
    }

    await redis.del(userSessionsKey);

    const accessToken = req.accessToken;
    const remainingTime = getRemainingTime(decoded.exp);

    if (remainingTime > 0) {
      await redis.set(`bl:${accessToken}`, "true", "EX", remainingTime);
    }

    res.clearCookie("refreshToken");

    res.status(200).json({
      message: "User logged out successfully from all devices",
    });
  } catch (err) {
    res.status(500).json({
      message: "Something went wrong",
      error: err.message,
    });
  }
}

async function tokenRecreate(req, res) {
  try {
    const decoded = req.decoded;

    const accessToken = jwt.sign(
      {
        id: decoded.id,
        role: decoded.role,
        sessionId: decoded.sessionId,
      },
      config.JWT_SECRET,
      {
        expiresIn: "15m",
      },
    );

    const refreshToken = jwt.sign(
      {
        id: decoded.id,
        role: decoded.role,
        sessionId: decoded.sessionId,
      },
      config.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    res.cookie("refreshtoken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    res.status(200).json({
      message: "Token recreate successfully",
      accessToken,
    });
  } catch (err) {
    res.status(500).json({
      message: "Something went wrong",
      error: err.message,
    });
  }
}


module.exports = {
  sendOTP,
  verifyOTP,
  createUser,
  loginUser,
  logOutUser,
  getMe,
  logOutUserFromAll,
  tokenRecreate
};
