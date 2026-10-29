const userData = require("../data/userData.json");
const userModel = require("../models/user.model");
const redis = require("./redis.middleware");
const jwt = require("jsonwebtoken");
const config = require("../config/config");

async function findUser(req, res, next) {
  try {
    const { id } = req.body;

    const user = userData.find((s) => s.id === id);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const isUserAlreadyExistsWithEmail = userData.filter(
      (s) => s.email === user.email,
    );

    if (isUserAlreadyExistsWithEmail.length > 1) {
      return res.status(404).json({
        message: "Multiple records exists with registered email",
      });
    }

    const isEmailRegistered = await userModel.findOne({ email: user.email });
    if (isEmailRegistered) {
      return res.status(400).json({
        message: "User already exists with registered email",
      });
    }

    req.user = user;

    return next();
  } catch (err) {
    res.status(500).json({
      message: "Something went wrong",
      error: err.message,
    });
  }
}

async function refreshTokenMiddleware(req, res, next) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Unauthorized",
    });
  }

  try {
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const sessionExists = await redis.get(
      `session:${decoded.id}:${decoded.sessionId}`,
    );

    if (!sessionExists) {
      return res.status(401).json({
        message: "Session expired or logged Out",
      });
    }

    req.decoded = decoded;
    req.session = sessionExists;
    req.refreshToken = refreshToken;

    next();
  } catch (err) {
    return res.status(500).json({
      message: "Unauthorized or invalid token",
      error: err.message,
    });
  }
}

async function accessTokenMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  const accessToken = authHeader?.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : null;

  if (!accessToken) {
    return res.status(401).json({
      message: "Unauthorized",
    });
  }

  try {

    const isBlacklisted = await redis.get(`bl:${accessToken}`);
    if (isBlacklisted) {
      return res.status(401).json({ message: "Token has been revoked" });
    }

    const decoded = jwt.verify(accessToken, config.JWT_SECRET);

    const sessionExists = await redis.get(
      `session:${decoded.id}:${decoded.sessionId}`,
    );

    if (!sessionExists) {
      return res.status(401).json({
        message: "Session expired or logged out",
      });
    }

    req.decoded = decoded;
    req.accessToken = accessToken;
    req.session = sessionExists;

    next();
  } catch (err) {
    res.status(401).json({
      message: "Unauthorized",
      error: err.message,
    });
  }
}

module.exports = { findUser, refreshTokenMiddleware, accessTokenMiddleware};
