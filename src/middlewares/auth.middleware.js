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

async function blackListToken(req,res,next){

  const isTokenBlackListed = await redis.get(`bl:${token}`);

  if(isTokenBlackListed){
    return res.status(401).json({
      message:"Token has been revoked"
    })
  }

  next();
}

async function authMiddleware(req,res,next){
  const refreshToken = req.cookies.refreshToken;

  if(!refreshToken){
    return res.status(401).json({
      message:"Unauthorized"
    })
  }

  try{
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const sessionExists = await redis.get(`session:${decoded.id}:${decoded.sessionId}`);

    if(!sessionExists){
      return res.status(401).json({
        message:"Session expired or logged Out"
      })
    }

    req.user = decoded;

    next();
  }
  catch(err){
    return res.status(500).json({
      message:"Unauthorized or invalid token",
      error:err.message
    })
  }
}
module.exports = { findUser , blackListToken , authMiddleware};
