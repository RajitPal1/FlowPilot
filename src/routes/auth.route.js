const express = require("express");
const {
  findUser,
} = require("../middlewares/auth.middleware");

const { sendOTP,verifyOTP,createUser } = require("../controller/auth.controller");

const router = express.Router();

router.post("/send-otp", findUser, sendOTP);

router.post("/verify-otp", findUser, verifyOTP);

router.post("/create-user", createUser );

module.exports = router;
