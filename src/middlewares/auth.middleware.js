const userData = require("../data/userData.json");
const userModel = require("../models/user.model");

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

module.exports = { findUser };
