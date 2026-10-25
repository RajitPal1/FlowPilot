const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, "Username is requried"],
  },
  id: {
    type: Number,
    required: [true, "Id is required"],
    unique: [true, "Id must be unique"],
  },
  role: {
    type: String,
    enum: ["staff", "admin"],
    required: [true, "Role is requried"],
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: [true, "Email must be unique"],
    match: [
      /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      "Please provide a valid email address",
    ],
    lowercase: true,
    trim: true,
  },
  password:{
    type: String,
    required: [true, "Password is requried"],
  }
});

const userModel = mongoose.model("user", userSchema);

module.exports = userModel;
