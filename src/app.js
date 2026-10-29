const express = require("express");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const authRouter = require("./routes/auth.route");

const app = express();

// MiddleWares

app.use(cookieParser());
app.use(express.json());
app.use(morgan("dev"));

// Routes

app.use("/api/auth", authRouter);

module.exports = app;