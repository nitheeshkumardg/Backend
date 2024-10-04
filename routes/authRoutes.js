const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const User = require("../modules/user");
const {
  JWT_SECRET,
  EMAIL_SERVICE,
  EMAIL_USER,
  EMAIL_PASS,
} = require("../config/config");
const { auth } = require("../middleware/auth");
const { check, validationResult } = require("express-validator");
const router=express.Router();

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  };

router.post(
    "/register",
    [
      check("email").isEmail().withMessage("Enter a valid email address"),
      check("password")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters long"),
    ],
    handleValidationErrors,
    async (req, res) => {
      const { email, password, name, userType } = req.body;
      try {
        if (!email || !password || !name || !userType) {
          return res.json({ message: "All fields are required" });
        }
        const user = await User.findOne({ email });
        if (user) return res.status(400).send("User is existed");
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
          email,
          password: hashedPassword,
          name,
          userType,
        });
        await newUser.save();
  
        res
          .status(201)
          .json({ message: "User registered successfully", newUser });
      } catch (error) {
        res.status(400).send(error.message);
      }
    }
  );

  router.post(
    "/Login",
    [
      check("email").isEmail().withMessage("Enter a valid email address"),
      check("password").exists().withMessage("Password is required"),
    ],
    handleValidationErrors,
    async (req, res) => {
      const { email, password } = req.body;
      try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send("Invalid credentials");
  
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send("Invalid credentials");
  
        const token = jwt.sign({ id: user._id }, JWT_SECRET);
  
        res
          .status(201)
          .json({ token: token, message: "Logged in successfully", user: user });
      } catch (error) {
        res.status(400).send(error.message);
      }
    }
  );




module.exports=router








