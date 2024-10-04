const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const Seller = require("../modules/seller");
const {
  JWT_SECRET,
  EMAIL_SERVICE,
  EMAIL_SELLER,
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
    "/sellerregister",
    [
      check("email").isEmail().withMessage("Enter a valid email address"),
      check("password")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters long"),
    ],
    handleValidationErrors,
    async (req, res) => {
      const { email, password, name } = req.body;
      try {
        if (!email || !password || !name) {
          return res.json({ message: "All fields are required" });
        }
        const seller = await Seller.findOne({ email });
        if (seller) return res.status(400).send("Seller is existed");
        const hashedPassword = await bcrypt.hash(password, 10);
        const newSeller = new Seller({
          email,
          password: hashedPassword,
          name,
          
        });
        await newSeller.save();
  
        res
          .status(201)
          .json({ message: "Seller registered successfully", newSeller });
      } catch (error) {
        res.status(400).send(error.message);
      }
    }
  );

  router.post(
    "/sellerLogin",
    [
      check("email").isEmail().withMessage("Enter a valid email address"),
      check("password").exists().withMessage("Password is required"),
    ],
    handleValidationErrors,
    async (req, res) => {
      const { email, password } = req.body;
      try {
        const seller = await Seller.findOne({ email });
        if (!seller) return res.status(400).send("Invalid credentials");
  
        const isMatch = await bcrypt.compare(password, seller.password);
        if (!isMatch) return res.status(400).send("Invalid credentials");
  
        const token = jwt.sign({ id: seller._id }, JWT_SECRET);
  
        res
          .status(201)
          .json({ token: token, message: "Logged in successfully", seller: seller });
      } catch (error) {
        res.status(400).send(error.message);
      }
    }
  );




module.exports=router