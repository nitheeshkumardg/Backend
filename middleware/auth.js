const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/config");
const User = require("../modules/user");
const seller=require("../modules/seller")
const { check } = require("express-validator");


const auth = async (req, res, next) => {
  const token = await req.headers?.authorization?.split(" ")[1];

  if (!token) return res.status(401).send(`Token: ${token} Access denied.`);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
  
    if (!user) return res.status(401).send("User not found");

    req.user = user; 
    next();
  } catch (error) {
    req.user = undefined; 
    res.status(401).send("Invalid token.");
  }
};


const validateResetPassword = [
  check("newPassword")
    .isLength({ min: 6 })
    .withMessage("New password must be at least 6 characters long"),
];


module.exports = { auth, validateResetPassword };
