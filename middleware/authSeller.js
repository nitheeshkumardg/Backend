const jwt = require("jsonwebtoken");
const Seller = require("../modules/seller");

const { JWT_SECRET } = require("../config/config");

const authSeller = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Access denied. No token provided.");

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const seller = await Seller.findById(decoded.id);

    if (!seller) {
      return res.status(401).send("Access denied. Not a valid seller.");
    }

    req.user = seller; 
    next();
  } catch (error) {
    res.status(400).send("Invalid token.");
  }
};

module.exports = { authSeller };
