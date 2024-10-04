const express = require("express");
const {authSeller}=require("../middleware/authSeller")
const Product = require("../modules/product");
const { check, validationResult } = require("express-validator");
const path = require("path");
const { upload } = require("../utility/multer");
const {auth}=require("../middleware/auth")

const router = express.Router();

// Middleware to handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Route to get all products
router.get('/products', async (req, res) => {
  try {
    const products = await Product.find(); // Fetch all products
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products', error });
  }
});













// Create Product
router.post(
  "/Vendor",
  [
    upload,
    authSeller,
    check("title").not().isEmpty().withMessage("Product name is required"),
    check("description")
      .not()
      .isEmpty()
      .withMessage("Product description is required"),
    check("price")
      .isFloat({ gt: 0 })
      .withMessage("Price must be a positive number"),
    check("category").not().isEmpty().withMessage("Category is required"),
    check("stock")
      .optional()
      .isInt({ min: 0 })
      .withMessage("Stock must be a non-negative integer"),
  ],
  handleValidationErrors,
  async (req, res) => {
    const { title, description, price, category, stock } = req.body;
    const seller = req.user; // Get the authenticated seller

    if (!req.file) {
      return res.status(400).send("Image file is required");
    }

    try {
      const newProduct = new Product({
        title,
        description,
        price,
        category,
        stock,
        image: req.file.filename,
        sellerID: seller._id, 
      });

      await newProduct.save();
      res.status(201).json({ message: "Product added successfully", newProduct });
    } catch (error) {
      console.error(error);
      res.status(400).send(error.message);
    }
  }
);

// Get Products by Seller
router.get("/Vendor/products",authSeller,  async (req, res) => {
  try {
    const sellerId = req.user._id; // Get the logged-in seller's ID
   
    const products = await Product.find({ sellerID: sellerId });
   
   return res.json(products);
  } catch (error) {
   
   return res.status(500).send("Server error");
  }
});

//Get the pagination
router.get("/", async (req, res) => {
  try {
    const page = parseInt(req.query.page);
    const perPage = 10;
    const totalProduct = await Product.countDocuments();
    const totalPage = Math.ceil(totalProduct / perPage);
    if (page > totalPage) {
      return res.status(404).json({ message: "Page not found" });
    }
    const Products = await Product.find()
      .skip((page - 1) * perPage)
      .limit(perPage)
      .exec();
    res.json({ Products, totalPage, page }).status(200).cookie("lofer", "Yes");
  } catch (error) {
    res.status(500).json({ err: error });
  }
});

// Get All Products
router.get("/all", async (req, res) => {
  try {
    const products = await Product.find();
    // Map products to include full image URL
    const productsWithimages = products.map((product) => ({
      name: product.title,
      description: product.description,
      price: product.price,
      category: product.category,
      stock: product.stock,
      image: `http://localhost:7777/static/${product.image}`, // Construct the full image URL
    }));

    // Send the list of products with image URLs
    res.json(productsWithimages);
  } catch (error) {
    res.status(500).send("Server Error");
  }
});

// Get Single Product by ID
router.get("/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const product = await Product.findById(id);
    if (!product) return res.status(404).send("Product not found");
    res.json(product);
  } catch (error) {
    res.status(500).send("Server Error");
  }
});

// Update Product by ID
router.put(
  "/:id",
  [
    auth, // Ensure the user is authenticated
    check("name")
      .optional()
      .not()
      .isEmpty()
      .withMessage("Product name is required"),
    check("description")
      .optional()
      .not()
      .isEmpty()
      .withMessage("Product description is required"),
    check("price")
      .optional()
      .isFloat({ gt: 0 })
      .withMessage("Price must be a positive number"),
    check("category")
      .optional()
      .not()
      .isEmpty()
      .withMessage("Category is required"),
    check("stock")
      .optional()
      .isInt({ min: 0 })
      .withMessage("Stock must be a non-negative integer"),
  ],
  handleValidationErrors,
  async (req, res) => {
    const { id } = req.params;
    const { name, description, price, category, stock, image } = req.body;

    try {
      const product = await Product.findByIdAndUpdate(
        id,
        { name, description, price, category, stock, image },
        { new: true, runValidators: true }
      );
      if (!product) return res.status(404).send("Product not found");
      res.json({ message: "Product updated successfully", product });
    } catch (error) {
      res.status(400).send(error.message);
    }
  }
);

// Delete Product by ID
router.delete("/:id", auth, async (req, res) => {
  const { id } = req.params;

  try {
    const product = await Product.findByIdAndDelete(id);
    if (!product) return res.status(404).send("Product not found");
    res.json({ message: "Product deleted successfully" });
  } catch (error) {
    res.status(500).send("Server Error");
  }
});

module.exports = router;