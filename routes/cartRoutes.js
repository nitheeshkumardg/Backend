// const express = require('express');
// const Cart = require('../modules/Cart');
// const Product = require('../modules/product');
// const router = express.Router();

// // Add item to cart
// router.post('/add', async (req, res) => {
//   const { userId, productId } = req.body;
//   try {
//     // Fetch the product details from the database
//     const product = await Product.findById(productId);
//     if (!product) {
//       return res.status(404).json({ message: 'Product not found' });
//     }

//     // Find the cart for the user
//     let cart = await Cart.findOne({ userId });

//     // If no cart exists for the user, create a new one
//     if (!cart) {
//       cart = new Cart({ userId, cartItems: [] });
//     }

//     // Check if the product already exists in the cart
//     const existingItemIndex = cart.cartItems.findIndex(item => item.product.toString() === productId);

//     if (existingItemIndex !== -1) {
//       // Update the existing product quantity and price
//       cart.cartItems[existingItemIndex].quantity += 1;
//       cart.cartItems[existingItemIndex].total_item_price = cart.cartItems[existingItemIndex].quantity * product.price;
//     } else {
//       // Add new product to the cart
//       cart.cartItems.push({
//         product: productId,
//         quantity: 1,
//         total_item_price: product.price
//       });
//     }

//     // Update cart totals
//     cart.cartCounter += 1;
//     cart.totalPrice += product.price;
//     cart.taxes = cart.totalPrice * 0.18;
//     cart.grandTotal = cart.totalPrice + cart.taxes + 50; // Assuming 50 is extra cost

//     // Save the cart
//     await cart.save();
//     res.status(200).json(cart);
//   } catch (error) {
//     console.error('Error adding item to cart:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// // Remove item from cart
// router.delete('/remove', async (req, res) => {
//   const { userId, productId } = req.body;
//   try {
//     // Find the cart for the user
//     const cart = await Cart.findOne({ userId });

//     if (!cart) {
//       return res.status(404).json({ message: 'Cart not found' });
//     }

//     // Find the product to remove
//     const removedItemIndex = cart.cartItems.findIndex(item => item.product.toString() === productId);
//     if (removedItemIndex === -1) {
//       return res.status(404).json({ message: 'Product not found in cart' });
//     }

//     // Update the cart totals
//     const removedItem = cart.cartItems[removedItemIndex];
//     cart.cartCounter -= removedItem.quantity;
//     cart.totalPrice -= removedItem.total_item_price;
//     cart.taxes = cart.totalPrice * 0.18;
//     cart.grandTotal = cart.totalPrice + cart.taxes + 50;

//     // Remove the item from the cart
//     cart.cartItems.splice(removedItemIndex, 1);

//     // Save the updated cart
//     await cart.save();
//     res.status(200).json(cart);
//   } catch (error) {
//     console.error('Error removing item from cart:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// // Fetch cart items for a user
// router.get('/:userId', async (req, res) => {
//   const { userId } = req.params;
//   try {
//     const cart = await Cart.findOne({ userId }).populate('cartItems.product');
//     if (!cart) {
//       return res.status(200).json({ cartItems: [], cartCounter: 0, totalPrice: 0, taxes: 0, grandTotal: 0 });
//     }
//     res.status(200).json(cart);
//   } catch (error) {
//     console.error('Error fetching cart:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// module.exports = router;


// const express = require('express');
// const Cart = require('../modules/Cart');
// const Product = require('../modules/product');
// const router = express.Router();

// // Add item to cart
// router.post('/add', async (req, res) => {
//   const { userId, productId } = req.body;
//   try {
//     // Fetch the product details from the database
//     const product = await Product.findById(productId);
//     if (!product) {
//       return res.status(404).json({ message: 'Product not found' });
//     }

//     // Find the cart for the user
//     let cart = await Cart.findOne({ userId });

//     // If no cart exists for the user, create a new one
//     if (!cart) {
//       cart = new Cart({ userId, cartItems: [] });
//     }

//     // Check if the product already exists in the cart
//     const existingItemIndex = cart.cartItems.findIndex(item => item.product.toString() === productId);

//     if (existingItemIndex !== -1) {
//       // Update the existing product quantity and price
//       cart.cartItems[existingItemIndex].quantity += 1;
//       cart.cartItems[existingItemIndex].total_item_price = cart.cartItems[existingItemIndex].quantity * product.price;
//     } else {
//       // Add new product to the cart
//       cart.cartItems.push({
//         product: productId,
//         quantity: 1,
//         total_item_price: product.price
//       });
//     }

//     // Update cart totals
//     cart.cartCounter += 1;
//     cart.totalPrice += product.price;
//     cart.taxes = cart.totalPrice * 0.18;
//     cart.grandTotal = cart.totalPrice + cart.taxes + 50; // Assuming 50 is extra cost

//     // Save the cart
//     await cart.save();
//     res.status(200).json(cart);
//   } catch (error) {
//     console.error('Error adding item to cart:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// // Remove item from cart
// router.delete('/remove', async (req, res) => {
//   const { userId, productId } = req.body;
//   try {
//     // Find the cart for the user
//     const cart = await Cart.findOne({ userId });

//     if (!cart) {
//       return res.status(404).json({ message: 'Cart not found' });
//     }

//     // Find the product to remove
//     const removedItemIndex = cart.cartItems.findIndex(item => item.product.toString() === productId);
//     if (removedItemIndex === -1) {
//       return res.status(404).json({ message: 'Product not found in cart' });
//     }

//     // Update the cart totals
//     const removedItem = cart.cartItems[removedItemIndex];
//     cart.cartCounter -= removedItem.quantity;
//     cart.totalPrice -= removedItem.total_item_price;
//     cart.taxes = cart.totalPrice * 0.18;
//     cart.grandTotal = cart.totalPrice + cart.taxes + 50;

//     // Remove the item from the cart
//     cart.cartItems.splice(removedItemIndex, 1);

//     // Save the updated cart
//     await cart.save();
//     res.status(200).json(cart);
//   } catch (error) {
//     console.error('Error removing item from cart:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// // Fetch cart items for a user
// router.get('/:userId', async (req, res) => {
//   const { userId } = req.params;
//   try {
//     const cart = await Cart.findOne({ userId }).populate('cartItems.product');
//     if (!cart) {
//       return res.status(200).json({ cartItems: [], cartCounter: 0, totalPrice: 0, taxes: 0, grandTotal: 0 });
//     }
//     res.status(200).json(cart);
//   } catch (error) {
//     console.error('Error fetching cart:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// module.exports = router;


// const express = require('express');
// const { auth } = require('../middleware/auth');
// const Cart = require('../modules/Cart');
// const router = express.Router();

// // Protected route to get the user's cart
// router.get('/', auth, async (req, res) => {
//   try {
//     const cart = await Cart.findOne({ userId: req.user._id }).populate('items.productId');
//     if (!cart) {
//       return res.status(404).json({ message: 'Cart not found' });
//     }
//     res.json(cart);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// // Protected route to add an item to the cart
// router.post('/add', auth, async (req, res) => {
//   const { productId, quantity, price } = req.body;
  
//   try {
//     let cart = await Cart.findOne({ userId: req.user._id });

//     if (!cart) {
//       // Create a new cart if one doesn't exist
//       cart = new Cart({ userId: req.user._id, items: [{ productId, quantity, price }] });
//     } else {
//       // Find if the product already exists in the cart
//       const itemIndex = cart.items.findIndex(item => item.productId == productId);

//       if (itemIndex > -1) {
//         // If product exists, update the quantity
//         cart.items[itemIndex].quantity += quantity;
//       } else {
//         // If product doesn't exist, add a new item
//         cart.items.push({ productId, quantity, price });
//       }
//     }

//     await cart.save();
//     res.json(cart);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// module.exports = router;



// routes/cart.js
// const express = require('express');
// const Cart = require('../modules/Cart');
// const router = express.Router();

// // Middleware to check if user is authenticated
// const {auth} = require('../middleware/auth');

// // Get the current user's cart items
// router.get('/', auth, async (req, res) => {
//   try {
//     const cart = await Cart.findOne({ userId: req.user.id }).populate('items.productId');
//     if (!cart) return res.status(200).json({ items: [], total: 0 });

//     // Calculate total cost
//     const totalCost = cart.items.reduce((total, item) => {
//       return total + item.productId.price * item.quantity;
//     }, 0);

//     res.status(200).json({ items: cart.items, total: totalCost });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Add item to the cart
// router.post('/add', auth, async (req, res) => {
//   const { productId, quantity } = req.body;
//   console.log("Product ID:", productId, "Quantity:", quantity);
//   try {
//     let cart = await Cart.findOne({ userId: req.user.id });

//     if (!cart) {
//       cart = new Cart({ userId: req.user.id, items: [] });
//     }

//     const itemIndex = cart.items.findIndex(item => item.productId.toString() === productId);

//     if (itemIndex > -1) {
//       // If product already exists, update quantity
//       cart.items[itemIndex].quantity += quantity;
//     } else {
//       cart.items.push({ productId, quantity });
//     }

//     await cart.save();
//     res.status(200).json(cart);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Remove item from cart
// router.post('/remove', auth, async (req, res) => {
//   const { productId } = req.body;
//   try {
//     const cart = await Cart.findOne({ userId: req.user.id });

//     if (cart) {
//       cart.items = cart.items.filter(item => item.productId.toString() !== productId);
//       await cart.save();
//     }

//     res.status(200).json(cart);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// module.exports = router;


const express = require('express');
const router = express.Router();
const { addToCart, removeFromCart,getCart}  = require('../controllers/cartControllers');
const {auth} = require('../middleware/auth'); 


router.post('/cart/add', auth, addToCart);


router.post('/cart/remove', auth, removeFromCart);
router.get('/', auth, getCart)

module.exports = router;


