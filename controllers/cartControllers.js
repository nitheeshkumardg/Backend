const Cart = require('../modules/Cart');
const Product = require("../modules/product");

// Add item to cart
exports.addToCart = async (req, res) => {
  const { productId, title, price, quantity,image } = req.body;
 
  
  const userId = req.user.id; 
  try {
   
   
    let cart = await Cart.findOne({ userId });

   
    if (!cart) {
      cart = new Cart({
        userId,
        items: [{ productId, title, price, quantity,image}],
      });
    } else {
     
      const existingItemIndex = cart.items.findIndex(item => item.productId.equals(productId));

      if (existingItemIndex >= 0) {
       
        cart.items[existingItemIndex].quantity += quantity;
      } else {
        
        cart.items.push({ productId, title, price, quantity,image });
      }
    }

  
    await cart.save();
    return res.status(200).json(cart);
  } catch (error) {
    console.error('Error adding to cart:', error.message);
    return res.status(500).json({ message: 'Server error' });
  }
};
exports.removeFromCart = async (req, res) => {
    const { productId } = req.body;
    const userId = req.user.id; 
  
    try {
      const cart = await Cart.findOne({ userId });
  
      if (!cart) {
        return res.status(404).json({ message: 'Cart not found' });
      }
  
    
      cart.items = cart.items.filter(item => !item.productId.equals(productId));
  
      await cart.save();
      return res.status(200).json({ message: 'Item removed', cart });
    } catch (error) {
      console.error('Error removing item from cart:', error.message);
      return res.status(500).json({ message: 'Server error' });
    }
  };

  exports.getCart = async (req, res) => {
    const userId = req.user.id; 
  
    try {
      
      const cart = await Cart.findOne({ userId });
  
      if (!cart) {
        return res.status(200).json({ message: 'No items in your cart', items: [] });
      }
  
      
      return res.status(200).json(cart);
    } catch (error) {
      console.error('Error fetching cart:', error.message);
      return res.status(500).json({ message: 'Server error' });
    }
  };
  
