// models/Cart.js
// const mongoose = require('mongoose');
// const Schema = mongoose.Schema;

// const cartItemSchema = new Schema({
//   productId: { type: Schema.Types.ObjectId, ref: 'Product', required: true },
//   quantity: { type: Number, required: true },
//   price: { type: Number, required: true },
// });

// const cartSchema = new Schema({
//   userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
//   items: [cartItemSchema],
//   updatedAt: { type: Date, default: Date.now },
// });

// const Cart = mongoose.model('Cart', cartSchema);
// module.exports = Cart;



// models/Cart.js
// const mongoose = require('mongoose');

// const cartSchema = new mongoose.Schema({
//   userId: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: 'User', // Assuming you have a User model
//     required: true
//   },
//   items: [
//     {
//       productId: {
//         type: mongoose.Schema.Types.ObjectId,
//         ref: 'Product', // Assuming you have a Product model
//         required: true
//       },
//       quantity: {
//         type: Number,
//         default: 1
//       }
//     }
//   ]
// }, { timestamps: true });

// module.exports = mongoose.model('Cart', cartSchema);

const mongoose = require('mongoose');

const CartSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [
    {
      productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
        required: true
      },
      title: {
        type: String,
        required: true
      },
      price: {
        type: Number,
        required: true
      },
      quantity: {
        type: Number,
        required: true,
        default: 1
      },
      image: {
        type: String, 
        required: true 
      }
    }
  ],
  subtotal: {
    type: Number,
    required: true,
    default: 0
  },
  tax: {
    type: Number,
    required: true,
    default: 0
  },
  extraCost: {
    type: Number,
    required: true,
    default: 50 // Flat ₹50 extra charge
  },
  grandTotal: {
    type: Number,
    required: true,
    default: 0
  }
});

// Pre-save hook to automatically calculate subtotal, tax, and grand total
CartSchema.pre('save', function (next) {
  try {
    // Calculate subtotal by summing up all item totals
    this.subtotal = this.items.reduce((acc, item) => acc + (item.price * item.quantity), 0);

    // Tax is 18% of the subtotal
    this.tax = this.subtotal * 0.18;

    // Calculate the grand total: subtotal + tax + extraCost
    this.grandTotal = this.subtotal + this.tax + this.extraCost;

    next();
  } catch (error) {
    next(error); // Forward the error to the error handler
  }
});

const Cart = mongoose.model('Cart', CartSchema);

module.exports = Cart;
