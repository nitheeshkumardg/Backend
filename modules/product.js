// const mongoose = require("mongoose");

// const productSchema = new mongoose.Schema(
//   {
//     title: { type: String },
//     description: { type: String },
//     price: { type: Number },
//     category: { type: String },
//     stock: { type: Number, default: 0 },
//     imageUrl: { type: String }, // Optional field for product image
//     sellerID: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "Seller",
//     },
//   },
//   {
//     timestamps: true, // Automatically adds createdAt and updatedAt fields
//   })


// module.exports = mongoose.model("Product", productSchema);



const mongoose = require("mongoose");

const productSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: { type: String },
    price: { type: Number, required: true },
    oldPrice: { type: Number }, 
    category: { type: String, required: true },
    stock: { type: Number, default: 0 },
    image: { type: String }, 
    isNew: { type: Boolean, default: false }, 
    rating: { type: Number, default: 0 },  
    sellerID: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Seller",
    },
  },
  {
    timestamps: true, 
  }
);

module.exports = mongoose.model("Product", productSchema);



