const express=require('express')
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const cookieParser = require("cookie-parser");
const authRoutes=require('./routes/authRoutes')
const connectDB=require('./config/database')
const productRoutes = require("./routes/products");
const sellerRoutes=require('./routes/sellerRoutes')
const cartRoutes = require('./routes/cartRoutes');

const dotenv=require('dotenv')
dotenv.config()
const app=express()
app.use(express.static(path.join(__dirname, "./public")));
app.use(
  cors({
    origin: "*", // Allows all origins
    methods: ["GET", "POST", "DELETE", "PUT"],
    credentials: true,
  })
);
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.json())
connectDB()





app.use('/api/auth',authRoutes)
app.use("/api/products", productRoutes);
app.use('/api/seller',sellerRoutes)
app.use('/api/cart', cartRoutes);





const PORT=process.env.PORT || 5000
app.listen(PORT,()=>console.log(`Runnning on http://localhost:${PORT}`))
