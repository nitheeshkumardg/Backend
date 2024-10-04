const mongoose=require("mongoose")


let connectDB =async ()=>{
    await mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
                   .then(() => console.log("MongoDB connected"))
                   .catch((err) => console.error(err));

}
  module.exports = connectDB