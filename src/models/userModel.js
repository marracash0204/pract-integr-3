import mongoose from "mongoose";

const userCollection = "usuarios";

const userSchema = new mongoose.Schema({
  first_name: String,
  last_name: String,
  email: {
    type: String,
    unique: true,
  },
  age: Number,
  password: String,
  cart: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "carts",
  },
  rol: { type: String, enum: ["usuario", "admin", "premium"], default: "usuario" }, 
  githubId: String,
  resetToken: String,
  resetTokenExpiration: Date,
});

const userModel = mongoose.model(userCollection, userSchema);

export { userModel };
