const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Create the User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'doctor', 'patient'], default: 'patient' },
  // Additional fields for patient and doctor can be added later
});

// Hash password before saving the user
userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    // this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

// Model definition
const User = mongoose.model('User', userSchema);

module.exports = User;
