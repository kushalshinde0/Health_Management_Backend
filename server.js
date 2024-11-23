const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const User = require('./models/User');  // Adjust this path based on your project structure
const Patient= require('./models/Patient');  
const authRoutes = require('./routes/auth'); // Import the auth routes



dotenv.config();  // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());  // Middleware to parse JSON bodies (replaces body-parser)


// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.log("MongoDB connection error:", err));



// Middleware to verify JWT token and authorize admin access
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Forbidden: Invalid or expired token.' });
    }

    req.user = user;
    
    next();
  });
};


app.use('/api/auth', authRoutes); // This mounts the auth routes to '/api/auth'

// Starting the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
