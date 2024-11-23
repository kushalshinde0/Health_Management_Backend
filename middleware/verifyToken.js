const jwt = require('jsonwebtoken');

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    // Try to get the token from 'Authorization' header or 'x-auth-token'
    const token = req.header('Authorization')?.split(' ')[1] || req.header('x-auth-token');

    if (!token) {
        return res.status(401).json({ msg: 'Access denied: No token provided' });
    }

    try {
        // Verify the token with the JWT_SECRET
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Attach the user data to the request object
        req.user = decoded;

        // Proceed to the next middleware/route handler
        next();
    } catch (err) {
        return res.status(400).json({ msg: 'Invalid token' });
    }
};

module.exports = verifyToken;
