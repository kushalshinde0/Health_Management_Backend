const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');  // Import the User model
const Patient = require('../models/Patient');  // Import the User model
const verifyToken = require('../middleware/verifyToken');  // Import the verifyToken middleware

const router = express.Router();  // Use Router instead of app

// User Registration Route
router.post('/register', async (req, res) => {
    const { email, password, role } = req.body;

    // Validate role input
    if (!["patient", "doctor", "admin"].includes(role)) {
        return res.status(400).json({ msg: "Invalid role" });
    }

    try {
        // Check if the user already exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create the user
        const newUser = new User({
            email,
            password: hashedPassword,
            role
        });

        await newUser.save();
        res.status(201).json({ msg: 'User created successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server error' });
    }
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        console.log("Entered Password:", password);
        console.log("Stored Hash:", user.password);
        console.log("Password Match:", isMatch);

        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Create JWT token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            token,
            user: {
                id: user._id,
                role: user.role,
                email: user.email
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server error' });
    }
});



// Create new patient record
router.post('/patient', verifyToken, async (req, res) => {
    if (req.user.role !== 'doctor' && req.user.role !== 'admin') {
        return res.status(403).json({ msg: 'Access denied: Doctor/Admin only' });
    }

    try {
        // Check if all required fields are present
        const { name, age, gender, email, contactNumber, address, medicalHistory } = req.body;
        if (!name || !age || !gender || !contactNumber || !address) {
            return res.status(400).json({ msg: 'Missing required fields' });
        }

        // Ensure the email is unique if provided
        if (email) {
            const existingEmail = await Patient.findOne({ email });
            if (existingEmail) {
                return res.status(400).json({ msg: 'Email is already in use' });
            }
        }

        // Correct initialization of patient object
        const newPatient = new Patient({
            name,
            age,
            gender,
            email,
            contactNumber,
            address,
            medicalHistory,
            createdBy: req.user.userId, // Reference to user who created
        });

        await newPatient.save();
        res.status(201).json({ msg: 'Patient record created successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server error' });
    }
});


// Update existing patient record
router.put('/patient/:id', verifyToken, async (req, res) => {
    if (req.user.role !== 'doctor' && req.user.role !== 'admin') {
        return res.status(403).json({ msg: 'Access denied: Doctor/Admin only' });
    }

    try {
        // Find the patient by ID
        const patient = await Patient.findById(req.params.id);
        if (!patient) {
            return res.status(404).json({ msg: 'Patient not found' });
        }

        // Check if the email being updated is unique (optional, based on your needs)
        if (req.body.email) {
            const existingEmail = await Patient.findOne({ email: req.body.email });
            if (existingEmail && existingEmail._id !== patient._id) {
                return res.status(400).json({ msg: 'Email is already in use' });
            }
        }

        // Update the patient details with new data
        Object.assign(patient, req.body);

        // Save the updated patient record
        await patient.save();

        res.status(200).json({ msg: 'Patient record updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server error' });
    }
});


// View patient records
router.get('/patient/:id', verifyToken, async (req, res) => {
    if (req.user.role !== 'doctor' && req.user.role !== 'admin') {
        return res.status(403).json({ msg: 'Access denied: Doctor/Admin only' });
    }

    try {
        const patient = await Patient.findById(req.params.id);
        if (!patient) {
            return res.status(404).json({ msg: 'Patient not found' });
        }

        res.json(patient);  // You can customize the fields returned
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server error' });
    }
});

// Example route that only admins can access
router.get('/admin', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ msg: 'Access denied' });
    }
    res.json({ msg: 'Welcome Admin' });
});

// Admin route example (protected)
router.get('/admin/dashboard', verifyToken, (req, res) => {
    console.log('Received request for /admin/dashboard');
    if (req.user.role !== 'admin') {
        return res.status(403).json({ msg: 'Access denied: Admins only' });
    }
    res.json({ msg: 'Welcome to the Admin Dashboard' });
});

// Get list of all users (Patients, Doctors, Admins)
router.get('/admin/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ msg: 'Access denied: Admin only' });
    }

    try {
        const users = await User.find();
        res.json(users);
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// Get list of all doctors
router.get('/admin/doctors', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ msg: 'Access denied: Admin only' });
    }

    try {
        const doctors = await User.find({ role: 'doctor' });
        res.json(doctors);
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
});





module.exports = router;  // Export router
