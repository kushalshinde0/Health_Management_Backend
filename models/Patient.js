const mongoose = require('mongoose');

// Define the Patient Schema
const PatientSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    age: {
        type: Number,
        required: true,
        min: 0
    },
    gender: {
        type: String,
        enum: ['Male', 'Female', 'Other'],
        required: true
    },
    email: {
        type: String,
        unique: true,   // Ensure email remains unique
        sparse: true,   // Allow multiple entries with null values
        trim: true
    },
    contactNumber: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    
    address: {
        type: String,
        required: true,
        trim: true
    },
    medicalHistory: {
        type: [String], // Array of strings for storing previous medical conditions
        default: []
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId, // Reference to the user (doctor/admin) who created the record
        ref: 'User',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});



// Create the Patient model
const Patient = mongoose.model('Patient', PatientSchema);

module.exports = Patient;
