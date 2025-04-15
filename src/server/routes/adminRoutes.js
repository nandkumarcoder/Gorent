const express = require('express');
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const router = express.Router();

// Admin Login Route
router.post('/login', async (req, res) => {
    const { email, password, key } = req.body;

    try {
        // Check if admin exists
        const admin = await Admin.findOne({ email });
        if (!admin) return res.status(404).json({ success: false, message: 'Admin not found' });

        // Validate password
        const isPasswordValid = await admin.comparePassword(password);
        if (!isPasswordValid) return res.status(401).json({ success: false, message: 'Invalid credentials' });

        // Validate admin key
        if (admin.key !== key) return res.status(401).json({ success: false, message: 'Invalid admin key' });

        // Generate JWT token
        const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ success: true, authToken: token });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Admin Registration Route (Optional)
router.post('/register', async (req, res) => {
    const { email, password, key } = req.body;

    try {
        const adminExists = await Admin.findOne({ email });
        if (adminExists) return res.status(400).json({ success: false, message: 'Admin already exists' });

        const newAdmin = new Admin({ email, password, key });
        await newAdmin.save();

        res.status(201).json({ success: true, message: 'Admin registered successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

module.exports = router;