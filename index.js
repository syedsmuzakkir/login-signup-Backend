require('dotenv').config();
const express = require('express');


const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); 
const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;
const app = express();
app.use(express.json()); // Parse request body as JSON


// Connect to MongoDB
mongoose.connect(process.env.URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

const User = mongoose.model('User', userSchema);

// Signup route
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash the password
    const saltRounds = 10; // Number of salt rounds for hashing
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create a new user
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User created' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


  

// Login route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate an access token
    const token = jwt.sign({ userId: user._id }, 'your_secret_key', {
      expiresIn: '12h',
    });

    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


  // Forget password route
app.post('/forgot-password', async (req, res) => {
    try {
      const { email } = req.body;
  
      // Find the user by email
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      // Generate a reset password token
      const resetPasswordToken = crypto.randomBytes(20).toString('hex');
      const resetPasswordExpires = Date.now() + 3600000; // 1 hour
  
      // Update the user with the reset password token and expiration date
      user.resetPasswordToken = resetPasswordToken;
      user.resetPasswordExpires = resetPasswordExpires;
      await user.save();
  
      // Send a reset password email
      const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        service:"gmail",
        // port:465,
        // secure:false,

        // host: 'smtp.gmail.com',
        // host: 'smtp-relay.brevo.com',
        port: 587,
        secure: false,
        requireTLS: true,
        
        auth: {
          user: process.env.Email,
          pass: process.env.Password,
        //   ', // Replace with your Gmail password
        //   dlzk apzq vkkz yjid,
        },
      });
  
      const mailOptions = {
        from: process.env.Email,
        to: email,
        subject: 'Reset your password',
        text: `You are receiving this email because you want to reset your password. Please click on the following link, or paste this into your browser to complete the process: http://localhost:3000/reset-password/${resetPasswordToken}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.`,
      };
  
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log(error);
          return res.status(500).json({ error: 'Failed to send email' });
        } else {
          console.log('Email sent: ' + info.response);
          return res.json({ message: 'Reset password email sent' });
        }
      });

   
    } catch (error) {
      res.status(500).json({ error: error.message });
    }



    

  })
  

// Reset password route
app.post('/reset-password/:token', async (req, res) => {
    try {
      const token = req.params.token;
      const { newPassword } = req.body;
         
      console.log(newPassword, 'this is new password')
      // Validate the token
      const user = await User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });
      if (!user) {
        return res.status(401).json({ error: 'Invalid token or token has expired' });
      }
  
      // Hash the new password
      const saltRounds = 10; // Number of salt rounds for hashing
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
  
      // Update the user's password and reset token fields
      user.password = hashedPassword;
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();
  
      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
