const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(session({
    secret: 'super_secret_key_change_in_production',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Mock Database
const users = []; // Stores verified users
const pendingVerifications = {}; // Stores users waiting to verify their email

// Disposable email domains list (in production, use an API like AbstractAPI)
const blockedDomains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com', 'throwaway.com'];

// Generate a random 6-digit code
const generateVerificationCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// ==========================================
// 1. SIGNUP ENDPOINT
// ==========================================
app.post('/api/signup', async (req, res) => {
    const { email, username, password } = req.body;

    // Validate Temp Email
    const domain = email.split('@');
    if (blockedDomains.includes(domain)) {
        return res.status(400).json({ error: "Temporary emails are not allowed." });
    }

    // Check if user already exists
    if (users.find(u => u.email === email)) {
        return res.status(400).json({ error: "User already exists." });
    }

    // Hash the password securely
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = generateVerificationCode();

    // Store temporarily until verified
    pendingVerifications[email] = {
        email,
        username,
        password: hashedPassword,
        code: verificationCode
    };

    // Send Verification Email (Using Ethereal for testing)
    const testAccount = await nodemailer.createTestAccount();
    const transporter = nodemailer.createTransport({
        host: "smtp.ethereal.email",
        port: 587,
        secure: false,
        auth: {
            user: testAccount.user,
            pass: testAccount.pass,
        },
    });

    const info = await transporter.sendMail({
        from: '"My App" <noreply@myapp.com>',
        to: email,
        subject: "Your Verification Code",
        text: `Your verification code is: ${verificationCode}`,
    });

    console.log("Verification email sent! Preview URL: ", nodemailer.getTestMessageUrl(info));
    
    res.json({ message: "Verification code sent to email." });
});

// ==========================================
// 2. VERIFY ENDPOINT
// ==========================================
app.post('/api/verify', (req, res) => {
    const { email, code } = req.body;
    const pendingUser = pendingVerifications[email];

    if (!pendingUser) {
        return res.status(400).json({ error: "No pending verification found for this email." });
    }

    if (pendingUser.code !== code) {
        return res.status(400).json({ error: "Invalid verification code." });
    }

    // Code is correct, move user to verified database
    users.push({
        email: pendingUser.email,
        username: pendingUser.username,
        password: pendingUser.password
    });
    
    delete pendingVerifications[email]; // Cleanup

    res.json({ message: "Account successfully verified." });
});

// ==========================================
// 3. LOGIN ENDPOINT
// ==========================================
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(401).json({ error: "Invalid credentials." });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.status(401).json({ error: "Invalid credentials." });
    }

    // Set session
    req.session.userId = email;
    res.json({ message: "Logged in successfully", username: user.username });
});

// ==========================================
// 4. OAUTH PLACEHOLDERS (Google, GitHub, Microsoft)
// ==========================================
// To implement these, you must install 'passport' and specific strategy packages 
// (e.g., passport-google-oauth20) and provide your Client IDs and Secrets from those providers.

app.get('/auth/google', (req, res) => {
    res.send("Redirecting to Google OAuth... (Requires Passport.js setup and API keys)");
});

app.get('/auth/github', (req, res) => {
    res.send("Redirecting to GitHub OAuth... (Requires Passport.js setup and API keys)");
});

app.get('/auth/microsoft', (req, res) => {
    res.send("Redirecting to Microsoft OAuth... (Requires Passport.js setup and API keys)");
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
