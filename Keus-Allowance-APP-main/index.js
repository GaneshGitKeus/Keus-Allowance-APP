const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require("path");
const fs = require("fs");

const sopFilePath = path.join(__dirname,"data", "sops.json");
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

const corsOptions = {
  origin: [
    "http://localhost:3000", // React Web (local)
    "capacitor://localhost", // Capacitor Mobile App
    "ionic://localhost", // Ionic Mobile App
    "https://yourfrontend.com" // Deployed frontend (Replace with actual URL)
  ],
  credentials: true, // Allow cookies/auth headers
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], 
  allowedHeaders: ["Content-Type", "Authorization"],
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// Ensure OPTIONS requests are handled
app.options("*", cors(corsOptions));

// Connect to MongoDB
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  designation: { type: String, default: "" },
  empid: { type: String, default: "" },
  phone: { type: String, default: "" },
  expenses: [
    {
      clientName: String,
      leadId: String,
      purpose: String,
      from: String,
      to: String,
      date: Date,
      distance: Number,
      restaurant: String,
      amount: Number,
      persons: Number,
      team: String,
      otherPurpose: String,
      otherAmount: Number
    }
  ]
});

const User = mongoose.model('User', UserSchema);

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, designation, empid, phone } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword, designation, empid, phone, expenses: [] });
    await newUser.save();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { emailOrEmpid, password } = req.body;

    const user = await User.findOne({
      $or: [{ email: emailOrEmpid }, { empid: emailOrEmpid }]
    });

    if (!user) return res.status(400).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.cookie('token', token, { httpOnly: true, sameSite: 'none', secure: true });
    res.json({ message: 'Login successful', user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'none', secure: true, });
  res.json({ message: 'Logged out successfully' });
});


// Get User Data
app.get('/api/user', async (req, res) => {
  try {
    const token =
      req.cookies.token ||
      req.headers.authorization?.split(" ")[1]; // ✅ support header

    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/user/change-password', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { oldPassword, newPassword } = req.body;
    console.log(oldPassword, newPassword);
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Old and new passwords are required' });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Old password is incorrect' });

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get("/api/expense/:userId/:expenseId", async (req, res) => {
  try {
    const { userId, expenseId } = req.params;

    // Find the user and filter out the specific expense
    const user = await User.findOne(
      { _id: userId, "expenses._id": expenseId },
      { "expenses.$": 1 } // `$` returns only the matching expense
    );

    if (!user || user.expenses.length === 0) {
      return res.status(404).json({ error: "Expense not found" });
    }

    res.json(user.expenses[0]); // Return the matched expense
  } catch (err) {
    res.status(500).json({ error: "Error fetching expense" });
  }
});


// **Update User Data**
app.put('/api/user/update', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const { name, designation, empid, email, phone } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      decoded.userId,
      { name, designation, empid, email, phone },
      { new: true }
    );

    res.json({ message: "Profile updated successfully", user: updatedUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add Expense
app.post('/api/expense', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    const newExpense = {
      clientName: req.body.clientName,
      leadId: req.body.leadId,
      purpose: req.body.purpose,
      from: req.body.from,
      to: req.body.to,
      date: req.body.date,
      distance: req.body.distance,
      restaurant: req.body.restaurant,
      amount: req.body.amount,
      persons: req.body.persons,
      team: req.body.team,
      otherPurpose: req.body.otherPurpose,
      otherAmount: req.body.otherAmount
    };

    user.expenses.push(newExpense);
    await user.save();

    res.json({ message: 'Expense added', expenses: user.expenses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Edit Expense
app.put('/api/expense/:expenseId', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) return res.status(404).json({ error: 'User not found' });

    const expense = user.expenses.id(req.params.expenseId);
    if (!expense) return res.status(404).json({ error: 'Expense not found' });

    Object.assign(expense, req.body); // Update expense with request data
    await user.save();

    res.json({ message: 'Expense updated', expenses: user.expenses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/expense/food/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const updatedExpense = await User.findOneAndUpdate(
      { "expenses._id": id },
      {
        $set: {
          "expenses.$.restaurant": req.body.restaurant || "",
          "expenses.$.amount": req.body.amount || 0,
          "expenses.$.persons": req.body.persons || 0,
          "expenses.$.team": req.body.team || ""
        }
      },
      { new: true }
    );

    if (!updatedExpense) {
      return res.status(404).json({ error: "Food expense not found" });
    }

    res.json(updatedExpense);
  } catch (err) {
    console.error("Error updating food expense:", err);
    res.status(500).json({ error: "Error updating food expense" });
  }
});


app.put("/api/expense/otherexpense/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const updatedExpense = await User.findOneAndUpdate(
      { "expenses._id": id },
      {
        $set: {
          "expenses.$.otherPurpose": "",
          "expenses.$.otherAmount": 0
        }
      },
      { new: true }
    );

    if (!updatedExpense) {
      return res.status(404).json({ error: "Food expense not found" });
    }

    res.json(updatedExpense);
  } catch (err) {
    console.error("Error updating food expense:", err);
    res.status(500).json({ error: "Error updating food expense" });
  }
});


// Delete Expense
app.delete("/api/expense/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findOneAndUpdate(
      { "expenses._id": id },
      { $pull: { expenses: { _id: id } } }, // Remove entire expense record
      { new: true }
    );
    res.json({ message: "Expense deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Error deleting expense" });
  }
});

// Get SOPs
app.get("/api/sop", (req, res) => {
  try {
    const data = fs.readFileSync(sopFilePath, "utf-8");
    const sops = JSON.parse(data);
    res.json(sops);
  } catch (err) {
    res.status(500).json({ error: "Failed to load SOPs" });
  }
});


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
