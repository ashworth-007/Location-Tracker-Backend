
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config(); 


const app = express();
app.use(express.json());
app.use(cors());

// Environment Variables
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;


mongoose
  .connect(MONGO_URI, { })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error(err));


const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" }, 
});

const locationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  latitude: Number,
  longitude: Number,
  timestamp: { type: Date, default: Date.now },
});


const User = mongoose.model("User", userSchema);
const Location = mongoose.model("Location", locationSchema);


const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Access Denied");
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send("Invalid Token");
    req.user = user;
    next();
  });
};


const createAdminUser = async () => {
  const adminEmail = "admin@gmail.com";
  const adminPassword = "123456789";

 
  const existingAdmin = await User.findOne({ email: adminEmail });
  if (existingAdmin) {
    console.log("Admin user already exists");
    return;
  }

 
  const hashedPassword = await bcrypt.hash(adminPassword, 10);

 
  const adminUser = new User({
    name: "Admin",
    email: adminEmail,
    password: hashedPassword,
    role: "admin", 
  });

  
  await adminUser.save();
  console.log("Admin user created successfully");
};


createAdminUser();


app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.status(201).send("User registered successfully");
  } catch (err) {
    res.status(400).send("Error registering user");
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
      res.json({ token });
    } else {
      res.status(400).send("Invalid credentials");
    }
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// Save location
// app.post("/location", authenticateToken, async (req, res) => {
//   const { latitude, longitude } = req.body;
//   try {
//     const location = new Location({ userId: req.user.id, latitude, longitude });
//     await location.save();
//     res.status(200).send("Location saved");
//   } catch (err) {
//     res.status(500).send("Server error");
//   }
// });
app.post("/location", authenticateToken, async (req, res) => {
  const { latitude, longitude } = req.body;
  const userId = req.user.id; // Now req.user will be populated by authenticateToken

  // Log the location data to ensure it's received
  console.log(`Received location: ${latitude}, ${longitude} for user ${userId}`);

  // Save the location to the database
  const newLocation = new Location({
    userId,
    latitude,
    longitude,
    timestamp: Date.now(),
  });

  try {
    await newLocation.save();
    res.status(200).send("Location saved successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error saving location");
  }
});



// Get all users (Admin only)
app.get("/admin/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).send("Access Denied");
  try {
    const users = await User.find({}, "-password");
    res.json(users);
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// Get location logs for a user (Admin only)
app.get("/admin/users/:id/locations", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).send("Access Denied");
  try {
    const locations = await Location.find({ userId: req.params.id });
    res.json(locations);
  } catch (err) {
    res.status(500).send("Server error");
  }
});


app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
