import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import {
  generateAccessToken,
  verifyToken,
  AuthRequest,
  generateRefreshToken,
} from "./middlewares/jwt.js";

// Configure app
const app = express();
dotenv.config();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Basic routes
app.get("/", (req, res) => {
  res.send("Welcome to the JWT Authentication API!");
});

// Authentication route
app.post("/login", (req, res) => {
  const { email, role } = req.body;

  if (!email || !role) {
    return res.status(400).json({ message: "Email and role are required" });
  }

  if (email === "herman@gmail.com" && role === "admin") {
    const token = generateAccessToken({ email, role });
    const refreshToken = generateRefreshToken({ email, role });
    return res.status(200).json({
      message: "Login successful",
      accessToken: token,
      refreshToken: refreshToken,
    });
  }

  return res.status(401).json({ message: "Invalid credentials" });
});

// Protected route
app.get("/protected", verifyToken, (req: AuthRequest, res) => {
  return res.status(200).json({
    message: "Protected route accessed",
    user: req.user,
  });
});

// Admin-only route
app.get("/admin-only", verifyToken, (req: AuthRequest, res) => {
  if (req.user?.role !== "admin") {
    return res
      .status(403)
      .json({ message: "Access denied: Admin role required" });
  }

  return res.status(200).json({
    message: "Admin area accessed",
    user: req.user,
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
