import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { generateToken, verifyToken, AuthRequest } from "./middlewares/jwt.js";

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

  // Here you would normally validate the user credentials with a database
  if (!email || !role) {
    return res.status(400).json({ message: "Email and role are required" });
  }

  if (email === "herman@gmail.com" && role === "admin") {
    // Generate a token if the credentials are valid
    const token = generateToken({ email, role });
    return res.status(200).json({ token });
  }

  return res.status(401).json({ message: "Invalid credentials" });
});

// Protected route - using middleware correctly
app.get("/protected", verifyToken, (req: AuthRequest, res) => {
  // This will only execute if the token is valid
  // Access user data from the request object
  return res.status(200).json({
    message: "Protected route accessed",
    user: req.user,
  });
});

// Another protected route example with role check
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
