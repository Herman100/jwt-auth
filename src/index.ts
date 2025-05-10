import express, { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import {
  generateAccessToken,
  verifyToken,
  generateRefreshToken,
  verifyRefreshToken,
} from "./middlewares/jwt.js";
import { RequestWithCookies } from "./types/cookies.js";
import { AuthRequest } from "./types/jwt.js";
import logger from "../logger.js";
import morganMiddleware from "./middlewares/morganHelper.js";

// Configure app
const app = express();
dotenv.config();
const PORT = process.env.PORT || 3000;

app.use(morganMiddleware);

// Middleware
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());

// Basic routes
app.get("/", (req: Request, res: Response) => {
  res.send("Welcome to the JWT Authentication API!");
});

// Authentication route
app.post("/login", (req: Request, res: Response) => {
  const { email, role } = req.body;

  if (!email || !role) {
    return res.status(400).json({ message: "Email and role are required" });
  }

  if (email === "herman@gmail.com" && role === "admin") {
    const token = generateAccessToken({ email, role });
    const refreshToken = generateRefreshToken({ email, role });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // secure in production
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: "/",
    });

    return res.status(200).json({
      message: "Login successful",
      accessToken: token,
    });
  }

  return res.status(401).json({ message: "Invalid credentials" });
});

app.post("/token-refresh", (req: RequestWithCookies, res: Response) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token required" });
  }

  const user = verifyRefreshToken(refreshToken);
  if (!user) {
    return res.status(403).json({ message: "Invalid refresh token" });
  }

  const newAccessToken = generateAccessToken({
    email: user.email,
    role: user.role,
  });

  return res.status(200).json({
    message: "New access token generated",
    accessToken: newAccessToken,
  });
});

// Protected route
app.get("/protected", verifyToken, (req: AuthRequest, res: Response) => {
  return res.status(200).json({
    message: "Protected route accessed",
    user: req.user,
  });
});

// Admin-only route
app.get("/admin-only", verifyToken, (req: AuthRequest, res: Response) => {
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
