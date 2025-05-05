import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

const app = express();
dotenv.config();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.sendStatus(200).send("Welcome to the JWT Authentication API!");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
