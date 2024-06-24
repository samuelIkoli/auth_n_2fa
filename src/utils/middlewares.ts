const jwt = require("jsonwebtoken");
import { RequestHandler, Request, Response, NextFunction } from "express";
import { Next } from "mysql2/typings/mysql/lib/parsers/typeCast";

const JWT_SECRET = "Lendianite"; // Replace with your actual secret key

export const authenticateToken: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers["authorization"];
  console.log(authHeader);
  const token = req.params.token || (authHeader && authHeader.split(" ")[1]);
  console.log(token);
  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    // req.user = user;
    next();
  } catch (error) {
    res.status(403).json({ message: "Invalid token" });
  }
};
