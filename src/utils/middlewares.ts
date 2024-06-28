import jwt from "jsonwebtoken";
import { RequestHandler, Request, Response, NextFunction } from "express";
import { Next } from "mysql2/typings/mysql/lib/parsers/typeCast";
import dotenv from "dotenv";
dotenv.config();

export const authenticateToken: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.log(process.env.JWT_SECRET);
  const authHeader = req.headers["authorization"];
  const token = req.params.token || (authHeader && authHeader.split(" ")[1]);
  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || "null");
    // req.user = user;
    next();
  } catch (error) {
    res.status(403).json({ message: "Invalid token" });
  }
};
