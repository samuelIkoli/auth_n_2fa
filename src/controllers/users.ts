import express, {
  RequestHandler,
  Request,
  Response,
  NextFunction,
} from "express";
import { knex } from "../knexfile";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Joi from "joi";
import speakeasy from "speakeasy";
import qrcode from "qrcode";

// const {} = process.env;
const JWT_SECRET = "Lendianite";

const userSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  password: Joi.string()
    .min(6)
    .pattern(/(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
    .required()
    .messages({
      "string.pattern.base":
        "Password must contain at least one uppercase letter, one number, and one special character",
    }),
  email: Joi.string().email().required(),
  phone: Joi.string()
    .pattern(/^\d{10}$/)
    .required(), // Validates that the phone is a 10-digit number
});

const loginSchema = Joi.object({
  phone: Joi.string()
    .pattern(/^\d{10}$/)
    .required(), // Validates that the phone is a 10-digit number
  password: Joi.string().required(),
});

const getResponse = (data: object) => {
  return {
    status: "success",
    message: "Information returned successfully",
    data,
  };
};

export const ping = (req: Request, res: Response) => {
  return res.send("Pinging is working");
};

export const getUsers: RequestHandler = async (req: Request, res: Response) => {
  try {
    const users = await knex("users");
    return res.status(200).json(getResponse(users));
  } catch (error) {
    return res.status(500).json({ message: "Error" });
  }
};

export const register: RequestHandler = async (req: Request, res: Response) => {
  const { error } = userSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  const { username, password, email, phone } = req.body;

  if (!username || !password || !email || !phone) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await knex("users")
      .where({ email })
      .orWhere({ phone })
      .first();

    if (existingUser) {
      return res.status(400).json({ message: "Email or phone already in use" });
    }
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    const new_user = await knex("users").insert({
      username,
      password: hashedPassword,
      email,
      phone,
    });

    return res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    return res.status(500).json({ message: "Error registering user" });
  }
};

export const login: RequestHandler = async (req: Request, res: Response) => {
  const { error } = loginSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { phone, password } = req.body;

  try {
    // Find the user in the database
    const user = await knex("users").where({ phone }).first();

    if (!user) {
      return res
        .status(400)
        .json({ message: "Invalid phone number or password" });
    }

    // Compare the hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "Invalid phone number or password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Set the token in an HTTP-only cookie
    res.cookie("token", token, { httpOnly: true, maxAge: 3600000 });
    res.setHeader("Authorization", `Bearer ${token}`);
    // console.log(res);
    return res.status(200).json(
      getResponse({
        id: user.id,
        username: user.username,
        phone: user.phone,
        email: user.email,
        two_fa: user.two_fa,
        token,
      })
    );
  } catch (error) {
    return res.status(500).json({ message: "Error logging in", error });
  }
};

export const setup_2fa = async (req: any, res: Response) => {
  const userId = 2;
  //   console.log(userId);

  try {
    // Generate a secret key for 2FA
    const secret: any = speakeasy.generateSecret({ length: 20 });
    console.log(secret);
    // Save the secret key to the user's record in the database
    await knex("users")
      .where({ id: userId })
      .update({ otp_secret: secret.base32 });

    // Generate a QR code for the user to scan
    // const otpAuthUrl = speakeasy.otpauthURL({
    //   secret: secret.base32,
    //   label: "Samuel Ikoli",
    // });
    const data_url = await qrcode.toDataURL(secret.otpauth_url);
    // console.log(qrCodeDataUrl);
    return res.status(200).json(getResponse({ data_url }));
    // return res.end('<img src="' + data_url + '">');
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error setting up 2FA", error });
  }
};

export const authenticate_otp: RequestHandler = async (req: any, res) => {
  const { otp } = req.body;
  const userId = req.user.id || 2;

  try {
    // Get the user's 2FA secret from the database
    const user = await knex("users").where({ id: userId }).first();

    if (!user || !user.otp_secret) {
      return res.status(400).json({ message: "2FA not set up" });
    }

    // Verify the token
    const isVerified = speakeasy.totp.verify({
      secret: user.otp_secret,
      encoding: "base32",
      token: otp,
    });

    if (!isVerified) {
      return res.status(400).json({ message: "Invalid 2FA token" });
    }

    const two_fa = await knex("users").update({ two_fa: 1 });

    if (!two_fa) {
      return res.status(400).json({ message: "Invalid 2FA token" });
    }

    // Generate a JWT for full session after 2FA verification
    //   const fullSessionToken = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

    // Set the token in the Authorization header
    //   res.setHeader('Authorization', `Bearer ${fullSessionToken}`);

    res.status(200).json({ message: "2FA verified and login successful" });
  } catch (error) {
    res.status(500).json({ message: "Error verifying 2FA", error });
  }
};
