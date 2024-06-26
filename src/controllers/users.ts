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
    .pattern(/^\d{11}$/)
    .required(), // Validates that the phone is a 11-digit number
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
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
    const users = await knex("users").select(
      "id",
      "username",
      "email",
      "phone",
      "two_fa"
    );
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

  const { email, password } = req.body;

  try {
    // Find the user in the database
    const user = await knex("users").where({ email }).first();

    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Compare the hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Set the token in an HTTP-only cookie
    res.cookie("token", token, { httpOnly: true, maxAge: 3600000 });
    res.setHeader("Authorization", `Bearer ${token}`);
    console.log(JSON.stringify(req.signedCookies));
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
  const user_id: string = req.query.user_id;
  const id = parseInt(user_id);
  if (!user_id || Number.isNaN(id)) {
    return res.status(400).json({
      message: "There is no userID or userID can not be parsed to a number",
    });
  }
  if (id <= 0) {
    return res
      .status(400)
      .json({ message: "User ID should be a positive integer" });
  }
  try {
    const user = await knex("users").where({ id }).first();
    let data_url;
    if (!user?.otp_secret || !user?.auth_url || !user?.two_fa) {
      // Generate a secret key for 2FA
      const secret: any = speakeasy.generateSecret({ length: 20 });
      data_url = await qrcode.toDataURL(secret.otpauth_url);
      const update = await knex("users")
        .where({ id: user_id })
        .update({ otp_secret: secret.base32 });
      const update2 = await knex("users")
        .where({ id: user_id })
        .update({ auth_url: secret.otpauth_url });
    } else {
      data_url = await qrcode.toDataURL(user.auth_url);
    }

    return res.status(200).json(getResponse({ data_url }));
    // return res.end('<img src="' + data_url + '">');
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error setting up 2FA", error });
  }
};

export const authenticate_otp: RequestHandler = async (req: any, res) => {
  const { otp, user_id } = req.body;
  console.log(otp);
  //   const userId = req.body.user_id || 2;

  try {
    // Get the user's 2FA secret from the database
    const user = await knex("users").where({ id: user_id }).first();

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

    const two_fa = await knex("users")
      .where({ id: user_id })
      .update({ two_fa: 1 });

    if (!two_fa) {
      return res
        .status(400)
        .json({ message: "Invalid 2FA token after update" });
    }

    res.status(200).json({ message: "2FA verified and login successful" });
  } catch (error) {
    res.status(500).json({ message: "Error verifying 2FA", error });
  }
};

export const showReq: RequestHandler = async (req, res) => {
  //   const authHeader = req.headers["authorization"];
  //   console.log(req.cookies);
  //   const token = authHeader && authHeader.split(" ")[1];
  //   console.log(token);
  console.log(JSON.stringify(req.signedCookies));
  console.log(JSON.stringify(req.cookies));
  return res.status(200).json({ message: "success", data: null });
};
