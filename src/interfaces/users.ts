import Joi from "joi";

export const userSchema = Joi.object({
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

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

export const otpSchema = Joi.object({
  otp: Joi.number().min(6).max(6).required(),
  user_id: Joi.number().required(),
});
