
import { z } from "zod";

// Signup
const createSignupZodSchema = z.object({
  name: z.string().nonempty({ message: "Name is required" }),
  email: z.string().email({ message: "Valid email is required" }),
  password: z.string().min(6, { message: "Password must be at least 6 characters" }),
  role: z.string().optional(),
  profileData: z.record(z.string(), z.any()).optional(),
});

// Verify OTP
const createVerifyOtpZodSchema = z.object({
  email: z.string().email({ message: "Valid email is required" }),
  otp: z.string().length(6, { message: "OTP must be 6 digits" }),
});

// Login
const createLoginZodSchema = z.object({
  email: z.string().email({ message: "Valid email is required" }),
  password: z.string().nonempty({ message: "Password is required" }),
});

// Refresh token
const createRefreshTokenZodSchema = z.object({
  refreshToken: z.string().nonempty({ message: "Refresh token is required" }),
});

// Resend OTP
const createResendOtpZodSchema = z.object({
  email: z.string().email({ message: "Valid email is required" }),
});

// Forgot password
const createForgotPasswordZodSchema = z.object({
  email: z.string().email({ message: "Valid email is required" }),
});

// Reset password (with OTP)
const createResetPasswordZodSchema = z.object({
  email: z.string().email({ message: "Valid email is required" }),
  otp: z.string().length(6, { message: "OTP must be 6 digits" }),
  newPassword: z.string().min(6, { message: "Password must be at least 6 characters" }),
  confirmPassword: z.string().min(6, { message: "Confirm password must be at least 6 characters" }),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"],
});

// Change password (protected)
const createChangePasswordZodSchema = z.object({
  currentPassword: z.string().nonempty({ message: "Current password is required" }),
  newPassword: z.string().min(6, { message: "Password must be at least 6 characters" }),
  confirmPassword: z.string().min(6, { message: "Confirm password must be at least 6 characters" }),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"],
});

export const AuthValidation = {
  createSignupZodSchema,
  createVerifyOtpZodSchema,
  createLoginZodSchema,
  createRefreshTokenZodSchema,
  createResendOtpZodSchema,
  createForgotPasswordZodSchema,
  createResetPasswordZodSchema,
  createChangePasswordZodSchema,
};
