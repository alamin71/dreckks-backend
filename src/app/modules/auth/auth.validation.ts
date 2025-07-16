import { z } from "zod";

const createVerifyEmailZodSchema = z.object({
  email: z.string().nonempty({ message: "Email is required" }),
  oneTimeCode: z.preprocess(
    (val) => Number(val),
    z.number().int().nonnegative({ message: "One time code is required" })
  ),
});

const createLoginZodSchema = z.object({
  email: z.string().nonempty({ message: "Email is required" }),
  password: z.string().nonempty({ message: "Password is required" }),
});

const createForgetPasswordZodSchema = z.object({
  email: z.string().nonempty({ message: "Email is required" }),
});

const createResetPasswordZodSchema = z.object({
  newPassword: z.string().nonempty({ message: "Password is required" }),
  confirmPassword: z
    .string()
    .nonempty({ message: "Confirm Password is required" }),
});

const createChangePasswordZodSchema = z.object({
  currentPassword: z
    .string()
    .nonempty({ message: "Current Password is required" }),
  newPassword: z.string().nonempty({ message: "New Password is required" }),
  confirmPassword: z
    .string()
    .nonempty({ message: "Confirm Password is required" }),
});

export const AuthValidation = {
  createVerifyEmailZodSchema,
  createForgetPasswordZodSchema,
  createLoginZodSchema,
  createResetPasswordZodSchema,
  createChangePasswordZodSchema,
};
