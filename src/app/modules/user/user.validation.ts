// import { string, z } from "zod";

// export const createUserZodSchema = z.object({
//   body: z.object({
//     name: z
//       .string({ required_error: "Name is required" })
//       .min(2, "Name must be at least 2 characters long"),
//     email: z
//       .string({ required_error: "Email is required" })
//       .email("Invalid email address"),

//     password: z
//       .string({ required_error: "Password is required" })
//       .min(8, "Password must be at least 8 characters long"),
//     phone: string().default("").optional(),
//     profile: z.string().optional(),
//   }),
// });

// const createBusinessUserZodSchema = z.object({
//   body: z.object({
//     name: z.string({ required_error: "Name is required" }),
//     phone: z.string({ required_error: "Contact is required" }),
//     email: z
//       .string({ required_error: "Email is required" })
//       .email("Invalid email address"),
//     password: z
//       .string({ required_error: "Password is required" })
//       .min(8, "Password must be at least 8 characters long"),
//     profile: z.string().optional(),
//   }),
// });

// const updateUserZodSchema = z.object({
//   body: z.object({
//     name: z.string().optional(),
//     contact: z.string().optional(),
//     address: z.string().optional(),
//     email: z.string().email("Invalid email address").optional(),
//     password: z.string().optional(),
//     image: z.string().optional(),
//   }),
// });

// export const UserValidation = {
//   createUserZodSchema,
//   updateUserZodSchema,
//   createBusinessUserZodSchema,
// };
import { string, z, ZodIssueCode } from "zod";

export const createUserZodSchema = z.object({
  body: z.object({
    name: z
      .string()
      .min(2, { message: "Name must be at least 2 characters long" })
      .nonempty({ message: "Name is required" }),
    email: z
      .string()
      .nonempty({ message: "Email is required" })
      .email("Invalid email address"),
    password: z
      .string()
      .min(8, { message: "Password must be at least 8 characters long" })
      .nonempty({ message: "Password is required" }),
    phone: string().default("").optional(),
    profile: z.string().optional(),
  }),
});

const createBusinessUserZodSchema = z.object({
  body: z.object({
    name: z.string().nonempty({ message: "Name is required" }),
    phone: z.string().nonempty({ message: "Contact is required" }),
    email: z
      .string()
      .nonempty({ message: "Email is required" })
      .email("Invalid email address"),
    password: z
      .string()
      .min(8, { message: "Password must be at least 8 characters long" })
      .nonempty({ message: "Password is required" }),
    profile: z.string().optional(),
  }),
});

const updateUserZodSchema = z.object({
  body: z.object({
    name: z.string().optional(),
    contact: z.string().optional(),
    address: z.string().optional(),
    email: z.string().email("Invalid email address").optional(),
    password: z.string().optional(),
    image: z.string().optional(),
  }),
});

export const UserValidation = {
  createUserZodSchema,
  updateUserZodSchema,
  createBusinessUserZodSchema,
};
