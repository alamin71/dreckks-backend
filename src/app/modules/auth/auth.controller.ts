// import { Request, Response } from "express";
// import { StatusCodes } from "http-status-codes";
// import catchAsync from "../../../shared/catchAsync";
// import sendResponse from "../../../shared/sendResponse";
// import { AuthService } from "./auth.service";
// import config from "../../../config";

// const verifyEmail = catchAsync(async (req, res) => {
//   const { ...verifyData } = req.body;
//   const result = await AuthService.verifyEmailToDB(verifyData);

//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: result.message,
//     data: { verifyToken: result.verifyToken, accessToken: result.accessToken },
//   });
// });

// const loginUser = catchAsync(async (req, res) => {
//   const { ...loginData } = req.body;
//   const result = await AuthService.loginUserFromDB(loginData);
//   const cookieOptions: any = {
//     secure: false,
//     httpOnly: true,
//     maxAge: 31536000000,
//   };

//   if (config.node_env === "production") {
//     cookieOptions.sameSite = "none";
//   }
//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: "User logged in successfully.",
//     data: {
//       accessToken: result.accessToken,
//       refreshToken: result.refreshToken,
//     },
//   });
// });

// const forgetPassword = catchAsync(async (req, res) => {
//   const email = req.body.email;
//   const result = await AuthService.forgetPasswordToDB(email);

//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message:
//       "Please check your email. We have sent you a one-time passcode (OTP).",
//     data: result,
//   });
// });
// const forgetPasswordByUrl = catchAsync(async (req, res) => {
//   const email = req.body.email;

//   // Call the service function
//   await AuthService.forgetPasswordByUrlToDB(email);

//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: "Please check your email. We have sent you a password reset link.",
//     data: {},
//   });
// });

// const resetPasswordByUrl = catchAsync(async (req, res) => {
//   let token = req?.headers?.authorization?.split(" ")[1];
//   const { ...resetData } = req.body;

//   const result = await AuthService.resetPasswordByUrl(token!, resetData);

//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: "Your password has been successfully reset.",
//     data: result,
//   });
// });
// const resetPassword = catchAsync(async (req, res) => {
//   const token: any = req.headers.resettoken;
//   const { ...resetData } = req.body;
//   const result = await AuthService.resetPasswordToDB(token!, resetData);

//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: "Your password has been successfully reset.",
//     data: result,
//   });
// });

// const changePassword = catchAsync(async (req, res) => {
//   const user: any = req.user;
//   const { ...passwordData } = req.body;
//   const result = await AuthService.changePasswordToDB(user, passwordData);

//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: "Your password has been successfully changed",
//     data: result,
//   });
// });
// // resend Otp
// const resendOtp = catchAsync(async (req, res) => {
//   const { email } = req.body;
//   await AuthService.resendOtpFromDb(email);

//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: "OTP sent successfully again",
//   });
// });

// // refresh token
// const refreshToken = catchAsync(async (req, res) => {
//   const refreshToken = req.headers?.refreshtoken as string;
//   const result = await AuthService.refreshToken(refreshToken);

//   sendResponse(res, {
//     statusCode: StatusCodes.OK,
//     success: true,
//     message: "Access token retrieved successfully",
//     data: result,
//   });
// });
// export const AuthController = {
//   verifyEmail,
//   loginUser,
//   forgetPassword,
//   resetPassword,
//   changePassword,
//   forgetPasswordByUrl,
//   resetPasswordByUrl,
//   resendOtp,
//   refreshToken,
// };
// src/modules/auth/auth.controller.ts
import { Request, Response } from 'express';
import catchAsync from '../../../shared/catchAsync';
import sendResponse from '../../../shared/sendResponse';
import * as AuthService from './auth.service';
import { StatusCodes } from 'http-status-codes';

// Signup (role optional)
export const signup = catchAsync(async (req: Request, res: Response) => {
  const role = req.body.role;
  const result = await AuthService.signup(req.body, role);
  sendResponse(res, { success: true, statusCode: StatusCodes.CREATED, message: result.message, data: result });
});

// Verify OTP (issue tokens)
export const verifyOtp = catchAsync(async (req: Request, res: Response) => {
  const { email, otp } = req.body;
  const result = await AuthService.verifyOtpAndIssueTokens(email, otp);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'OTP verified', data: result });
});

// Login
export const login = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const result = await AuthService.login(email, password);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'Login successful', data: result });
});

// Refresh token
export const refreshToken = catchAsync(async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  const result = await AuthService.refreshAccessToken(refreshToken);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'New access token', data: result });
});

// Resend OTP
export const resendOtp = catchAsync(async (req: Request, res: Response) => {
  const { email } = req.body;
  const result = await AuthService.resendOtp(email);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message || 'OTP resent' });
});

// Forgot password (send OTP)
export const forgotPassword = catchAsync(async (req: Request, res: Response) => {
  const { email } = req.body;
  const result = await AuthService.forgotPassword(email);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
});

// Reset password (OTP)
export const resetPassword = catchAsync(async (req: Request, res: Response) => {
  const { email, otp, newPassword } = req.body;
  const result = await AuthService.resetPasswordWithOtp(email, otp, newPassword);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
});

// Change password (protected)
export const changePassword = catchAsync(async (req: Request, res: Response) => {
  const user = req.user!;
  const { currentPassword, newPassword } = req.body;
  const result = await AuthService.changePassword(user.id, currentPassword, newPassword);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
});