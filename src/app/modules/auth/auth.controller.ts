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
// import { Request, Response } from 'express';
// import catchAsync from '../../../shared/catchAsync';
// import sendResponse from '../../../shared/sendResponse';
// import * as AuthService from './auth.service';
// import { StatusCodes } from 'http-status-codes';

// // Signup (role optional)
// export const signup = catchAsync(async (req: Request, res: Response) => {
//   const role = req.body.role;
//   const result = await AuthService.signup(req.body, role);
//   sendResponse(res, { 
//     success: true, statusCode: StatusCodes.CREATED, message: result.message, data: result });
// });

// // Verify OTP (issue tokens)
// export const verifyOtp = catchAsync(async (req: Request, res: Response) => {
//   const { email, otp } = req.body;
//   const result = await AuthService.verifyOtpAndIssueTokens(email, otp);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'OTP verified', data: result });
// });

// // Login
// export const login = catchAsync(async (req: Request, res: Response) => {
//   const { email, password } = req.body;
//   const result = await AuthService.login(email, password);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'Login successful', data: result });
// });

// // Refresh token
// export const refreshToken = catchAsync(async (req: Request, res: Response) => {
//   const { refreshToken } = req.body;
//   const result = await AuthService.refreshAccessToken(refreshToken);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'New access token', data: result });
// });

// // Resend OTP
// export const resendOtp = catchAsync(async (req: Request, res: Response) => {
//   const { email } = req.body;
//   const result = await AuthService.resendOtp(email);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message || 'OTP resent' });
// });

// // Forgot password (send OTP)
// export const forgotPassword = catchAsync(async (req: Request, res: Response) => {
//   const { email } = req.body;
//   const result = await AuthService.forgotPassword(email);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
// });

// // Reset password (OTP)
// export const resetPassword = catchAsync(async (req: Request, res: Response) => {
//   const { email, otp, newPassword } = req.body;
//   const result = await AuthService.resetPasswordWithOtp(email, otp, newPassword);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
// });

// // Change password (protected)
// export const changePassword = catchAsync(async (req: Request, res: Response) => {
//   const user = req.user!;
//   const { currentPassword, newPassword } = req.body;
//   const result = await AuthService.changePassword(user.id, currentPassword, newPassword);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
// });

// import { Request, Response } from 'express';
// import catchAsync from '../../../shared/catchAsync';
// import sendResponse from '../../../shared/sendResponse';
// import * as AuthService from './auth.service';
// import { StatusCodes } from 'http-status-codes';

// // Signup
// export const signupInitController = catchAsync(async (req: Request, res: Response) => {
//   const result = await AuthService.signupInit(req.body);
//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.CREATED,
//     message: result.message,
//     data: { signupToken: result.signupToken, expiresIn: result.expiresIn, ...(process.env.NODE_ENV === 'development' && { otp: result.otp }) },
//   });
// });

// export const signupVerifyOtpController = catchAsync(async (req: Request, res: Response) => {
//   const token = req.headers.token as string;
//   const { otp } = req.body;
//   const result = await AuthService.signupVerifyOtp(token, otp);
//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: result.message,
//     data: { accessToken: result.accessToken, refreshToken: result.refreshToken, user: result.user },
//   });
// });

// // Login
// export const login = catchAsync(async (req: Request, res: Response) => {
//   const { email, password } = req.body;
//   const result = await AuthService.login(email, password);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message, data: result });
// });

// // Refresh token
// export const refreshToken = catchAsync(async (req: Request, res: Response) => {
//   const { refreshToken } = req.body;
//   const result = await AuthService.refreshAccessToken(refreshToken);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'New access token', data: result });
// });

// // Resend OTP
// export const resendSignupOtp = catchAsync(async (req: Request, res: Response) => {
//   const signupToken = req.headers['x-signup-token'] as string;
//   const result = await AuthService.resendSignupOtp(signupToken);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message, data: result });
// });

// // Forgot password
// export const forgotPassword = catchAsync(async (req: Request, res: Response) => {
//   const { email } = req.body;
//   const result = await AuthService.forgotPassword(email);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message, data: result });
// });

// // Reset password
// export const resetPassword = catchAsync(async (req: Request, res: Response) => {
//   const { email, otp, newPassword } = req.body;
//   const result = await AuthService.resetPasswordWithOtp(email, otp, newPassword);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
// });

// // Change password
// export const changePassword = catchAsync(async (req: Request, res: Response) => {
//   const user = req.user!;
//   const { currentPassword, newPassword } = req.body;
//   const result = await AuthService.changePassword(user.id, currentPassword, newPassword);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
// });
// import { Request, Response } from 'express';
// import catchAsync from '../../../shared/catchAsync';
// import sendResponse from '../../../shared/sendResponse';
// import * as AuthService from './auth.service';
// import { StatusCodes } from 'http-status-codes';
// import AppError from '../../../errors/AppError';

// // -------------------- Signup --------------------
// export const signupInitController = catchAsync(async (req: Request, res: Response) => {
//   const result = await AuthService.signupInit(req.body);
//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.CREATED,
//     message: result.message,
//     data: { email: result.email, role: result.role, profileData: result.profileData, ...(process.env.NODE_ENV === 'development' && { otp: result.otp }) },
//   });
// });

// export const signupVerifyOtpController = catchAsync(async (req: Request, res: Response) => {
//   const { email, otp } = req.body;
//   if (!email || !otp) throw new AppError(StatusCodes.BAD_REQUEST, 'Email and OTP are required');

//   const result = await AuthService.signupVerifyOtp(email, otp);
//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: 'OTP verified successfully',
//     data: result,
//   });
// });

// // --------------------Resend OTP --------------------
// export const resendSignupOtp = catchAsync(async (req: Request, res: Response) => {
//   const signupToken = req.headers['x-signup-token'] as string;
//   if (!signupToken) throw new AppError(400, 'Signup token missing');

//   const result = await AuthService.resendSignupOtp(signupToken);

//   sendResponse(res, {
//     success: true,
//     statusCode: StatusCodes.OK,
//     message: result.message,
//     data: result,
//   });
// });


// // -------------------- Login --------------------
// export const loginController = catchAsync(async (req: Request, res: Response) => {
//   const { email, password } = req.body;
//   const result = await AuthService.login(email, password);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message, data: result });
// });

// // -------------------- Refresh Token --------------------
// export const refreshTokenController = catchAsync(async (req: Request, res: Response) => {
//   const { refreshToken } = req.body;
//   const result = await AuthService.refreshAccessToken(refreshToken);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'New access token', data: result });
// });

// // -------------------- Forgot Password --------------------
// export const forgotPasswordController = catchAsync(async (req: Request, res: Response) => {
//   const { email } = req.body;
//   const result = await AuthService.forgotPassword(email);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message, ...(process.env.NODE_ENV === 'development' && { otp: result.otp }) });
// });

// // -------------------- Verify Forgot Password OTP --------------------
// export const verifyForgotPasswordOtpController = catchAsync(async (req: Request, res: Response) => {
//   const { email, otp } = req.body;
//   const result = await AuthService.verifyForgotPasswordOtp(email, otp);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'OTP verified', data: { resetToken: result.resetToken } });
// });

// // -------------------- Reset Password --------------------
// export const resetPasswordController = catchAsync(async (req: Request, res: Response) => {
//   const resetToken = req.headers['x-reset-token'] as string;
//   const { newPassword, confirmPassword } = req.body;

//   if (!newPassword || !confirmPassword) throw new AppError(StatusCodes.BAD_REQUEST, 'Both passwords are required');
//   if (newPassword !== confirmPassword) throw new AppError(StatusCodes.BAD_REQUEST, 'Passwords do not match');

//   const result = await AuthService.resetPasswordWithToken(resetToken, newPassword);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
// });

// // -------------------- Change Password --------------------
// export const changePasswordController = catchAsync(async (req: Request, res: Response) => {
//   const user = req.user!;
//   const { oldPassword, newPassword, confirmPassword } = req.body;

//   if (!oldPassword || !newPassword || !confirmPassword) throw new AppError(StatusCodes.BAD_REQUEST, 'All fields are required');
//   if (newPassword !== confirmPassword) throw new AppError(StatusCodes.BAD_REQUEST, 'Passwords do not match');

//   const result = await AuthService.changePassword(user.id, oldPassword, newPassword);
//   sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message });
// });
import { Request, Response } from 'express';
import catchAsync from '../../../shared/catchAsync';
import sendResponse from '../../../shared/sendResponse';
import * as AuthService from './auth.service';
import { StatusCodes } from 'http-status-codes';
import AppError from '../../../errors/AppError';

// -------------------- Signup --------------------
export const signupInitController = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthService.signupInit(req.body);
  sendResponse(res, {
    success: true,
    statusCode: StatusCodes.CREATED,
    message: result.message,
    data: { 
      email: result.email, 
      role: result.role, 
      profileData: result.profileData, 
      signupToken: result.signupToken,
      ...(process.env.NODE_ENV === 'development' && { otp: result.otp })
    },
  });
});

export const signupVerifyOtpController = catchAsync(async (req: Request, res: Response) => {
  const signupToken = req.headers['x-signup-token'] as string;
  if (!signupToken) throw new AppError(StatusCodes.BAD_REQUEST, 'Signup token missing');

  const decoded = AuthService.verifySignupToken(signupToken);
  const { otp } = req.body;
  if (!otp) throw new AppError(StatusCodes.BAD_REQUEST, 'OTP is required');

  const result = await AuthService.signupVerifyOtp(decoded.email, otp);
  sendResponse(res, {
    success: true,
    statusCode: StatusCodes.OK,
    message: 'OTP verified successfully',
    data: result,
  });
});

// -------------------- Resend OTP --------------------
export const resendSignupOtp = catchAsync(async (req: Request, res: Response) => {
  const signupToken = req.headers['x-signup-token'] as string;
  if (!signupToken) throw new AppError(StatusCodes.BAD_REQUEST, 'Signup token missing');

  const result = await AuthService.resendSignupOtp(signupToken);
  sendResponse(res, {
    success: true,
    statusCode: StatusCodes.OK,
    message: result.message,
    data: result,
  });
});

// -------------------- Login --------------------
export const loginController = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const result = await AuthService.login(email, password);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: result.message, data: result });
});

// -------------------- Refresh Token --------------------
export const refreshTokenController = catchAsync(async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  const result = await AuthService.refreshAccessToken(refreshToken);
  sendResponse(res, { success: true, statusCode: StatusCodes.OK, message: 'New access token', data: result });
});

// -------------------- Forgot Password --------------------
// -------------------- Forgot Password --------------------
export const forgotPasswordController = catchAsync(async (req: Request, res: Response) => {
  const { email } = req.body;
  const result = await AuthService.forgotPassword(email);

  // Response with OTP in dev environment
  sendResponse(res, {
    success: true,
    statusCode: StatusCodes.OK,
    message: 'OTP sent to email',
    data: result, // { otp } included in dev
  });
});

// -------------------- Verify Forgot Password OTP --------------------
export const verifyForgotPasswordOtpController = catchAsync(async (req: Request, res: Response) => {
  const { otp } = req.body; // only otp in body
  const { email } = req.query as { email: string }; // email passed as query param

  const { resetToken } = await AuthService.verifyForgotPasswordOtp(email, otp);

  // Set reset token in headers
  res.setHeader('x-reset-token', resetToken);

  sendResponse(res, {
    success: true,
    statusCode: StatusCodes.OK,
    message: 'OTP verified successfully. You can now reset your password.',
  });
});

// -------------------- Reset Password --------------------
export const resetPasswordController = catchAsync(async (req: Request, res: Response) => {
  const resetToken = req.headers['x-reset-token'] as string;
  const { newPassword, confirmPassword } = req.body;

  if (!newPassword || !confirmPassword) 
    throw new AppError(StatusCodes.BAD_REQUEST, 'All fields are required');

  if (newPassword !== confirmPassword) 
    throw new AppError(StatusCodes.BAD_REQUEST, 'Passwords do not match');

  await AuthService.resetPasswordWithToken(resetToken, newPassword, confirmPassword);

  sendResponse(res, {
    success: true,
    statusCode: StatusCodes.OK,
    message: 'Password reset successfully. Please login.',
  });
});



// -------------------- Change Password --------------------
export const changePasswordController = catchAsync(async (req: Request, res: Response) => {
  const user = req.user!;
  const { oldPassword, newPassword, confirmPassword } = req.body;

  if (!oldPassword || !newPassword || !confirmPassword) throw new AppError(StatusCodes.BAD_REQUEST, 'All fields are required');
  if (newPassword !== confirmPassword) throw new AppError(StatusCodes.BAD_REQUEST, 'Passwords do not match');

  const result = await AuthService.changePassword(user.id, oldPassword, newPassword);

  sendResponse(res, {
    success: true,
    statusCode: StatusCodes.OK,
    message: result.message,
  });
});
