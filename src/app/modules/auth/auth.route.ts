

// import express from 'express';
// import * as AuthController from './auth.controller';
// import { AuthValidation } from './auth.validation';
// import validateRequest from '../../middleware/validateRequest'; 

// const router = express.Router();

// router.post('/signup', validateRequest(AuthValidation.createSignupZodSchema), AuthController.signup);
// router.post('/verify-otp', validateRequest(AuthValidation.createVerifyOtpZodSchema), AuthController.verifyOtp);
// router.post('/login', validateRequest(AuthValidation.createLoginZodSchema), AuthController.login);
// router.post('/refresh-token', validateRequest(AuthValidation.createRefreshTokenZodSchema), AuthController.refreshToken);
// router.post('/resend-otp', validateRequest(AuthValidation.createResendOtpZodSchema), AuthController.resendOtp);
// router.post('/forgot-password', validateRequest(AuthValidation.createForgotPasswordZodSchema), AuthController.forgotPassword);
// router.patch('/reset-password', validateRequest(AuthValidation.createResetPasswordZodSchema), AuthController.resetPassword);
// router.post('/change-password', validateRequest(AuthValidation.createChangePasswordZodSchema), AuthController.changePassword);

// export default router;
import express from 'express';
import * as AuthController from './auth.controller';
import { AuthValidation } from './auth.validation';
import validateRequest from '../../middleware/validateRequest';

const router = express.Router();

// Signup
router.post('/signup/init', validateRequest(AuthValidation.createSignupZodSchema), AuthController.signupInitController);
router.post('/verify-otp', validateRequest(AuthValidation.createVerifyOtpZodSchema), AuthController.signupVerifyOtpController);
router.post('/resend-otp', AuthController.resendSignupOtp);

// Login
router.post('/login', validateRequest(AuthValidation.createLoginZodSchema), AuthController.loginController);
router.post('/refresh-token', validateRequest(AuthValidation.createRefreshTokenZodSchema), AuthController.refreshTokenController);

// Forgot / Reset / Change Password
router.post('/forgot-password', validateRequest(AuthValidation.createForgotPasswordZodSchema), AuthController.forgotPasswordController);
router.post('/verify-forgot-password-otp', validateRequest(AuthValidation.createForgotPasswordZodSchema), AuthController.verifyForgotPasswordOtpController);
router.patch('/reset-password', validateRequest(AuthValidation.createResetPasswordZodSchema), AuthController.resetPasswordController);
router.post('/change-password', validateRequest(AuthValidation.createChangePasswordZodSchema), AuthController.changePasswordController);

export default router;
