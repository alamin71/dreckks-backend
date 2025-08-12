

import express from 'express';
import * as AuthController from './auth.controller';
import { AuthValidation } from './auth.validation';
import validateRequest from '../../middleware/validateRequest'; 

const router = express.Router();

router.post('/signup', validateRequest(AuthValidation.createSignupZodSchema), AuthController.signup);
router.post('/verify-otp', validateRequest(AuthValidation.createVerifyOtpZodSchema), AuthController.verifyOtp);
router.post('/login', validateRequest(AuthValidation.createLoginZodSchema), AuthController.login);
router.post('/refresh-token', validateRequest(AuthValidation.createRefreshTokenZodSchema), AuthController.refreshToken);
router.post('/resend-otp', validateRequest(AuthValidation.createResendOtpZodSchema), AuthController.resendOtp);
router.post('/forgot-password', validateRequest(AuthValidation.createForgotPasswordZodSchema), AuthController.forgotPassword);
router.patch('/reset-password', validateRequest(AuthValidation.createResetPasswordZodSchema), AuthController.resetPassword);
router.post('/change-password', validateRequest(AuthValidation.createChangePasswordZodSchema), AuthController.changePassword);

export default router;
