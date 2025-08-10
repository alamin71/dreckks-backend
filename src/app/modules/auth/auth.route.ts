import express from 'express';
import * as AuthController from './auth.controller';

const router = express.Router();

router.post('/signup', AuthController.signup);
router.post('/verify-otp', AuthController.verifyOtp);
router.post('/login', AuthController.login);
router.post('/refresh-token', AuthController.refreshToken);
router.post('/resend-otp', AuthController.resendOtp);
router.post('/forgot-password', AuthController.forgotPassword);
router.post('/reset-password', AuthController.resetPassword);
router.post('/change-password', AuthController.changePassword);

export default router;