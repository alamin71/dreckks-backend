
// src/modules/auth/auth.service.ts
import { StatusCodes } from 'http-status-codes';
import bcrypt from 'bcrypt';
import config from '../../../config';
import generateOTP from '../../../utils/generateOTP';
import { User } from '../user/user.model';
import AppError from '../../../errors/AppError';
import { jwtHelper } from '../../../helpers/jwtHelper';
import { emailTemplate } from '../../../shared/emailTemplate';
import { emailHelper } from '../../../helpers/emailHelper';
import { USER_ROLES } from '../../../enums/user';

type SignupPayload = {
  name: string;
  email: string;
  password: string;
  role?: string;
  profileData?: any;
};

export const signup = async (payload: SignupPayload, role?: string) => {
  const existing = await User.isExistUserByEmail(payload.email);
  if (existing) throw new AppError(StatusCodes.CONFLICT, 'Email already exists');

  const assignRole = (role && Object.values(USER_ROLES).includes(role as USER_ROLES) ? role : USER_ROLES.USER);

  const newUser = await User.create({
    name: payload.name,
    email: payload.email,
    password: payload.password,
    role: assignRole,
    profileData: payload.profileData || {},
    verified: false,
  });

  // send OTP
  const otp = generateOTP(6);
  const authObj = { oneTimeCode: otp, expireAt: new Date(Date.now() + 10 * 60 * 1000), isResetPassword: false };
  newUser.authentication = authObj;
  await newUser.save();

  const mail = emailTemplate.createAccount({ name: newUser.name, otp, email: newUser.email });
  await emailHelper.sendEmail(mail);

  return { message: 'Signup successful. OTP sent to email', email: newUser.email };
};

export const verifyOtpAndIssueTokens = async (email: string, otp: string) => {
  const user = await User.findOne({ email }).select('+authentication +password');
  if (!user || !user.authentication) throw new AppError(StatusCodes.NOT_FOUND, 'User or OTP not found');

  if (String(user.authentication.oneTimeCode) !== otp) throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid OTP');
  if (user.authentication.expireAt && new Date() > new Date(user.authentication.expireAt)) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'OTP expired');
  }

  user.verified = true;
  user.authentication = undefined;
  await user.save();

  const payload = { id: user._id.toString(), role: user.role, email: user.email };
  const accessToken = jwtHelper.createAccessToken(payload);
  const refreshToken = jwtHelper.createRefreshToken(payload);

  return { accessToken, refreshToken, user: { id: user._id, name: user.name, email: user.email, role: user.role } };
};

export const login = async (email: string, password: string) => {
  const user = await User.findOne({ email }).select('+password');
  if (!user) throw new AppError(StatusCodes.BAD_REQUEST, 'User not found');
  if (!(await User.isMatchPassword(password, user.password))) throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid credentials');
  if (!user.verified) throw new AppError(StatusCodes.FORBIDDEN, 'Account not verified');
  if (user.status !== 'active') throw new AppError(StatusCodes.FORBIDDEN, 'Account not active');

  const payload = { id: user._id.toString(), role: user.role, email: user.email };
  const accessToken = jwtHelper.createAccessToken(payload);
  const refreshToken = jwtHelper.createRefreshToken(payload);

  return { accessToken, refreshToken, user: { id: user._id, name: user.name, email: user.email, role: user.role } };
};

export const refreshAccessToken = async (refreshToken: string) => {
  try {
    const decoded: any = jwtHelper.verifyRefreshToken(refreshToken) as any;
    const payload = { id: decoded.id, role: decoded.role, email: decoded.email };
    const accessToken = jwtHelper.createAccessToken(payload);
    return { accessToken };
  } catch (err) {
    throw new AppError(StatusCodes.UNAUTHORIZED, 'Invalid refresh token');
  }
};

export const resendOtp = async (email: string) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(StatusCodes.NOT_FOUND, 'User not found');

  const otp = generateOTP(6);
  user.authentication = { oneTimeCode: otp, expireAt: new Date(Date.now() + 10 * 60 * 1000), isResetPassword: false };
  await user.save();

  const mail = emailTemplate.createAccount({ name: user.name, otp, email: user.email });
  await emailHelper.sendEmail(mail);

  return { message: 'OTP resent' };
};

export const forgotPassword = async (email: string) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(StatusCodes.NOT_FOUND, 'User not found');

  const otp = generateOTP(6);
  user.authentication = { oneTimeCode: otp, expireAt: new Date(Date.now() + 10 * 60 * 1000), isResetPassword: true };
  await user.save();

  const mail = emailTemplate.resetPassword({ otp, email: user.email });
  await emailHelper.sendEmail(mail);

  return { message: 'Password reset OTP sent to email' };
};

export const resetPasswordWithOtp = async (email: string, otp: string, newPassword: string) => {
  const user = await User.findOne({ email }).select('+password +authentication');
  if (!user || !user.authentication) throw new AppError(StatusCodes.NOT_FOUND, 'User not found or OTP not issued');

  if (String(user.authentication.oneTimeCode) !== otp) throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid OTP');
  if (user.authentication.expireAt && new Date() > new Date(user.authentication.expireAt)) throw new AppError(StatusCodes.BAD_REQUEST, 'OTP expired');

  user.password = await bcrypt.hash(newPassword, Number(config.bcrypt_salt_rounds));
  user.authentication = undefined;
  await user.save();

  return { message: 'Password reset successfully' };
};

export const changePassword = async (userId: string, currentPassword: string, newPassword: string) => {
  const user = await User.findById(userId).select('+password');
  if (!user) throw new AppError(StatusCodes.NOT_FOUND, 'User not found');

  if (!(await User.isMatchPassword(currentPassword, user.password))) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Current password incorrect');
  }
  const hashed = await bcrypt.hash(newPassword, Number(config.bcrypt_salt_rounds));
  user.password = hashed;
  await user.save();
  return { message: 'Password changed successfully' };
};