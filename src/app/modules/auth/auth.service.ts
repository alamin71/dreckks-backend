
// // src/modules/auth/auth.service.ts
// import { StatusCodes } from 'http-status-codes';
// import bcrypt from 'bcrypt';
// import config from '../../../config';
// import generateOTP from '../../../utils/generateOTP';
// import { User } from '../user/user.model';
// import AppError from '../../../errors/AppError';
// import { jwtHelper } from '../../../helpers/jwtHelper';
// import { emailTemplate } from '../../../shared/emailTemplate';
// import { emailHelper } from '../../../helpers/emailHelper';
// import { USER_ROLES } from '../../../enums/user';

// type SignupPayload = {
//   name: string;
//   email: string;
//   password: string;
//   role?: string;
//   profileData?: any;
// };

// export const signup = async (payload: SignupPayload, role?: string) => {
//   const existing = await User.isExistUserByEmail(payload.email);
//   if (existing) throw new AppError(StatusCodes.CONFLICT, 'Email already exists');

//   const assignRole = (role && Object.values(USER_ROLES).includes(role as USER_ROLES) ? role : USER_ROLES.USER);

//   const newUser = await User.create({
//     name: payload.name,
//     email: payload.email,
//     password: payload.password,
//     role: assignRole,
//     profileData: payload.profileData || {},
//     verified: false,
//   });

//   // send OTP
//   const otp = generateOTP(6);
//   const authObj = { oneTimeCode: otp, expireAt: new Date(Date.now() + 10 * 60 * 1000), isResetPassword: false };
//   newUser.authentication = authObj;
//   await newUser.save();

//   const mail = emailTemplate.createAccount({ name: newUser.name, otp, email: newUser.email });
//   await emailHelper.sendEmail(mail);

//   return { message: 'Signup successful. OTP sent to email', email: newUser.email };
// };

// export const verifyOtpAndIssueTokens = async (email: string, otp: string) => {
//   const user = await User.findOne({ email }).select('+authentication +password');
//   if (!user || !user.authentication) throw new AppError(StatusCodes.NOT_FOUND, 'User or OTP not found');

//   if (String(user.authentication.oneTimeCode) !== otp) throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid OTP');
//   if (user.authentication.expireAt && new Date() > new Date(user.authentication.expireAt)) {
//     throw new AppError(StatusCodes.BAD_REQUEST, 'OTP expired');
//   }

//   user.verified = true;
//   user.authentication = undefined;
//   await user.save();

//   const payload = { id: user._id.toString(), role: user.role, email: user.email };
//   const accessToken = jwtHelper.createAccessToken(payload);
//   const refreshToken = jwtHelper.createRefreshToken(payload);

//   return { accessToken, refreshToken, user: { id: user._id, name: user.name, email: user.email, role: user.role } };
// };

// export const login = async (email: string, password: string) => {
//   const user = await User.findOne({ email }).select('+password');
//   if (!user) throw new AppError(StatusCodes.BAD_REQUEST, 'User not found');
//   if (!(await User.isMatchPassword(password, user.password))) throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid credentials');
//   if (!user.verified) throw new AppError(StatusCodes.FORBIDDEN, 'Account not verified');
//   if (user.status !== 'active') throw new AppError(StatusCodes.FORBIDDEN, 'Account not active');

//   const payload = { id: user._id.toString(), role: user.role, email: user.email };
//   const accessToken = jwtHelper.createAccessToken(payload);
//   const refreshToken = jwtHelper.createRefreshToken(payload);

//   return { accessToken, refreshToken, user: { id: user._id, name: user.name, email: user.email, role: user.role } };
// };

// export const refreshAccessToken = async (refreshToken: string) => {
//   try {
//     const decoded: any = jwtHelper.verifyRefreshToken(refreshToken) as any;
//     const payload = { id: decoded.id, role: decoded.role, email: decoded.email };
//     const accessToken = jwtHelper.createAccessToken(payload);
//     return { accessToken };
//   } catch (err) {
//     throw new AppError(StatusCodes.UNAUTHORIZED, 'Invalid refresh token');
//   }
// };

// export const resendOtp = async (email: string) => {
//   const user = await User.findOne({ email });
//   if (!user) throw new AppError(StatusCodes.NOT_FOUND, 'User not found');

//   const otp = generateOTP(6);
//   user.authentication = { oneTimeCode: otp, expireAt: new Date(Date.now() + 10 * 60 * 1000), isResetPassword: false };
//   await user.save();

//   const mail = emailTemplate.createAccount({ name: user.name, otp, email: user.email });
//   await emailHelper.sendEmail(mail);

//   return {
//     message: 'Signup successful. OTP sent to email',
  
//     ...(process.env.NODE_ENV === 'development' && { otp }) 
//   };
// };

// export const forgotPassword = async (email: string) => {
//   const user = await User.findOne({ email });
//   if (!user) throw new AppError(StatusCodes.NOT_FOUND, 'User not found');

//   const otp = generateOTP(6);
//   user.authentication = { oneTimeCode: otp, expireAt: new Date(Date.now() + 10 * 60 * 1000), isResetPassword: true };
//   await user.save();

//   const mail = emailTemplate.resetPassword({ otp, email: user.email });
//   await emailHelper.sendEmail(mail);

//   return { message: 'Password reset OTP sent to email' };
// };

// export const resetPasswordWithOtp = async (email: string, otp: string, newPassword: string) => {
//   const user = await User.findOne({ email }).select('+password +authentication');
//   if (!user || !user.authentication) throw new AppError(StatusCodes.NOT_FOUND, 'User not found or OTP not issued');

//   if (String(user.authentication.oneTimeCode) !== otp) throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid OTP');
//   if (user.authentication.expireAt && new Date() > new Date(user.authentication.expireAt)) throw new AppError(StatusCodes.BAD_REQUEST, 'OTP expired');

//   user.password = await bcrypt.hash(newPassword, Number(config.bcrypt_salt_rounds));
//   user.authentication = undefined;
//   await user.save();

//   return { message: 'Password reset successfully' };
// };

// export const changePassword = async (userId: string, currentPassword: string, newPassword: string) => {
//   const user = await User.findById(userId).select('+password');
//   if (!user) throw new AppError(StatusCodes.NOT_FOUND, 'User not found');

//   if (!(await User.isMatchPassword(currentPassword, user.password))) {
//     throw new AppError(StatusCodes.BAD_REQUEST, 'Current password incorrect');
//   }
//   const hashed = await bcrypt.hash(newPassword, Number(config.bcrypt_salt_rounds));
//   user.password = hashed;
//   await user.save();
//   return { message: 'Password changed successfully' };
// };

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

  const assignRole =
    role && Object.values(USER_ROLES).includes(role as USER_ROLES)
      ? role
      : USER_ROLES.USER;

  // Role-based profile data
  let roleProfileData: any = {};
  if (assignRole === USER_ROLES.USER) {
    roleProfileData = {
      firstName: payload.profileData?.firstName || '',
      lastName: payload.profileData?.lastName || '',
      age: payload.profileData?.age || null,
      weight: payload.profileData?.weight || null,
      sex: payload.profileData?.sex || '',
    };
  } else if (assignRole === USER_ROLES.SERVICE_PROVIDER) {
    roleProfileData = {
      designation: payload.profileData?.designation || '',
      resumeUrl: payload.profileData?.resumeUrl || '',
    };
  } else if (assignRole === USER_ROLES.HOSPITALITY_VENUE) {
    roleProfileData = {
      venueName: payload.profileData?.venueName || '',
      hoursOfOperation: payload.profileData?.hoursOfOperation || '',
      capacity: payload.profileData?.capacity || null,
      displayQrCodes: payload.profileData?.displayQrCodes || false,
      inAppPromotion: payload.profileData?.inAppPromotion || false,
      allowRewards: payload.profileData?.allowRewards || false,
      allowEvents: payload.profileData?.allowEvents || false,
      venueTypes: payload.profileData?.venueTypes || [],
    };
  }

  const profileData = {
    phone: payload.profileData?.phone || '',
    location: payload.profileData?.location || '',
    ...roleProfileData,
  };

  const newUser = await User.create({
    name: payload.name,
    email: payload.email,
    password: payload.password,
    role: assignRole,
    profileData,
    verified: false,
  });

  // send OTP
  const otp = generateOTP(6);
  newUser.authentication = {
    oneTimeCode: otp,
    expireAt: new Date(Date.now() + 10 * 60 * 1000),
    isResetPassword: false,
  };
  await newUser.save();

  const mail = emailTemplate.createAccount({
    name: newUser.name,
    otp,
    email: newUser.email,
  });
  
  await emailHelper.sendEmail(emailTemplate.createAccount({ name: newUser.name, otp, email: newUser.email }));


  return {
    message: 'Signup initiate. OTP sent to email',
    email: newUser.email,
    role: newUser.role,
    profileData: newUser.profileData,
    ...(process.env.NODE_ENV === 'development' && { otp }),
  };
};



export const verifyOtpAndIssueTokens = async (email: string, otp: string) => {
  const user = await User.findOne({ email }).select('+authentication +password');
  if (!user || !user.authentication) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User or OTP not found');
  }

  if (String(user.authentication.oneTimeCode) !== otp) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid OTP');
  }

  if (user.authentication.expireAt && new Date() > new Date(user.authentication.expireAt)) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'OTP expired');
  }

  if (user.authentication.isResetPassword) {
    // Forgot password OTP verified
    const payload = {
      id: user._id.toString(),
      email: user.email,
      resetPassword: true,
    };

    // এই token দিয়ে user password reset API call করবে
    const resetToken = jwtHelper.createResetPasswordToken(payload);

    // Optional: এখানে OTP ডাটা রাখো, অথবা পরবর্তীতে password reset এর পর ডিলিট করো
    return { resetToken };
  } else {
    // Signup OTP verified
    user.verified = true;
    user.authentication = undefined; // OTP ডাটা রিসেট
    await user.save();

    const payload = { id: user._id.toString(), role: user.role, email: user.email };
    const accessToken = jwtHelper.createAccessToken(payload);
    const refreshToken = jwtHelper.createRefreshToken(payload);

    return {
      accessToken,
      refreshToken,
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
    };
  }
};
export const login = async (email: string, password: string) => {
  const user = await User.findOne({ email }).select('+password');
  if (!user) throw new AppError(StatusCodes.BAD_REQUEST, 'User not found');
  if (!(await User.isMatchPassword(password, user.password)))
    throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid credentials');
  if (!user.verified)
    throw new AppError(StatusCodes.FORBIDDEN, 'Account not verified');
  if (user.status !== 'active')
    throw new AppError(StatusCodes.FORBIDDEN, 'Account not active');

  const payload = {
    id: user._id.toString(),
    role: user.role,
    email: user.email,
  };
  const accessToken = jwtHelper.createAccessToken(payload);
  const refreshToken = jwtHelper.createRefreshToken(payload);

  return {
    message: 'Login successful',
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
    ...(process.env.NODE_ENV === 'development'
      ? { accessToken, refreshToken }
      : {}),
  };
};

export const refreshAccessToken = async (refreshToken: string) => {
  try {
    const decoded: any = jwtHelper.verifyRefreshToken(refreshToken) as any;
    const payload = {
      id: decoded.id,
      role: decoded.role,
      email: decoded.email,
    };
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
  user.authentication = {
    oneTimeCode: otp,
    expireAt: new Date(Date.now() + 10 * 60 * 1000),
    isResetPassword: false,
  };
  await user.save();

  const mail = emailTemplate.createAccount({
    name: user.name,
    otp,
    email: user.email,
  });
  await emailHelper.sendEmail(mail);

  return {
    message: 'OTP resent to email',
    ...(process.env.NODE_ENV === 'development' && { otp }),
  };
};

export const forgotPassword = async (email: string) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(StatusCodes.NOT_FOUND, 'User not found');

  const otp = generateOTP(6);
  user.authentication = {
    oneTimeCode: otp,
    expireAt: new Date(Date.now() + 10 * 60 * 1000),
    isResetPassword: true,
  };
  await user.save();

  const mail = emailTemplate.resetPassword({ otp, email: user.email });
  await emailHelper.sendEmail(mail);

  return {
    message: 'Password reset OTP sent to email',
    ...(process.env.NODE_ENV === 'development' && { otp }),
  };
};

export const resetPasswordWithOtp = async (
  email: string,
  otp: string,
  newPassword: string
) => {
  const user = await User.findOne({ email }).select('+password +authentication');
  if (!user || !user.authentication)
    throw new AppError(
      StatusCodes.NOT_FOUND,
      'User not found or OTP not issued'
    );

  if (String(user.authentication.oneTimeCode) !== otp)
    throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid OTP');
  if (
    user.authentication.expireAt &&
    new Date() > new Date(user.authentication.expireAt)
  )
    throw new AppError(StatusCodes.BAD_REQUEST, 'OTP expired');

  user.password = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt_rounds)
  );
  user.authentication = undefined;
  await user.save();

  return { message: 'Password reset successfully' };
};

export const changePassword = async (
  userId: string,
  currentPassword: string,
  newPassword: string
) => {
  const user = await User.findById(userId).select('+password');
  if (!user) throw new AppError(StatusCodes.NOT_FOUND, 'User not found');

  if (!(await User.isMatchPassword(currentPassword, user.password))) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Current password incorrect');
  }
  const hashed = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt_rounds)
  );
  user.password = hashed;
  await user.save();
  return { message: 'Password changed successfully' };
};
