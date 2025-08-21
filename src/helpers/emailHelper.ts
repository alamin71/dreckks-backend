// import nodemailer from "nodemailer";
// import config from "../config";
// import { errorLogger, logger } from "../shared/logger";
// import { ISendEmail } from "../types/email";

// const transporter = nodemailer.createTransport({
//   host: config.email.host,
//   port: Number(config.email.port),
//   secure: false,
//   auth: {
//     user: config.email.user,
//     pass: config.email.pass,
//   },
// });

// const sendEmail = async (values: ISendEmail) => {
//   try {
//     const info = await transporter.sendMail({
//       from: `${config.email.email_header} ${config.email.from}`,
//       to: values.to,
//       subject: values.subject,
//       html: values.html,
//     });

//     logger.info("Mail send successfully", info.accepted);
//   } catch (error) {
//     errorLogger.error("Email", error);
//   }
// };
// const sendEmailForAdmin = async (values: ISendEmail) => {
//   try {
//     const info = await transporter.sendMail({
//       from: `"${values.to}" <${values.to}>`,
//       to: config.email.user,
//       subject: values.subject,
//       html: values.html,
//     });

//     logger.info("Mail send successfully", info.accepted);
//   } catch (error) {
//     errorLogger.error("Email", error);
//   }
// };

// export const emailHelper = {
//   sendEmail,
//   sendEmailForAdmin,
// };
import nodemailer from "nodemailer";
import config from "../config";
import { errorLogger, logger } from "../shared/logger";
import { ISendEmail } from "../types/email";

const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: Number(config.email.port),
  secure: Number(config.email.port) === 465, // 465 হলে secure:true হবে
  auth: {
    user: config.email.user,
    pass: config.email.pass,
  },
});

const sendEmail = async (values: ISendEmail) => {
  try {
    const info = await transporter.sendMail({
      from: `"${config.email.email_header}" <${config.email.user}>`, // <-- must match EMAIL_USER
      to: values.to,
      subject: values.subject,
      html: values.html,
    });

    logger.info("Mail sent successfully", info.accepted);
  } catch (error) {
    errorLogger.error("Email", error);
  }
};

const sendEmailForAdmin = async (values: ISendEmail) => {
  try {
    const info = await transporter.sendMail({
      from: `"${config.email.email_header}" <${config.email.user}>`, // <-- always send as Gmail user
      to: config.email.user,
      subject: values.subject,
      html: values.html,
    });

    logger.info("Mail sent successfully", info.accepted);
  } catch (error) {
    errorLogger.error("Email", error);
  }
};

export const emailHelper = {
  sendEmail,
  sendEmailForAdmin,
};
