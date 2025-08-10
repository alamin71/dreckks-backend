import jwt, { JwtPayload, Secret } from "jsonwebtoken";
 const verifyAccessToken = (token: string, secret: Secret) => {
  return jwt.verify(token, secret) as JwtPayload;
};
export default verifyAccessToken;