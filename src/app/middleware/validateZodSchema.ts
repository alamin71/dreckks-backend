import { NextFunction, Request, Response } from "express";
import type { ZodSchema } from "zod";

const validateZodSchema = (schema: ZodSchema<any>) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await schema.parseAsync(req.body);
      next();
    } catch (error) {
      next(error);
    }
  };
};

export default validateZodSchema;
