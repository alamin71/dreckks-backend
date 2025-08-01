import { Types } from 'mongoose';

export interface ISubscription {
  name: string;
  price: number;
  duration: 'monthly' | 'yearly'; // Better to restrict this
  features: string[];
  isActive?: boolean;
  category?: Types.ObjectId; // Reference to Category model
}
