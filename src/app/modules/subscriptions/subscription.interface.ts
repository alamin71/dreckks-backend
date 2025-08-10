export interface ISubscription {
  title: string;
  billingCycle: 'monthly' | 'quarterly' | 'yearly';
  price: number;
  category: 'user' | 'hospitality venue' | 'service provider';
  features: string[];
   planId?: string | null;
   startDate?: Date | null;
  endDate?: Date | null;
  plan?: string;
  status?: string;
  isActive?: boolean;
}
