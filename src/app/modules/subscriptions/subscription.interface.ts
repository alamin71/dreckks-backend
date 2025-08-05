export interface ISubscription {
  title: string;
  billingCycle: 'monthly' | 'quarterly' | 'yearly';
  price: number;
  category: 'user' | 'hospitality venue' | 'service provider';
  features: string[];
  isActive?: boolean;
}
