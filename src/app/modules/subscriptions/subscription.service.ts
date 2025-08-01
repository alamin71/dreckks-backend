import { Subscription } from './subscription.model';
import { ISubscription } from './subscription.interface';

const createSubscription = async (payload: ISubscription) => {
  return await Subscription.create(payload);
};

const getAllSubscriptions = async () => {
  return await Subscription.find();
};

const getSingleSubscription = async (id: string) => {
  return await Subscription.findById(id);
};

const updateSubscription = async (id: string, payload: Partial<ISubscription>) => {
  return await Subscription.findByIdAndUpdate(id, payload, { new: true });
};

const deleteSubscription = async (id: string) => {
  return await Subscription.findByIdAndDelete(id);
};

export const SubscriptionService = {
  createSubscription,
  getAllSubscriptions,
  getSingleSubscription,
  updateSubscription,
  deleteSubscription,
};
