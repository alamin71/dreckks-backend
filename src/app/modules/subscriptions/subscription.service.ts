import { Subscription } from './subscription.model';
import { ISubscription } from './subscription.interface';
import QueryBuilder from '../../builder/QueryBuilder';
import { User } from '../user/user.model';

const createSubscription = async (payload: ISubscription) => {
  return await Subscription.create(payload);
};

const getAllSubscriptions = async (query: Record<string, unknown>) => {
  const subscriptionQuery = Subscription.find();

  const queryBuilder = new QueryBuilder(subscriptionQuery, query)
    .search(['title'])  // Search in title field
    .filter()           // Dynamic filtering like ?category=USER
    .sort()
    .paginate()
    .fields()
    .applyExclusions();

  await queryBuilder.executePopulate(); // If you want population (optional)

  const subscriptions = await queryBuilder.modelQuery;
  const meta = await queryBuilder.countTotal();

  return {
    meta,
    data: subscriptions,
  };
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
const selectSubscription = async (userId: string, planId: string) => {
  
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }
  user.subscription = { plan: planId, status: 'active', isActive: true };
  await user.save();
  return user.subscription;
};

export const SubscriptionService = {
  createSubscription,
  getAllSubscriptions,
  getSingleSubscription,
  updateSubscription,
  deleteSubscription,
  selectSubscription
};
