// import { Subscription } from './subscription.model';
// import { ISubscription } from './subscription.interface';
// import QueryBuilder from '../../builder/QueryBuilder';
// import { User } from '../user/user.model';

// const createSubscription = async (payload: ISubscription) => {
//   return await Subscription.create(payload);
// };

// const getAllSubscriptions = async (query: Record<string, unknown>) => {
//   const subscriptionQuery = Subscription.find();

//   const queryBuilder = new QueryBuilder(subscriptionQuery, query)
//     .search(['title'])  // Search in title field
//     .filter()           // Dynamic filtering like ?category=USER
//     .sort()
//     .paginate()
//     .fields()
//     .applyExclusions();

//   await queryBuilder.executePopulate(); // If you want population (optional)

//   const subscriptions = await queryBuilder.modelQuery;
//   const meta = await queryBuilder.countTotal();

//   return {
//     meta,
//     data: subscriptions,
//   };
// };

// const getSingleSubscription = async (id: string) => {
//   return await Subscription.findById(id);
// };

// const updateSubscription = async (id: string, payload: Partial<ISubscription>) => {
//   return await Subscription.findByIdAndUpdate(id, payload, { new: true });
// };

// const deleteSubscription = async (id: string) => {
//   return await Subscription.findByIdAndDelete(id);
// };
// const selectSubscription = async (userId: string, planId: string) => {
  
//   const user = await User.findById(userId);
//   if (!user) {
//     throw new Error('User not found');
//   }
//   user.subscription = { plan: planId, status: 'active', isActive: true };
//   await user.save();
//   return user.subscription;
// };

// export const SubscriptionService = {
//   createSubscription,
//   getAllSubscriptions,
//   getSingleSubscription,
//   updateSubscription,
//   deleteSubscription,
//   selectSubscription
// };

import { Subscription } from './subscription.model';
import { ISubscription } from './subscription.interface';
import QueryBuilder from '../../builder/QueryBuilder';
import { User } from '../user/user.model';
import cron from 'node-cron';

// ---------------- CREATE ----------------
const createSubscription = async (payload: ISubscription) => {
  return await Subscription.create(payload);
};

// ---------------- GET ALL ----------------
const getAllSubscriptions = async (query: Record<string, unknown>) => {
  const subscriptionQuery = Subscription.find();

  const queryBuilder = new QueryBuilder(subscriptionQuery, query)
    .search(['title'])
    .filter()
    .sort()
    .paginate()
    .fields()
    .applyExclusions();

  await queryBuilder.executePopulate();

  const subscriptions = await queryBuilder.modelQuery;
  const meta = await queryBuilder.countTotal();

  return { meta, data: subscriptions };
};

// ---------------- GET SINGLE ----------------
const getSingleSubscription = async (id: string) => {
  return await Subscription.findById(id);
};

// ---------------- UPDATE ----------------
const updateSubscription = async (id: string, payload: Partial<ISubscription>) => {
  return await Subscription.findByIdAndUpdate(id, payload, { new: true });
};

// ---------------- DELETE ----------------
const deleteSubscription = async (id: string) => {
  return await Subscription.findByIdAndDelete(id);
};

// ---------------- SELECT PLAN (Set Expiry) ----------------
const selectSubscription = async (userId: string, planId: string) => {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');

  const plan = await Subscription.findById(planId);
  if (!plan) throw new Error('Subscription plan not found');

  // Plan duration mapping based on billing cycle
  let durationDays = 30; // default
  if (plan.billingCycle === 'monthly') durationDays = 30;
  if (plan.billingCycle === 'quarterly') durationDays = 90;
  if (plan.billingCycle === 'yearly') durationDays = 365;

  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + durationDays);

  user.subscription = {
    plan: planId,
    status: 'active',
    isActive: true,
    expiresAt: expiryDate
  };

  await user.save();
  return user.subscription;
};


// ---------------- CRON JOB (Auto-expire) ----------------
cron.schedule('0 0 * * *', async () => { // every day at midnight
  const now = new Date();
  const result = await User.updateMany(
    { 'subscription.expiresAt': { $lte: now }, 'subscription.isActive': true },
    { $set: { 'subscription.status': 'expired', 'subscription.isActive': false } }
  );
  if (result.modifiedCount > 0) {
    console.log(`[CRON] Expired subscriptions updated: ${result.modifiedCount}`);
  }
});

export const SubscriptionService = {
  createSubscription,
  getAllSubscriptions,
  getSingleSubscription,
  updateSubscription,
  deleteSubscription,
  selectSubscription
};
