// import { Schema, model } from 'mongoose';
// import { ISubscription } from './subscription.interface';

// const subscriptionSchema = new Schema<ISubscription>(
//   {
//     title: { type: String, required: true },
//     price: { type: Number, required: true },
//     category:{
//       type:String,
//       requred:true,
//       enum["user","hospitality venue",["service provider"]],
//        default:[]},
//     features: { type: [String], default: [] },
//     isActive: { type: Boolean, default: true },
//   },
//   { timestamps: true }
// );

// export const Subscription = model<ISubscription>('Subscription', subscriptionSchema);
import { Schema, model } from 'mongoose';
import { ISubscription } from './subscription.interface';

const subscriptionSchema = new Schema<ISubscription>(
  {
    title: { type: String, required: true },
    billingCycle: { 
      type: String, 
      required: true, 
      enum: ['monthly', 'quarterly', 'yearly'] 
    },
    price: { type: Number, required: true },
    category: {
      type: String,
      required: true,
      enum: ['user', 'hospitality venue', 'service provider']
    },
    features: { type: [String], default: [] },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

export const Subscription = model<ISubscription>('Subscription', subscriptionSchema);
