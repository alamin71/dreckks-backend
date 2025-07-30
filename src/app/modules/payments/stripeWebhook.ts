import express, { Request, Response } from 'express';
import  stripe  from '../../../config/stripe';
import { Payment } from './payment.model';
import { PaymentStatus } from './payment.interface';

const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET!;
const router = express.Router();

router.post('/webhook', express.raw({ type: 'application/json' }), async (req: Request, res: Response) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig!, endpointSecret);
  } catch (err: any) {
    console.error('Webhook Error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object as any;

    await Payment.findOneAndUpdate(
      { transactionId: paymentIntent.id },
      { status: PaymentStatus.SUCCESS }
    );
  }

  res.status(200).json({ received: true });
});

export default router;
