import express from 'express';
import { SubscriptionController } from '../subscriptions/subscription.controller';

const router = express.Router();

router.post('/', SubscriptionController.createSubscription);
router.get('/', SubscriptionController.getAllSubscriptions);
router.get('/:id', SubscriptionController.getSingleSubscription);
router.patch('/:id', SubscriptionController.updateSubscription);
router.delete('/:id', SubscriptionController.deleteSubscription);

export const SubscriptionRoutes = router;
