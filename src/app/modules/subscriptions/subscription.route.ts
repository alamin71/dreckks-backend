
import express from 'express';
import { SubscriptionController } from './subscription.controller';
import validateRequest from '../../middleware/validateRequest';
import { SubscriptionValidation } from './subscription.validation';

const router = express.Router();

router.post(
  '/',
  validateRequest(SubscriptionValidation.createSubscriptionZodSchema),
  SubscriptionController.createSubscription
);

router.get('/', SubscriptionController.getAllSubscriptions);
router.get('/:id', SubscriptionController.getSingleSubscription);

router.patch(
  '/:id',
  validateRequest(SubscriptionValidation.updateSubscriptionZodSchema),
  SubscriptionController.updateSubscription
);

router.delete('/:id', SubscriptionController.deleteSubscription);

export const SubscriptionRoutes = router;
