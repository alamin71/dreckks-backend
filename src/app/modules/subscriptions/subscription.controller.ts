import { Request, Response } from 'express';
import httpStatus from 'http-status';
import catchAsync from '../../../shared/catchAsync';
import { SubscriptionService } from './subscription.service';
import sendResponse from '../../../shared/sendResponse';

const createSubscription = catchAsync(async (req: Request, res: Response) => {
  const result = await SubscriptionService.createSubscription(req.body);
  sendResponse(res, {
    statusCode: httpStatus.CREATED,
    success: true,
    message: 'Subscription created successfully',
    data: result,
  });
});

const getAllSubscriptions = catchAsync(async (req: Request, res: Response) => {
  const result = await SubscriptionService.getAllSubscriptions(req.query);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Subscriptions retrieved successfully',
    meta: result.meta,
    data: result.data,
  });
});


const getSingleSubscription = catchAsync(async (req: Request, res: Response) => {
  const result = await SubscriptionService.getSingleSubscription(req.params.id);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Subscription retrieved successfully',
    data: result,
  });
});

const updateSubscription = catchAsync(async (req: Request, res: Response) => {
  const result = await SubscriptionService.updateSubscription(req.params.id, req.body);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Subscription updated successfully',
    data: result,
  });
});

const deleteSubscription = catchAsync(async (req: Request, res: Response) => {
  await SubscriptionService.deleteSubscription(req.params.id);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Subscription deleted successfully',
  });
});

export const SubscriptionController = {
createSubscription,
getAllSubscriptions,
getSingleSubscription,
updateSubscription,
deleteSubscription
}
