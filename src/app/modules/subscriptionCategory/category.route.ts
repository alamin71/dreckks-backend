import express from 'express';
import {
  createCategory,
  getAllCategories,
  getSingleCategory,
  updateCategory,
  deleteCategory,
} from './category.controller';

const router = express.Router();

router.post('/', createCategory);
router.get('/', getAllCategories);
router.get('/:id', getSingleCategory);
router.patch('/:id', updateCategory);
router.delete('/:id', deleteCategory);

export const CategoryRoutes = router;