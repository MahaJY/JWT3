const express = require('express');
const authController = require('../controllers/authcontrollers');
const authenticateToken = require('../middlewares/authenticatetoken');
const JWTUtils = require('../utils/JWTutils')
const router = express.Router();
router.post('/register',authController.register);
router.post('/login',authController.login);
router.post('/refresh', authController.refreshToken);
router.get('/protected', authenticateToken('admin'), (req, res) => {
  const user = req.user;
  res.json({ message: 'This is a protected route', user });
});
module.exports = router;