const jwt = require('jsonwebtoken');
const { secretKey } = require('../utils/JWTutils');
function authenticateRole(requiredRole) {
    return (req, res, next) => {
    try {
  const authorizationHeader = req.headers.authorization;
if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access token is missing or invalid format' });
  }
const token = authorizationHeader.split(' ')[1];
jwt.verify(token, secretKey, (err,user) => {
    if (err) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    if (user.role !== requiredRole) {
        return res.status(403).json({ message: 'Forbidden' });
      }
    console.log('Token verified successfully:', user);
    req.user = user;
    next();
  });
}
catch (err) {
    if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
}};
module.exports = authenticateRole;