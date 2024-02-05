const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const secretKey = crypto.randomBytes(64).toString('hex');
function generateaccessToken(user) {
    console.log('Generating access token for user:', user);
    return jwt.sign({
      id: user.id,
      name: user.name,
      age: user.age,
      username: user.username,
      role:user.role,
    }, secretKey, { expiresIn: '3 m' });
  }
function generateRefreshToken () {
    return crypto.randomBytes(32).toString('hex');
  };
  const refreshTokens = {};
  module.exports = {
  generateaccessToken,
  generateRefreshToken,
  refreshTokens,
  secretKey
};
