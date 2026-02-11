const { Session, User } = require('../models/user');

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = null;
    return next();
  }
  
  const token = authHeader.substring(7);
  const userId = await Session.verify(token);
  
  if (!userId) {
    req.user = null;
    return next();
  }
  
  const user = await User.findById(userId);
  req.user = user;
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

module.exports = { authMiddleware, requireAuth };
