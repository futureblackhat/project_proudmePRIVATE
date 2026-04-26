const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const mongoose = require('mongoose');

async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send('Missing authorization header');
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });

    // Reject if this token has been server-side logged out (H20).
    // Lookup is keyed on sha256(token); the RevokedToken collection has a
    // TTL index, so blacklist size is bounded by the number of currently
    // active revoked sessions and self-cleans at JWT expiry.
    const RevokedToken = mongoose.model('RevokedToken');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const revoked = await RevokedToken.findOne({ tokenHash });
    if (revoked) {
      return res.status(401).send('Token has been revoked');
    }

    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(400).send('Invalid token');
  }
}

function attachUserId(req, res, next) {
  req._id = req.userId;
  next();
}

module.exports = { verifyToken, attachUserId };

