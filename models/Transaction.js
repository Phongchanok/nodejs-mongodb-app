const mongoose = require('mongoose');

/**
 * Transaction schema to record each QR-code based transfer. A token
 * derived from the QR payload is stored to prevent re-use. Each
 * transfer records the sender (`from`), the receiver (`to`), the
 * amount and the timestamp. The `used` flag indicates whether the
 * transaction has been redeemed.
 */
const transactionSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  from: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  to: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  timestamp: {
    type: Date,
    required: true
  },
  used: {
    type: Boolean,
    default: false
  }
});

module.exports = mongoose.model('Transaction', transactionSchema);