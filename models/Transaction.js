const mongoose = require('mongoose');

/**
 * Transaction schema to record each QR-code based transfer. A token
 * derived from the QR payload is stored to prevent re-use. Each
 * transfer records the sender (`from`), the receiver (`to`), the
 * amount and the timestamp. The `used` flag indicates whether the
 * transaction has been redeemed.
 */

/**
 * สคีมาธุรกรรมสำหรับบันทึกการโอนผ่าน QR-code  
 * จะเก็บโทเคนที่สร้างจาก QR payload เพื่อป้องกันการนำมาใช้ซ้ำ  
 * ธุรกรรมแต่ละครั้งจะบันทึก: ผู้ส่ง (`from`), ผู้รับ (`to`),  
 * จำนวนเงิน และเวลาที่ทำรายการ  
 * ตัวแปร `used` ใช้ระบุว่าธุรกรรมนั้นถูกใช้งานแล้วหรือยัง
 */



const transactionSchema = new mongoose.Schema({
  /**token: {
    type: String,
    required: true,
    unique: true // ป้องกันการใช้ซ้ำ
  },
  from: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true // ID ผู้ส่ง
  },
  to: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true // ID ผู้รับ
  },
  amount: {
    type: Number,
    required: true // จำนวนเงิน
  },
  timestamp: {
    type: Date,
    required: true // เวลาอัตโนมัติ
  },
  used: {
    type: Boolean,
    default: false // false = ยังไม่ถูกใช้
  }
});

module.exports = mongoose.model('Transaction', transactionSchema);
*/
// token: optional – สำหรับกรณีที่ยังอยากใช้แบบ one-time ในอนาคต
  token: { 
    type: String, 
    index: true, 
    sparse: true 
  }, // ลบ unique และ required ออก

  from: { 
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', 
    required: true 
  }, // ผู้จ่าย
  
  to:   { 
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', 
    required: true 
  }, // ร้านค้า
  
  amount: { 
    type: Number, 
    required: true, 
    min: 1,
    validate: { 
      validator: Number.isInteger, 
      message: 'amount ต้องเป็นจำนวนเต็ม' 
    } 
  }, // จำนวนเครดิต (จำนวนเต็มบวก)
  
  timestamp: { 
    type: Date, 
    default: Date.now 
  }, // เวลาทำรายการ
  
  used: { 
    type: Boolean, 
    default: true 
  }  // คงไว้เพื่อความเข้ากันได้ (true สำหรับธุรกรรมที่เกิดขึ้นจริง)
});

// บังคับจำนวนเต็มบวก
transactionSchema.path('amount').validate(Number.isInteger, 'amount ต้องเป็นจำนวนเต็ม');

module.exports = mongoose.model('Transaction', transactionSchema);