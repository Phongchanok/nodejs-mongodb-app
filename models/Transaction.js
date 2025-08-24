const mongoose = require('mongoose');

const { Schema } = mongoose;

/**
 * Transaction (Ledger)
 * - บันทึกรายการแบบ append-only
 * - รองรับ type: pay (จ่ายร้าน), payout (ปิดรอบหักออก), adjust, reversal
 * - มีฟิลด์ปิดรอบ: settled, settlement_id, settled_at
 * - รักษาความเข้ากันได้ย้อนหลังด้วยฟิลด์ legacy: timestamp
 */

const TransactionSchema = new Schema(
  {
    // ผู้โอน / ผู้รับ
    from: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    to:   { type: Schema.Types.ObjectId, ref: 'User', required: true },

    // ประเภทธุรกรรม
    type: {
      type: String,
      enum: ['pay', 'payout', 'adjust', 'reversal'],
      default: 'pay',
      index: true
    },

    // จำนวนเครดิต (จำนวนเต็มบวก)
    amount: {
      type: Number,
      required: true,
      min: [1, 'amount ต้อง ≥ 1'],
      validate: { validator: Number.isInteger, message: 'amount ต้องเป็นจำนวนเต็ม' }
    },

    // โทเคน (optional) สำหรับกันใช้ซ้ำ/อ้างอิง
    token: { type: String, index: true, sparse: true },

    // ธุรกรรมที่เกิดขึ้นจริงให้ used=true (คงไว้เพื่อความเข้ากันได้)
    used: { type: Boolean, default: true },

    // ฟิลด์สำหรับ "ปิดรอบ"
    settled:       { type: Boolean, default: false, index: true },
    settlement_id: { type: String, index: true }, // เช่น d2025-08-24_m<merchantId>
    settled_at:    { type: Date },

    // เวลาเกิดรายการ (ใหม่) + alias เดิม (timestamp)
    createdAt: { type: Date, default: Date.now, index: true },
    timestamp: { type: Date } // legacy alias สำหรับโค้ดเก่าที่อ้าง field นี้
  },
  {
    versionKey: false,
    strict: true
  }
);

/**
 * Sync createdAt <-> timestamp (legacy)
 * - ถ้ามี timestamp แต่ไม่มี createdAt → คัดลอกมาใส่ createdAt
 * - ถ้ามี createdAt แต่ไม่มี timestamp → คัดลอกไปใส่ timestamp
 */
TransactionSchema.pre('save', function(next) {
  if (!this.createdAt && this.timestamp) this.createdAt = this.timestamp;
  if (!this.timestamp && this.createdAt) this.timestamp = this.createdAt;
  next();
});

// Indexes ที่ใช้บ่อย
TransactionSchema.index({ to: 1, type: 1, createdAt: 1, settled: 1 }); // ปิดรอบ/รายงานตามร้าน+เวลา
TransactionSchema.index({ from: 1, createdAt: 1 });                     // ค้นฝั่งผู้จ่าย
TransactionSchema.index({ settlement_id: 1 });                           // export ตามรอบ

module.exports = mongoose.model('Transaction', TransactionSchema);
