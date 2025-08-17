const mongoose = require('mongoose');

/**
 * User schema for the credit wallet application.
 *
 * Each user has a unique username and a hashed password. A role field
 * controls access within the application – the value can be one of
 * "user", "merchant", or "admin". Users and merchants both have a
 * credit balance stored directly on the user document. Admin users
 * typically do not use a personal credit balance but the field is
 * provided for completeness and to simplify queries. Using Mongoose
 * ensures that the collection enforces the structure defined here.
 */
const userSchema = new mongoose.Schema({
  // The unique identifier that users will log in with. In this
  // application the employee code doubles as the username for
  // employees. For merchants and admins it can be any string.
  username: {
    type: String,
    required: true,
    unique: true
  },
  // The user's hashed password. For employee accounts, the start
  // date (YYYY-MM-DD) will be hashed and stored here during import.
  password: {
    type: String,
    required: true
  },
  // The user's full name. For employee accounts, this comes from
  // the imported CSV and will be displayed on their dashboard.
  name: {
    type: String
  },
  // Employee code field. While `username` is used for login, this
  // field stores the actual employee code for clarity. For non-
  // employee roles (e.g. merchant, admin) it may be undefined.
  employeeCode: {
    type: String
  },
  // Employment start date (YYYY-MM-DD). This is stored as a string
  // rather than Date to match the imported CSV format. It may be
  // undefined for non-employee roles.
  startDate: {
    type: String
  },
  role: {
    type: String,
    enum: ['user', 'merchant', 'admin'],
    default: 'user',
    required: true
  },
  credit: {
    type: Number,
    default: 0
  }
});

module.exports = mongoose.model('User', userSchema);