const mongoose = require("mongoose");

// MUST stay in sync with the inline `userSchema` in `server.js`. The two
// definitions exist because `server.js` registers the model with the Mongoose
// connection it owns, while `cron.js` is a separate one-shot script that
// opens its own connection and needs its own model registration. Diverging
// the field shapes here from server.js will silently mis-shape data written
// by cron.js. See todo.md M24 for the consolidation plan; until then, edit
// both files together.
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  name: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  schoolName: { type: String, required: true },
  birthMonth: { type: String, required: true },
  birthYear: { type: String, required: true },
  gradeLevel: { type: String, required: true },
  gender: { type: String, required: true },
  isVerifiedEmail: { type: Boolean, default: true },
  verificationCode: { type: String, select: false },
});

const User = mongoose.model("User", userSchema);

module.exports = User;
