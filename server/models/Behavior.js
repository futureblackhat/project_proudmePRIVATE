const mongoose = require("mongoose");

// MUST stay in sync with the inline `behaviorSchema` in `server.js`. Same
// rationale as `models/User.js` — cron.js opens its own connection and needs
// its own model. Adding a field to one definition without the other will
// silently mis-shape the data written from cron.js. See todo.md M24.
const behaviorSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  name: { type: String },
  goalType: { type: String, required: true },
  date: { type: String },
  dateToday: { type: Date },
  goalValue: { type: Number },
  behaviorValue: { type: Number, default: 0 },
  goalStatus: { type: String },
  divInfo1: { type: String },
  divInfo2: { type: String },
  reflection: { type: String },
  feedback: { type: String },
  recommendedValue: { type: Number, default: 0 },
  activities: { type: Object, default: {} },
  screentime: { type: Object, default: {} },
  servings: { type: Object, default: {} },
  sleep: {
    bedBehavior: Number,
    wakeUpBehavior: Number,
    bedGoal: Number,
    wakeUpGoal: Number,
  },
});

const Behavior = mongoose.model("Behavior", behaviorSchema);

module.exports = Behavior;
