require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const authMiddleware = require("./authMiddleware");
const bcrypt = require("bcrypt");
const sgMail = require("@sendgrid/mail");
const openai = require("openai");
const cron = require('node-cron');
const rateLimit = require("express-rate-limit");

// 20 chatbot calls per hour per authenticated user. Each call hits OpenAI at
// real cost; without this a stolen JWT can loop and drain the lab's OpenAI
// budget. Keyed by req._id so it survives shared NAT / school WiFi.
const chatbotLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req._id || req.ip,
  message: { error: "Too many chatbot requests. Please try again later." },
});

// Login: 10 attempts / 15 min / IP. Blocks credential stuffing without
// punishing legitimate typo-then-retry. Keyed by IP because no token exists
// at this point.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please try again later." },
});

// Verify: 5 attempts / 15 min / IP. Tighter than login because the
// verification code is only 6 digits — must bound brute-force window.
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many verification attempts. Please try again later." },
});

// Send-code: 3 / 15 min / IP. Stops attacker (or buggy client retry loop)
// from burning the SendGrid quota and spamming an inbox.
const sendCodeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many code requests. Please wait before trying again." },
});

const app = express();
const port = 3001;

// Chain in front of the app is: client → Cloudflare → Render LB → app
// (confirmed by `Server: cloudflare` + `CF-RAY` response headers). That's
// 2 trusted upstream hops. With `trust proxy: 2` Express pops both XFF
// entries and `req.ip` resolves to the actual client IP (stable).
//
// Tried `trust proxy: 1` first — that only popped the Render LB entry,
// leaving `req.ip` = Cloudflare edge IP, which rotates between Cloudflare
// PoPs per request. Result: rate-limit counters bounced because each
// request keyed against a different Cloudflare edge. Fixed by trusting
// both hops.
app.set("trust proxy", 2);

const uri = process.env.REACT_APP_MONGODB_URI;

// helmet first so its security headers (X-Frame-Options, X-Content-Type-Options,
// Strict-Transport-Security, etc.) are applied to every response, including
// errors emitted by middleware below.
app.use(helmet());

// Browser-callable origins. Native iOS/Android Flutter apps don't trigger
// CORS at all (no browser), so the only legitimate browser callers are local
// dev (Flutter web on Chrome) and any future hosted web frontend. Anything
// else gets rejected — closes the browser-side CSRF/embed-our-API-in-a-rogue-
// site risk class. Requests with no Origin header (curl, native mobile,
// server-to-server) pass through.
const allowedOriginPatterns = [
  /^http:\/\/localhost(:\d+)?$/,
  /^http:\/\/127\.0\.0\.1(:\d+)?$/,
];
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      const ok = allowedOriginPatterns.some((re) => re.test(origin));
      return cb(ok ? null : new Error("Origin not allowed"), ok);
    },
    credentials: false,
  })
);

// 1 MB cap on every request body. Without this an attacker can send a
// 100 MB JSON body and OOM the dyno; legitimate journal payloads are
// well under 10 KB.
app.use(bodyParser.urlencoded({ extended: false, limit: "1mb" }));
app.use(bodyParser.json({ limit: "1mb" }));

sgMail.setApiKey(process.env.SENDGRID_API_KEY);


// Connect to MongoDB
mongoose
  .connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error(err);
  });

// Define user schema and model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  schoolName: { type: String, required: true },
  birthMonth: { type: String, required: true },
  birthYear: { type: String, required: true },
  gradeLevel: { type: String, required: true },
  gender: { type: String, required: true },
  isVerifiedEmail: { type: Boolean, default: true },
  verificationCode: { type: String },
});

const goalSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  name: {
    type: String,
  },
  goalType: {
    type: String,
    required: true,
  },
  goalValue: {
    type: Number,
  },
  behaviorValue: {
    type: Number,
  },
  divInfo1: {
    type: String,
  },
  divInfo2: {
    type: String,
  },
  reflection: {
    type: String,
  },
  date: {
    type: String,
  },
  dateToday: {
    type: Date,
  },
  goalStatus: {
    type: String,
  },
  recommendedValue: {
    type: Number,
  },
});

const behaviorSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  name: {
    type: String,
  },
  goalType: {
    type: String,
    required: true,
  },
  date: {
    type: String,
  },
  dateToday: {
    type: Date,
  },
  goalValue: {
    type: Number,
  },
  behaviorValue: {
    type: Number,
    default: 0,
  },
  goalStatus: {
    type: String,
  },
  divInfo1: {
    type: String,
  },
  divInfo2: {
    type: String,
  },
  reflection: {
    type: String,
  },
  feedback: {
    type: String,
  },
  recommendedValue: {
    type: Number,
    default: 0,
  },
  // New fields
  activities: {
    type: Object,
    default: {}
  },
  screentime: {
    type: Object,
    default: {}
  },
  servings: {
    type: Object,
    default: {}
  },
  sleep: {
    bedBehavior: Number,
    wakeUpBehavior: Number,
    bedGoal: Number,
    wakeUpGoal: Number
  },
});

const selectedItemsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Assuming each user has their own selected items
  activity: { type: Array, default: [] },
  screentime: { type: Array, default: [] },
  eating: { type: Array, default: [] },
  sleep: { type: Array, default: [] }
});

const goalInputsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  activity: {
      type: Map,
      of: { hours: Number, minutes: Number }
  },
  screentime: {
      type: Map,
      of: { hours: Number, minutes: Number }
  },
  eating: {
      type: Map,
      of: { servings: Number}
  },
  sleep: {
      "Expected Sleep": {
          bedtime: { type: String},
          wakeUpTime: { type: String},
          hours: Number,
          minutes: Number
      }
  },
  date: {
    type: String,
    required: true
  },
});

const behaviorInputsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  activity: {
      type: Map,
      of: { hours: Number, minutes: Number }
  },
  screentime: {
      type: Map,
      of: { hours: Number, minutes: Number }
  },
  eating: {
      type: Map,
      of: {servings: Number }
  },
  sleep: {
      "Actual Sleep": {
          bedtime: { type: String },
          wakeUpTime: { type: String},
          hours: Number,
          minutes: Number
      }
  },
  date: {
    type: String,
    required: true
  },
});

const chatbotResponseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  goalType: { type: String, required: true },
  feedback: { type: String, required: true },
  date: {
    type: String,
    required: true
  },
});



const ChatbotResponse = mongoose.model("ChatbotResponse", chatbotResponseSchema);
const BehaviorInputs = mongoose.model('BehaviorInputs', behaviorInputsSchema);
const GoalInputs = mongoose.model('GoalInputs', goalInputsSchema);
const SelectedItems = mongoose.model('SelectedItems', selectedItemsSchema);
const User = mongoose.model("User", userSchema);
const Behavior = mongoose.model("Behavior", behaviorSchema);
const Goal = mongoose.model("Goal", goalSchema);


//delete file everyday it passes 

cron.schedule('0 0 * * *', async () => {
  console.log('Running daily data reset job');

  try {
    // Clear the collections
    await SelectedItems.deleteMany({});
    // await GoalInputs.deleteMany({});
    // await BehaviorInputs.deleteMany({});
    // await ChatbotResponse.deleteMany({});

    console.log('Data reset successfully');
  } catch (error) {
    console.error('Error resetting data:', error);
  }
});

// Login endpoint
app.post("/login", loginLimiter, async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    // Check email and password against database
    const user = await User.findOne({
      $or: [{ email: email }, { name: email }],
    });

    if (!user || !bcrypt.compareSync(password, user.password)) {
      // If login fails, return an error response
      res.status(401).send("Incorrect email or password");
      return;
    }

    // If login is successful, return a success response
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    console.log(`User with email ${email} logged in successfully.`)
    res.send(token);
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
});

// Registration endpoint
app.post("/register", async (req, res) => {
  const { email, password, confirmPassword, name, firstName, lastName, schoolName, birthMonth, birthYear, gradeLevel, gender } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send("Passwords do not match");
  }

  // Explicit uniqueness check so we return a clean 409 instead of letting
  // Mongoose throw a generic 500 on the unique-index violation.
  try {
    const existing = await User.findOne({ $or: [{ email }, { name }] });
    if (existing) {
      const field = existing.email === email ? "email" : "name";
      return res.status(409).json({ field, message: `This ${field} is already registered.` });
    }
  } catch (lookupErr) {
    console.error("Register uniqueness check failed:", lookupErr);
    return res.status(500).send("Internal server error");
  }

  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);
  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code

  try {
    const newUser = new User({
      email,
      password: hashedPassword,
      name,
      firstName,
      lastName,
      schoolName,
      birthMonth,
      birthYear,
      gradeLevel,
      gender,
      isVerifiedEmail: true,
      verificationCode
    });
    await newUser.save();

    const msg = {
      to: email,
      from: "pklab@projectproudme.com",
      subject: "Email Verification",
      text: `Your verification code is: ${verificationCode}`,
    };

    sgMail.send(msg)
      .then(() => res.status(200).send("User registered. Please verify your email."))
      .catch((error) => {
        console.error(error);
        res.status(500).send("Failed to send verification email");
      });
  } catch (error) {
    res.status(500).send("Internal server error");
    console.error(error);
  }
});

// Email verification endpoint
app.post("/verify", verifyLimiter, async (req, res) => {
  const { email, code } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).send("User not found");
    }

    if (user.verificationCode === code) {
      user.isVerifiedEmail = true;
      user.verificationCode = null; // Clear the verification code
      await user.save();
      res.status(200).send("Email verified successfully");
    } else {
      res.status(400).send("Invalid verification code");
    }
  } catch (error) {
    res.status(500).send("Internal server error");
    console.error(error);
  }
});

// Resend verification email endpoint
app.post("/send-code", sendCodeLimiter, async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email }) || await User.findOne({name: email});

    if (!user) {
      return res.status(400).send("User not found");
    }

    if (user.isVerifiedEmail) {
      return res.status(400).send("Email is already verified");
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.verificationCode = verificationCode;
    await user.save();

    const msg = {
      to: user.email,
      from: "pklab@projectproudme.com",
      subject: "Email Verification",
      text: `Your verification code is: ${verificationCode}`,
    };

    sgMail.send(msg)
      .then(() => res.send("Verification email sent successfully"))
      .catch((error) => {
        console.error(error);
        res.status(500).send("Failed to send verification email");
      });
  } catch (error) {
    res.status(500).send("Internal server error");
    console.error(error);
  }
});

// Add behaviors endpoint
app.post("/behaviors", authMiddleware.verifyToken, authMiddleware.attachUserId, async (req, res) => {
  try {
    if (String(req.body.user) !== String(req._id)) {
      return res.status(403).send("Forbidden: cannot write to another user's behaviors.");
    }

    const existingBehavior = await Behavior.findOne({
      user: req.body.user,
      goalType: req.body.goalType,
      date: req.body.date,
    });
    
    const newBehaviorData = {
      dateToday: req.body.dateToday,
      behaviorValue: req.body.behaviorValue,
      name: req.body.name,
      goalValue: req.body.goalValue,
      goalStatus: req.body.goalStatus,
      divInfo1: req.body.divInfo1,
      divInfo2: req.body.divInfo2,
      reflection: req.body.reflection,
      recommendedValue: req.body.recommendedValue,
      feedback: req.body.feedback,
    };

    // Add new fields based on goalType
    if (req.body.goalType === "activity") {
      newBehaviorData.activities = req.body.activities;
    } else if (req.body.goalType === "screentime") {
      newBehaviorData.screentime = req.body.screentime;
    } else if (req.body.goalType === "eating") {
      newBehaviorData.servings = req.body.servings;
    } else if (req.body.goalType === "sleep") {
      newBehaviorData.sleep = req.body.sleep;
    }
    if (existingBehavior) {
      const behavior = await Behavior.findOneAndUpdate(
        {
          user: req.body.user,
          goalType: req.body.goalType,
          date: req.body.date,
        },
        { $set: newBehaviorData },
        { new: true }
      );
      res.status(200).json(behavior);
    } else {
      const behavior = new Behavior({
        user: req.body.user,
        ...newBehaviorData,
        goalType: req.body.goalType,
        date: req.body.date,
      });
      const savedBehavior = await behavior.save();
      res.status(201).json(savedBehavior);
    }
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


// User endpoint
app.get("/users", authMiddleware.verifyToken, authMiddleware.attachUserId, async (req, res) => {
  try {
    const user = await User.findById(req._id);
    res.json(user);
  } catch (error) {
    res.status(500).send("Internal server error");
    console.error(error);
  }
});

// Account deletion endpoint — Apple App Store Guideline 5.1.1(v).
// Hard-deletes the user document plus every collection that references the user.
app.delete(
  "/user/:id",
  authMiddleware.verifyToken,
  authMiddleware.attachUserId,
  async (req, res) => {
    try {
      if (String(req._id) !== String(req.params.id)) {
        return res
          .status(403)
          .send("Forbidden: cannot delete another user's account.");
      }

      const userId = req._id;

      // Cascade delete all user-linked collections. Each is wrapped so a
      // missing/empty collection doesn't block the main user delete.
      const cascades = [
        () => Behavior.deleteMany({ user: userId }),
        () => Goal.deleteMany({ user: userId }),
        () => BehaviorInputs.deleteMany({ user: userId }),
        () => GoalInputs.deleteMany({ user: userId }),
        () => ChatbotResponse.deleteMany({ user: userId }),
      ];
      for (const run of cascades) {
        try {
          await run();
        } catch (cascadeErr) {
          console.error("Cascade delete error:", cascadeErr);
        }
      }

      const deleted = await User.findByIdAndDelete(userId);
      if (!deleted) {
        return res.status(404).send("User not found.");
      }

      return res
        .status(200)
        .json({ message: "Account and associated data deleted." });
    } catch (error) {
      console.error("Account deletion error:", error);
      return res.status(500).send("Internal server error");
    }
  }
);

// Get behaviors by user, date, and goalType
app.get("/dailyBehavior", authMiddleware.verifyToken, authMiddleware.attachUserId, async (req, res) => {
  try {
    if (String(req.query.user) !== String(req._id)) {
      return res.status(403).send("Forbidden: cannot read another user's behaviors.");
    }

    const behaviorToday = await Behavior.find({
      user: req.query.user,
      goalType: req.query.goalType,
      date: req.query.date,
    });
    res.status(200).json(behaviorToday);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.get("/journals-date/v1", authMiddleware.verifyToken, authMiddleware.attachUserId, async (req, res) => {
  try {
    if (String(req.query.userId) !== String(req._id)) {
      return res.status(403).send("Forbidden: cannot read another user's journal dates.");
    }

    const date = new Date(req.query.date);

    const last30Days = [];

    for (let i = 0; i < 30; i++) {
      const prevDate = new Date(date);
      prevDate.setDate(date.getDate() - i);
      const mm = prevDate.getMonth() + 1;
      const dd = prevDate.getDate();
      const yyyy = prevDate.getFullYear();
      last30Days.push(`${mm}/${dd}/${yyyy}`);
    }

    const last30DaysBehavior = await Behavior.find({
      user: req.query.userId,
      date: { $in: last30Days }
    });
    
    const entryDatesForLast30Days = new Set();

    last30DaysBehavior.forEach(item => {
      entryDatesForLast30Days.add(item.date);
    });
    

    res.status(200).json(Array.from(entryDatesForLast30Days));
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

const openaiInstance = new openai({ apiKey: process.env.OPEN_AI_API_KEY });
const handleSave = async () => {
  // Log current selected items, goal inputs, and behavior inputs

  // Prepare the data to be sent
  const data = {
    user: user._id,
    // For activity, screentime, eating, and sleep, make sure values are passed correctly
    activities: selectedItems.activity.reduce((acc, item) => {
      acc[item] = {
        goal: `${goalInputs.activity[item]?.hours || 0} hours ${goalInputs.activity[item]?.minutes || 0} minutes`,
        behavior: `${behaviorInputs.activity[item]?.hours || 0} hours ${behaviorInputs.activity[item]?.minutes || 0} minutes`
      };
      return acc;
    }, {}),
    screentime: selectedItems.screentime.reduce((acc, item) => {
      acc[item] = {
        goal: `${goalInputs.screentime[item]?.hours || 0} hours ${goalInputs.screentime[item]?.minutes || 0} minutes`,
        behavior: `${behaviorInputs.screentime[item]?.hours || 0} hours ${behaviorInputs.screentime[item]?.minutes || 0} minutes`
      };
      return acc;
    }, {}),
    servings: selectedItems.eating.reduce((acc, item) => {
      acc[item] = {
        goal: `${goalInputs.eating[item]?.servings || 0} servings`,
        behavior: `${behaviorInputs.eating[item]?.servings || 0} servings`
      };
      return acc;
    }, {}),
    sleep: {
      bedGoal: goalInputs.sleep["Expected Sleep"]?.bedTime || "0",
      wakeUpGoal: goalInputs.sleep["Expected Sleep"]?.wakeUpTime || "0",
      bedBehavior: behaviorInputs.sleep["Actual Sleep"]?.bedTime || "0",
      wakeUpBehavior: behaviorInputs.sleep["Actual Sleep"]?.wakeUpTime || "0",
    },
  };

  // Log data before sending to the server

  try {
    const response = await axios.post("/chatbot", data);
    setAiResponse(response.data.chat_reply);
  } catch (error) {
    console.error("Error saving behavior: ", error);
  }
};


app.post("/chatbot", authMiddleware.verifyToken, authMiddleware.attachUserId, chatbotLimiter, (req, res) => {
  const prompt = req.body.prompt;
  try {
    openaiInstance.chat.completions
    .create({
      model: "gpt-4o-mini",
      // model="gpt-4",
      messages: [
        {
          role: "system",
          content: /category\d/.test(JSON.stringify(prompt))
            ? "You are an feedback provider who provides feedback to user based on their screen time values\
            You are provided one of 9 categories listed below: based on categories. provide feedback \
            category 1: User did not achieve their goal and their screen time is more than double of their set goal, ask them to reduce there screen time further\
            category 2: User missed their goal but not by more than double, encourage them to work harder and reach the goal\
            category 3: User achieved their screen time goal, congratulate them and ask them to set their actual goal to recommended value \
            category 4: User achieved their set goal and recommended goal, congratulate them got meeting goal and praise them for setting goal better then recommended value \
            category 5: User has reduced their screen time by more than half of their goal value, they are champion and achiever, praise them for their achievement. \
            category 6: User has not yet set their goal or behavior values for screentime; tell them to enter valid values.\
            category 7: User has not yet set a behavior value, tell them that they haven't started working towards their goal yet.\
            category 8: Uer has not yet set a goal value, tell them to remember to set a goal before starting their behaviors.\
            category 9: Praise the user for working towards their goal \
            Keep your feedback encouraging and limited to 60 words\
            If there is a reflection provided as an input, incorporate it into your feedback."
            : "you will be provided a list of behavior/activity types, recommended goals, actual goals, actual values, percentage of actual goal achieved, percenatge of recommended goal achieved \
      you have to provide feedback based on percentage of goal achieved \
      If goal achieved is less than 50%, tell user to put extra effort and give them tips \
      If goal achieved is more than 50%, encourage them to reach the goal and keep it up \
      If they meet their goal, congratulate them and give high five\
      If their set goal is more than the recommended goal, praise them for setting goal more than recommended value \
      If the goal type is screentime, it is better if they do less than the specified goal/recommendation, if their goal and behavior is less than the recommended value congratulate them else encourage them to reduce their screentime  \
      if the goal type is sleep, 8-10 hours are a good range, less than 8 you have to encourage them to sleep more, more than 10 encourage them to have a healthy routine and do some exercise\
      so give feedback for the opposite case.\
      If they achieve more than 120% of goal, They nailed it. \
      Keep your feedback encouraging and limited to 50 words\
      Provide realistic feedback on how they can improve in the future\
      relevant to the goal type; for example, specific fruits/veggies to eat for eating, specific exercise methods for activity,\
      specific alternatives to laptops for screentime, specific sleep methods for sleep.\
      If the set goal is 0, tell the user to set a valid amount for their goal; if their behavior value is 0, tell them that they need to get started. If both values are 0, tell them that they need to save their progress for that goal.\
      If the user provides a reflection associated with the given behavior,\
      incorporate it into your feedback.",
        },
        { role: "user", content: JSON.stringify(prompt) },
      ],
      temperature: 0.9,
      max_tokens: 75,
      top_p: 1,
      frequency_penalty: 0,
      presence_penalty: 0.6,
    })
    .then((response) => {
      const chat_reply = response.choices[0].message.content;
      res.json({ chat_reply });
    });
  } catch (error) {
    console.error("Chatbot error: ", error);
    res.status(500).json({ error: "Chatbot request failed" });
  }
});

app.post("/chatbot/screentime", authMiddleware.verifyToken, authMiddleware.attachUserId, chatbotLimiter, (req, res) => {
  const prompt = req.body.prompt;
  try {
    openaiInstance.chat.completions
    .create({
      model: "gpt-4o-mini",
      // model="gpt-4",
      messages: [
        {
          role: "system",
          content: /category\d/.test(JSON.stringify(prompt))
            ? "You are an feedback provider who provides feedback to user based on their screen time values\
            You are provided one of 9 categories listed below: based on categories. provide feedback \
            category 1: User did not achieve their goal and their screen time is more than double of their set goal, ask them to reduce there screen time further\
            category 2: User missed their goal but not by more than double, encourage them to work harder and reach the goal\
            category 3: User achieved their screen time goal, congratulate them and ask them to set their actual goal to recommended value \
            category 4: User achieved their set goal and recommended goal, congratulate them got meeting goal and praise them for setting goal better then recommended value \
            category 5: User has reduced their screen time by more than half of their goal value, they are champion and achiever, praise them for their achievement. \
            category 6: User has not yet set their goal or behavior values for screentime; tell them to enter valid values.\
            category 7: User has not yet set a behavior value, tell them that they haven't started working towards their goal yet.\
            category 8: Uer has not yet set a goal value, tell them to remember to set a goal before starting their behaviors.\
            category 9: Praise the user for working towards their goal \
            Keep your feedback encouraging and limited to 60 words\
            If there is a reflection provided as an input, incorporate it into your feedback."
            : "you will be provided recommended value, personal goal set, goal achieved and reflection for screentime activity \
      you have to provide feedback based on percentage of goal achieved \
      If goal set or goal achieved is more than recommended value, dont congratulate them, ask them to reduce their screentime further; if goal set is higher ask them to set goal below recommended value, if actual value is higher ask them to reduce time spent on screen\
      If both goal set and goal achieved is less than recommended value but they didnt meet their goal encourage them to keep working towards their goal but congratulate them for keeping screentime below the recommended value \
      If both goal set and goal achieved is less than recommended value and the goals were met, congratulate them for meeting their goal and spending below recommended time on screen \
      Keep your feedback encouraging and limited to 50 words\
      Provide realistic feedback on how they can improve in the future\
      relevant to the goal type; for example, \
      specific alternatives to laptops for screentime,\
      If the set goal is 0, tell the user to set a valid amount for their goal; if their behavior value is 0, tell them that they need to get started. If both values are 0, tell them that they need to save their progress for that goal.\
      If the user provides a reflection associated with the given behavior,\
      incorporate it into your feedback.",
        },
        { role: "user", content: JSON.stringify(prompt) },
      ],
      temperature: 0.9,
      max_tokens: 75,
      top_p: 1,
      frequency_penalty: 0,
      presence_penalty: 0.6,
    })
    .then((response) => {
      const chat_reply = response.choices[0].message.content;
      res.json({ chat_reply });
    });
  } catch (error) {
    console.error("Chatbot error: ", error);
    res.status(500).json({ error: "Chatbot request failed" });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
