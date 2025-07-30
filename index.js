const express = require("express");
const bodyParser = require("body-parser"); 
const ejs = require("ejs");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();


app.use(express.json());

app.use(cookieParser());
app.use(session({
  secret: process.env.SECRET || "thisisasecretkey",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true
  }
}));



app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));


const mongoose = require("mongoose");
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));


const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secrets: {
    type: [String],
    default: [] 
  }
});

const User = mongoose.model("User", userSchema);
function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}


app.get("/", (req, res) => {
  const message = req.cookies.logoutMessage;
  res.clearCookie("logoutMessage"); 
  res.render("home", { message });
});


app.get("/register", (req, res) => res.render("register", { error: null }));

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  if (!passwordRegex.test(password)) {
    return res.render("register", {
      error: "Password must be at least 8 characters, contain a letter, a number, and a special character."
    });
  }

  try {
    const existingUser = await User.findOne({ email: username });
    if (existingUser) {
      return res.render("register", {
        error: "🚫 This email is already registered. Please use a different one or log in."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email: username, password: hashedPassword });
    await newUser.save();
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.status(500).send("Registration failed.");
  }
});


app.get("/login", (req, res) => res.render("login", { error: null }));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ email: username });
    if (!user) return res.render("login", { error: "User not found." });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.render("login", { error: "Incorrect password." });
    req.session.user = user.email;
    res.redirect("/secrets");
  } catch (err) {
    console.error(err);
    res.status(500).send("Login failed.");
  }
});


app.get("/secrets", isAuthenticated, async (req, res) => {
  try {
    const allUsers = await User.find({ secrets: { $exists: true, $not: { $size: 0 } } });
    const sessionUser = req.session.user;
    const currentUser = allUsers.find(u => u.email === sessionUser);
    const otherUsers = allUsers.filter(u => u.email !== sessionUser);
    const message = req.session.message;
    req.session.message = null;
    res.render("secrets", {
      currentUser,
      otherUsers,
      sessionUser,
      editEmail: req.query.edit,
      editIndex: req.query.index,
      message
    });
  } catch (err) {
    res.status(500).send("Could not load secrets.");
  }
});


app.put("/update-secret", isAuthenticated, async (req, res) => {
  const { updatedSecret, index } = req.body;
  try {
    const user = await User.findOne({ email: req.session.user });
    if (user && user.secrets && user.secrets.length > index) {
      user.secrets[index] = updatedSecret;
      await user.save();
      req.session.message = "Your secret has been updated successfully.";
      res.status(200).json({ message: "Secret updated." });
    } else {
      res.status(400).json({ error: "Invalid secret index." });
    }
  } catch (err) {
    console.error("Error updating secret:", err);
    res.status(500).json({ error: "Failed to update secret." });
  }
});


app.get("/submit", isAuthenticated, (req, res) => res.render("submit"));

app.post("/submit", isAuthenticated, async (req, res) => {
  const secret = req.body.secret;
  try {
    const user = await User.findOne({ email: req.session.user });
    if (user) {
      
      if (!Array.isArray(user.secrets)) {
        user.secrets = [];
      }

      user.secrets.push(secret);
      await user.save();
      res.redirect("/secrets");
    } else {
      res.redirect("/login");
    }
  } catch (err) {
    console.error("Error submitting secret:", err);
    res.status(500).send("Failed to submit secret.");
  }
});


app.get("/logout", (req, res) => {
  const logoutMessage = " You have logged out successfully.";

  req.session.destroy(err => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).send("Logout failed.");
    }
    res.cookie("logoutMessage", logoutMessage, { maxAge: 3000, httpOnly: true });
    res.redirect("/");
  });
});


app.listen(3000, () => console.log("Server running on port 3000"));