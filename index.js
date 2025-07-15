const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs"); 
const path = require("path");
const encrypt = require("mongoose-encryption");
require("dotenv").config();


const app = express();

const session = require("express-session");

app.use(session({
  secret: "thisisasecretkey",
  resave: false,
  saveUninitialized: false
}));

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs"); 
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));


const mongoose = require("mongoose");
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log("MongoDB connection error:", err));

  const trySchema = new mongoose.Schema({
  email: String,
  password: String
});

trySchema.plugin(encrypt, {
  secret: process.env.SECRET,
  encryptedFields: ["password"]
});
const Item = mongoose.model("second", trySchema);

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/register", function (req, res) {
  res.render("register");
});


app.post("/register", async function(req, res) {
  console.log("Register POST hit");

  const password = req.body.password;

  // Strong password pattern check
  const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  if (!passwordRegex.test(password)) {
    return res.status(400).send("Password must be at least 8 characters long and include letters, numbers, and special characters.");
  }

  try {
    const newUser = new Item({
      email: req.body.username,
      password: password
    });

    await newUser.save();
    console.log("User saved successfully");

    res.render("login");
  } catch (err) {
    console.error("Error saving user:", err);
    res.status(500).send("Error saving data");
  }
});




app.post("/login", async function(req, res) {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const foundUser = await Item.findOne({ email: username });

    if (foundUser) {
      if (foundUser.password === password) {
        res.render("secrets");
      } else {
        res.send("Incorrect password.");
      }
    } else {
      res.send("No user found with that email.");
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Server error");
  }
});

app.get("/login", function (req, res) {
  res.render("login")
});

app.get("/logout", function (req, res) {
  req.session.destroy(function (err) {
    if (err) {
      console.log("Logout error:", err);
    }
    res.redirect("/");
  });
});


app.listen(3000, function () {
    console.log("Server started on port 3000");
});
