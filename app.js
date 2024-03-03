const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");
const flash = require("connect-flash");
const MongoDBStore = require("connect-mongodb-session")(session);
const mongoose = require("mongoose");
const port = 8000;
const axios = require("axios");
const clientID = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const {
  isAdminUser,
  isAuthenticatedUser,
  isRegisterUser,
  logoutUser,
} = require("./middleware/user_Middleware");
const {
  createBlogPost,
  getAllBlogPosts,
} = require("./controller/blog_Controller");

const { User } = require("./models/User_Model");
const bcrypt = require("bcrypt");
const app = express();
require("dotenv").config();

// Middleware
// app.use(express.json());
app.use(flash());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session and Flash Middleware
const store = new MongoDBStore({
  uri: process.env.MONGODB_URL,
  collection: "sessions",
});

app.use(
  session({
    secret: process.env.secretKey,
    resave: false,
    saveUninitialized: true,
    store: store,
  })
);

app.get("/home", (req, res) => res.render("index"));
app.get("/register", (req, res) => res.render("register"));
app.get("/about", (req, res) => res.render("about"));
app.get("/login", (req, res) => {
  res.render("login", {
    successMessage: req.flash("successMessage"),
  });
});
app.get("/logout", logoutUser);

// Handle user input in regular users

app.post("/register", isRegisterUser, (req, res) => {
  if (req.session.user) {
    req.session.user = {
      username: req.body.username,
      userId: req.session.user.userId,
    };
    req.flash("successMessage", "User registration successful");
    res.redirect(`/login?username=${encodeURIComponent(req.body.username)}`);
  } else {
    res.status(401).json({ success: false, message: "Registration failed" });
  }
});

app.post("/login", function (req, res) {
  const { username, password } = req.body;

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        return res.status(401).json({ error: "The user does not exist" });
      } else {
        if (!bcrypt.compareSync(password, user.password)) {
          return res.status(401).json({ error: "Incorrect password" });
        } else {
          return res.status(200).json({ message: "Successful login" });
        }
      }
    })
    .catch((err) => {
      // Handle the error separately
      console.error("Error occurred during login:", err);
      return res
        .status(500)
        .json({ error: "Some error occurred unexpectedly" });
    });
});

app.get("/login/github", (req, res) => {
  const requestToken = req.query.code;

  axios({
    method: "post",
    url: `https://github.com/login/oauth/access_token?client_id=${clientID}&client_secret=${clientSecret}&code=${requestToken}`,
    headers: {
      accept: "application/json",
    },
  })
    .then((response) => {
      const accessToken = response.data.access_token;
      console.log(response.data);
      res.redirect("/login/create-blog");
      // res.redirect(`/create-blog?access_token=${accessToken}`);
    })
    .catch((error) => {
      console.error("Error occurred during access token request:", error);
      res.status(500).send("Error occurred during access token request");
    });
});

app.get("/login/create-blog", (req, res) => res.render("create-blog"));
app.post("/login/create-blog", createBlogPost);


// Regular user routes
app.get("/create-blog", isAuthenticatedUser);
app.get("/create-blog", isAdminUser);
app.post("/create-blog", isAdminUser, createBlogPost);
app.post("/create-blog", isAuthenticatedUser, createBlogPost); // Only authenticated users can create a blog post
app.get("/blogs", isAuthenticatedUser, getAllBlogPosts); // Only authenticated users can view their own blog posts

// Admin routes
app.get("/admin-login", (req, res) => {
  res.render("admin-login");
});

app.post("/admin-login", isAdminUser, async (req, res) => {
  try {
    if (req.session.user && req.session.user.role === "admin") {
      req.session.adminSuccessMessage = "Admin login successful";
      res.json({ success: true });
      res.render("admin");
    } else {
      res
        .status(401)
        .json({ success: false, message: "Invalid admin credentials" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "An error occurred during admin login.",
    });
  }
});

app.use("/admin", isAdminUser); // Middleware to check if the user is an admin for the following routes
app.get("/admin", isAdminUser, (req, res) => {
  res.render("admin");
});
app.get("/admin/blogs", getAllBlogPosts); // Admins can view all blog posts

// Static files and views
app.use(express.static(path.join(__dirname, "public")));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => console.log("DB Connection Successful!"))
  .catch((err) => console.log(err));

// Start the server
app.listen(port, () =>
  console.log(`Backend server is running on port ${port}!`)
);
