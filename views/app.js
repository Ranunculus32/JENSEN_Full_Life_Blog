const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");
const flash = require("connect-flash");
const MongoDBStore = require("connect-mongodb-session")(session);
const mongoose = require("mongoose");
const port = 8000;
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
app.use(express.json());
app.use(flash());

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

app.get("/index", (req, res) => res.render("index"));
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
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Log the received request payload
    console.log("Received login request:", { username, password });

    // Find the user in the database
    const user = await User.findOne({ username });

    // Log the user found in the database
    console.log("User found in the database:", user);

    if (user) {
      // Check if the provided password matches the hashed password in the database
      const isPasswordMatched = await bcrypt.compare(password, user.password);

      if (isPasswordMatched) {
        // Set the user session
        req.session.user = { username, userId: user.userId };
        const clientExpectation = req.get("Content-Type");

        if (clientExpectation === "application/json") {
          res.json({ success: true, message: "Login successful" });
        } else {
          res.redirect("/create-blog");
        }
      } else {
        console.log("Incorrect password");
        res.json({ success: false, message: "Invalid login credentials" });
      }
    } else {
      console.log("User not found");
      res.json({ success: false, message: "User not found" });
    }
  } catch (error) {
    console.error("Server error during login:", error);
    res.status(500).json({
      success: false,
      message: `Server error during login: ${error.message}`,
    });
  }
});

// Regular user routes
app.get("/create-blog", isAuthenticatedUser);
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
