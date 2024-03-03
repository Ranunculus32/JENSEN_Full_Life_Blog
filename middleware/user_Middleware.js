const bcrypt = require("bcrypt");
const { User } = require("../models/User_Model");

const isAdminUser = async (req, res, next) => {
  const { username, password, isAdmin } = req.body;
  try {
    if (isAdmin) {
      const adminUsername = process.env.ADMIN_USERNAME;
      const adminPassword = process.env.ADMIN_PASSWORD;

      if (username === adminUsername && password === adminPassword) {
        req.session.user = { username: adminUsername, role: "admin" };
        next();
      } else {
        res.status(401).send("Invalid admin credentials");
      }
    } else {
      next();
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error during admin login.");
  }
};

function isGenerateUserId() {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return timestamp + random;
}

const isRegisterUser = async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Username is already taken.",
      });
    }
    console.log("Attempting to register user:", username);
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      password: hashedPassword,
      userId: isGenerateUserId(),
    });

    await user.save();
    console.log("User registered successfully");
    res.status(201).json({
      success: true,
      message: "Registration successful. Redirecting to login page.",
    });
  } catch (error) {
    console.error("Error during user registration:", error);
    res.status(500).json({
      success: false,
      message: "Server error during user registration.",
    });
  }
};

const isAuthenticatedUser = async (req, res, next) => {
  try {
    const { username, password } = req.body;

    console.log("Request body:", req.body);

    // Case-sensitive query to find the user
    const user = await User.findOne({ username });

    console.log("User found in the database:", user);

    if (user) {
      console.log("Hashed password during login:", user.password);

      const isPasswordMatched = await bcrypt.compare(password, user.password);

      if (isPasswordMatched) {
        req.session.user = { username, userId: user.userId };
        res.redirect("/create-blog");
      } else {
        console.error(
          "Incorrect password. Hashed:",
          user.password,
          "Input:",
          password.trim()
        );
        res.json({ success: false, message: "Incorrect password" });
      }
    } else {
      res.json({ success: false, message: "User not found" });
    }
  } catch (error) {
    console.error("Error during user authentication:", error);
    res.status(500).send("Server error upon login");
  }
};

const logoutUser = (req, res, next) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      res.status(500).send("Error logging out");
    } else {
      res.redirect("/login");
    }
  });
};
module.exports = {
  isAdminUser,
  isAuthenticatedUser,
  isRegisterUser,
  logoutUser,
};
