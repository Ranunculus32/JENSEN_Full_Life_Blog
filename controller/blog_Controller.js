const { Blog } = require("../models/Blog_model");

const createBlogPost = async (req, res) => {
  try {
    const { title, body } = req.body;
    const { userId } = req.session.user;

    const blogPost = new Blog({
      title,
      body,
      userId,
    });

    await blogPost.save();

    // Redirect to /blogs after successful blog post
    res.redirect("/blogs");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error creating blog post");
  }
};

const getAllBlogPosts = async (req, res) => {
  try {
    const { user } = req.session;

    if (user && user.role === "admin") {
      // If user is admin, show all blog posts
      const blogPosts = await Blog.find();
      res.json(blogPosts);
    } else {
      // If user is not admin, show only their own blog posts
      const { userId } = user;
      const userBlogPosts = await Blog.find({ userId });
      res.json(userBlogPosts);
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error retrieving blog posts");
  }
};

const deleteBlogPost = async (req, res) => {
  try {
    const { id } = req.params;

    // Check if the user is an admin
    const { user } = req.session;
    if (user && user.role === "admin") {
      // If admin, proceed with deleting the blog post
      const result = await Blog.findByIdAndDelete(id);

      if (result) {
        res.sendStatus(204);
      } else {
        res.status(404).send("Blog post not found");
      }
    } else {
      // If not admin, unauthorized to delete
      res.status(403).send("Unauthorized to delete blog post");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error deleting blog post");
  }
};

module.exports = {
  createBlogPost,
  getAllBlogPosts,
  deleteBlogPost,
};
