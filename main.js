require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { storage } = require("./CloudinaryImages/cloudinaryConfig");
const multer = require("multer");
const path = require("path");

const connection = require("./DatabaseConnection/database");

console.log("env", process.env.CLOUDINARY_API_KEY);

const upload = multer({ storage });

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token required" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

app.post("/register-admin", async (req, res) => {
  try {
    const { name, email, password, address } = req.body;

    if (!name || !email || !password || !address) {
      return res.status(400).send("All fields are required");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const query =
      "INSERT INTO users (username, email, password, address, role) VALUES (?, ?, ?, ?, ?)";
    const values = [name, email, hashedPassword, address, "admin"];

    await connection.query(query, values);

    res.send("Admin registered successfully");
  } catch (err) {
    console.error("Admin Register Error:", err.message);
    res.status(500).send("Server error: " + err.message);
  }
});

app.post("/register-user", async (req, res) => {
  try {
    const { name, email, password, address } = req.body;

    if (!name || !email || !password || !address) {
      return res.status(400).send("All fields are required");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const query =
      "INSERT INTO users (username, email, password, address, role) VALUES (?, ?, ?, ?, ?)";
    const values = [name, email, hashedPassword, address, "user"];

    await connection.query(query, values);

    res.send("User registered successfully");
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).send("Server error: " + err.message);
  }
});

app.post("/register-storeowner", async (req, res) => {
  try {
    const { name, email, password, address } = req.body;

    // Basic validation
    if (!name || !email || !password || !address) {
      return res.status(400).send("All fields are required");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into users table
    const query = `
      INSERT INTO users (username, email, password, address, role)
      VALUES (?, ?, ?, ?, ?)
    `;
    const values = [name, email, hashedPassword, address, "storeowner"];

    await connection.query(query, values);

    res.send("Storeowner registered successfully");
  } catch (err) {
    console.error("Register Storeowner Error:", err.message);
    res.status(500).send("Server error: " + err.message);
  }
});
// 🔐 Update Password Route
app.post("/update-password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: "Both fields are required" });
  }

  try {
    const [results] = await connection.query(
      "SELECT password FROM users WHERE id = ?",
      [userId]
    );

    if (results.length === 0)
      return res.status(404).json({ error: "User not found" });

    const valid = await bcrypt.compare(currentPassword, results[0].password);
    if (!valid)
      return res.status(401).json({ error: "Incorrect current password" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await connection.query("UPDATE users SET password = ? WHERE id = ?", [
      hashedPassword,
      userId,
    ]);

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Update Password Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/owner/stores/ratings", authenticateToken, async (req, res) => {
  const ownerId = req.user.id;

  try {
    const [results] = await connection.query(
      `SELECT 
        s.id AS store_id,
        s.shop_name,
        s.shop_address,
        IFNULL(AVG(r.rating), 0) AS average_rating,
        JSON_ARRAYAGG(
          IF(r.rating IS NOT NULL,
            JSON_OBJECT('user_id', u.id, 'username', u.username, 'rating', r.rating),
            NULL
          )
        ) AS user_ratings
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      LEFT JOIN users u ON u.id = r.user_id
      WHERE s.owner_id = ?
      GROUP BY s.id;`,
      [ownerId]
    );

    const stores = results.map((store) => ({
      ...store,
      user_ratings: (store.user_ratings || []).filter(Boolean),
    }));

    res.json(stores);
  } catch (error) {
    console.error("Dashboard fetch failed:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/", (req, res) => {
  res.send("backend is live");
});

app.get("/storesRating", authenticateToken, async (req, res) => {
  try {
    const [stores] = await connection.execute(`
      SELECT 
        s.id,
        s.shop_name,
        s.shop_address,
        s.shop_email,
        ROUND(AVG(r.rating), 2) AS average_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      GROUP BY s.id, s.shop_name, s.shop_address, s.shop_email
    `);

    res.json(stores);
  } catch (err) {
    console.error("Error fetching stores:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// 🏬 Get Stores

app.get("/store-owners", authenticateToken, async (req, res) => {
  try {
    const [owners] = await connection.execute(
      "SELECT id, username, email FROM users WHERE role = 'storeowner'"
    );
    res.json(owners);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch store owners" });
  }
});

app.post(
  "/stores",
  authenticateToken,
  upload.single("shop_image"),
  async (req, res) => {
    try {
      const { shop_name, shop_email, shop_address, owner_id } = req.body;
      const imageUrl = req.file ? req.file.path : null;

      if (!shop_name || !shop_email || !shop_address || !owner_id) {
        return res.status(400).json({ message: "Missing required fields" });
      }

      await connection.execute(
        "INSERT INTO stores (shop_name, shop_email, shop_address, owner_id, shop_img_url) VALUES (?, ?, ?, ?, ?)",
        [shop_name, shop_email, shop_address, owner_id, imageUrl]
      );

      return res.status(201).json({ message: "Store added successfully" });
    } catch (error) {
      console.error("🔥 Failed to add store:", error);
      return res
        .status(500)
        .json({ message: "Failed to add store", error: error.message });
    }
  }
);

app.get("/stores", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const search = req.query.search || "";

  try {
    const [results] = await connection.query(
      `SELECT 
        s.id, s.shop_name, s.shop_address, s.shop_img_url,s.shop_email,
        IFNULL(AVG(r.rating), 0) AS overall_rating,
        (
          SELECT rating 
          FROM ratings 
          WHERE user_id = ? AND store_id = s.id
          LIMIT 1
        ) AS user_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      WHERE s.shop_name LIKE ? OR s.shop_address LIKE ?
      GROUP BY s.id`,
      [userId, `%${search}%`, `%${search}%`]
    );

    res.json(results);
  } catch (err) {
    console.error("Fetch stores failed", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ⭐ Rate a Store
app.post("/stores/:id/rate", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const storeId = req.params.id;
  const { rating } = req.body;

  try {
    const [existing] = await connection.query(
      "SELECT * FROM ratings WHERE user_id = ? AND store_id = ?",
      [userId, storeId]
    );

    if (existing.length > 0) {
      await connection.query(
        "UPDATE ratings SET rating = ? WHERE user_id = ? AND store_id = ?",
        [rating, userId, storeId]
      );
    } else {
      await connection.query(
        "INSERT INTO ratings (user_id, store_id, rating) VALUES (?, ?, ?)",
        [userId, storeId, rating]
      );
    }

    res.json({ message: "Rating submitted" });
  } catch (err) {
    console.error("Rating error:", err);
    res.status(500).json({ error: "Failed to submit rating" });
  }
});

// 🧑 Register
app.post("/register", async (req, res) => {
  const { name, email, password, address, role } = req.body;

  if (!name || !email || !password || !address || !role) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const [results] = await connection.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (results.length > 0)
      return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await connection.query(
      "INSERT INTO users (username, email, password, address, role) VALUES (?, ?, ?, ?, ?)",
      [name, email, hashedPassword, address, role]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// 🔐 Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  try {
    const [results] = await connection.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (results.length === 0)
      return res.status(401).json({ error: "Invalid username" });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(401).json({ error: "Incorrect password" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// GET all users (admin only)
app.get("/users", authenticateToken, async (req, res) => {
  try {
    const [users] = await connection.execute(`
      SELECT 
  u.id,
  u.username,
  u.email,
  u.address,
  u.role,
  CASE 
    WHEN u.role = 'owner' THEN (
      SELECT ROUND(AVG(r.rating), 2)
      FROM stores s
      JOIN ratings r ON s.id = r.store_id
      WHERE s.owner_id = u.id
    )
    ELSE NULL
  END AS rating
FROM users u;

    `);

    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
