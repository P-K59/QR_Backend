require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000'
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/qr-menu')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Menu Item Schema
const menuItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  price: { type: Number, required: true },
  category: String,
  image: String,
  available: { type: Boolean, default: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false }
});

const MenuItem = mongoose.model('MenuItem', menuItemSchema);

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  restaurantName: String,
  tables: [Number],
  profilePicture: String,
  bannerImage: String,
  resetToken: String,
  resetTokenExpiry: Date
});
const User = mongoose.model('User', userSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  items: [{
    menuItem: { type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem', required: false },
    menuItemName: String,
    price: Number,
    quantity: { type: Number, default: 1 }
  }],
  tableNumber: Number,
  customerName: String,
  status: { type: String, default: 'pending' },
  totalAmount: Number,
  restaurantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  createdAt: { type: Date, default: Date.now }
});

const Order = mongoose.model('Order', orderSchema);

// User Routes
app.post('/api/users/register', async (req, res) => {
  try {
    const { email, password, restaurantName, tables } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'User already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, restaurantName, tables });
    await user.save();
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    res.json({ message: 'Registered', token, userId: user._id });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Registration failed' });
  }
});

app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    res.json({ token, userId: user._id });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed' });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const { restaurantName, tables, profilePicture, bannerImage } = req.body;
    
    // Validate input
    if (!restaurantName || !restaurantName.trim()) {
      return res.status(400).json({ message: 'Restaurant name is required' });
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { restaurantName, tables, profilePicture, bannerImage },
      { new: true }
    ).select('-password');
    
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ message: error.message || 'Failed to update profile' });
  }
});

app.post('/api/users/:id/change-password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(400).json({ message: 'Current password is incorrect' });
    
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    await user.save();
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/users/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Email not found' });

    // Generate reset token (6-digit code for simplicity, or use longer token)
    const resetToken = Math.random().toString(36).substring(2, 8).toUpperCase();
    const resetTokenExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();

    // Send email with reset token
    const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}&email=${email}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request - QR Menu',
      html: `
        <h2>Password Reset Request</h2>
        <p>You requested to reset your password. Your reset code is:</p>
        <h3 style="color: #2196F3; font-size: 24px; letter-spacing: 2px;">${resetToken}</h3>
        <p>This code will expire in 30 minutes.</p>
        <p>Or click the link below:</p>
        <a href="${resetLink}" style="color: #2196F3;">Reset Password</a>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Failed to send reset email' });
  }
});

app.post('/api/users/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    if (!email || !token || !newPassword) {
      return res.status(400).json({ message: 'Email, token, and new password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    // Check if token is valid and not expired
    if (!user.resetToken || user.resetToken !== token) {
      return res.status(400).json({ message: 'Invalid reset token' });
    }

    if (new Date() > user.resetTokenExpiry) {
      return res.status(400).json({ message: 'Reset token has expired' });
    }

    // Update password
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Failed to reset password' });
  }
});

// Menu Routes
app.get('/api/menu', async (req, res) => {
  try {
    const menuItems = await MenuItem.find();
    res.json(menuItems);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/menu/:userId', async (req, res) => {
  try {
    const menuItems = await MenuItem.find({ owner: req.params.userId });
    res.json(menuItems);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/menu', async (req, res) => {
  try {
    const { name, description, price, category, image, owner } = req.body;
    const item = new MenuItem({ name, description, price, category, image, owner: owner || null });
    const saved = await item.save();
    res.json(saved);
  } catch (err) {
    console.error('Create menu error:', err);
    res.status(500).json({ message: 'Failed to create menu item' });
  }
});

app.put('/api/menu/:id', async (req, res) => {
  try {
    // Extract only the fields that should be updatable
    const { name, description, price, category, image, available } = req.body;
    const updateData = { name, description, price, category, image, available };
    
    // Remove undefined fields
    Object.keys(updateData).forEach(key => updateData[key] === undefined && delete updateData[key]);
    
    const updated = await MenuItem.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updated) return res.status(404).json({ message: 'Item not found' });
    res.json(updated);
  } catch (err) {
    console.error('Update menu error:', err);
    res.status(500).json({ message: 'Failed to update item' });
  }
});

app.delete('/api/menu/:id', async (req, res) => {
  try {
    const removed = await MenuItem.findByIdAndDelete(req.params.id);
    if (!removed) return res.status(404).json({ message: 'Item not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete menu error:', err);
    res.status(500).json({ message: 'Failed to delete item' });
  }
});

// Order Routes
app.post('/api/orders', async (req, res) => {
  try {
    const raw = req.body;
    const items = (raw.items || []).map(i => ({
      menuItem: i.menuItem || null,
      menuItemName: i.menuItemName || i.name || 'Unknown Item',
      price: i.price !== undefined ? i.price : 0,
      quantity: i.quantity || 1
    }));

    const order = new Order({
      items,
      tableNumber: raw.tableNumber,
      customerName: raw.customerName || '',
      totalAmount: raw.totalAmount || 0,
      restaurantId: raw.restaurantId || null
    });

    const savedOrder = await order.save();

    try {
      const restId = raw.restaurantId;
      if (restId) {
        io.to(restId.toString()).emit('newOrder', savedOrder);
      } else {
        io.emit('newOrder', savedOrder);
      }
    } catch (emitErr) {
      console.error('Socket emit error:', emitErr);
    }

    res.status(201).json(savedOrder);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/api/orders', async (req, res) => {
  try {
    // Get restaurantId from query params
    const restaurantId = req.query.restaurantId;
    
    if (!restaurantId) {
      return res.status(400).json({ message: 'restaurantId is required' });
    }
    
    // Filter orders by restaurantId matching the logged-in user
    const orders = await Order.find({ restaurantId: restaurantId })
      .populate('items.menuItem')
      .sort({ createdAt: -1 });
    
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put('/api/orders/:id', async (req, res) => {
  try {
    const { status } = req.body;
    const validStatuses = ['pending', 'process', 'complete', 'cancelled'];
    
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate('items.menuItem');

    if (!updatedOrder) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Emit update via socket
    try {
      const restId = updatedOrder.restaurantId;
      if (restId) {
        io.to(restId.toString()).emit('orderUpdated', updatedOrder);
      } else {
        io.emit('orderUpdated', updatedOrder);
      }
    } catch (emitErr) {
      console.error('Socket emit error:', emitErr);
    }

    res.json(updatedOrder);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Server & Socket.io
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  socket.on('join', (room) => {
    if (room) {
      socket.join(room);
      console.log(`Socket ${socket.id} joined room ${room}`);
    }
  });

  socket.on('menuUpdated', (updatedItem) => {
    // Broadcast to all clients in the restaurant's room
    const restaurantId = updatedItem.owner;
    if (restaurantId) {
      io.to(restaurantId.toString()).emit('menuUpdated', updatedItem);
      console.log(`Menu updated for restaurant ${restaurantId}`);
    } else {
      io.emit('menuUpdated', updatedItem);
    }
  });

  socket.on('disconnect', () => {
    console.log('Socket disconnected:', socket.id);
  });
});