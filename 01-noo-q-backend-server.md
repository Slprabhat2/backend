# Noo-Q Backend - Complete API Server

## 🚀 Express.js Server Setup

```javascript
// server.js - Main server file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const socketIo = require('socket.io');
const http = require('http');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URLS?.split(',') || ["http://localhost:3000"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
  }
});

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const providerRoutes = require('./routes/providers');
const appointmentRoutes = require('./routes/appointments');
const serviceRoutes = require('./routes/services');
const paymentRoutes = require('./routes/payments');
const notificationRoutes = require('./routes/notifications');
const qrRoutes = require('./routes/qr');
const analyticsRoutes = require('./routes/analytics');
const inventoryRoutes = require('./routes/inventory');
const adminRoutes = require('./routes/admin');

// Import middleware
const { errorHandler } = require('./middleware/errorHandler');
const { notFound } = require('./middleware/notFound');
const logger = require('./utils/logger');

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Compression middleware
app.use(compression());

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.FRONTEND_URLS?.split(',') || [
      'http://localhost:3000',
      'https://admin.noo-q.com',
      'https://providers.noo-q.com',
      'https://app.noo-q.com',
      'https://noo-q.com'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));

// Logging middleware
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
} else {
  app.use(morgan('dev'));
}

// Database connection
const connectDatabase = async () => {
  try {
    const connection = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/nooq', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    logger.info(`MongoDB connected: ${connection.connection.host}`);
    
    // Set up database indexes for optimization
    await createDatabaseIndexes();
    
  } catch (error) {
    logger.error('Database connection error:', error);
    process.exit(1);
  }
};

// Create database indexes for performance
const createDatabaseIndexes = async () => {
  try {
    const User = require('./models/User');
    const Provider = require('./models/Provider');
    const Appointment = require('./models/Appointment');
    const Service = require('./models/Service');
    const Payment = require('./models/Payment');
    
    // User indexes
    await User.collection.createIndex({ email: 1 }, { unique: true });
    await User.collection.createIndex({ phone: 1 });
    await User.collection.createIndex({ role: 1 });
    
    // Provider indexes
    await Provider.collection.createIndex({ email: 1 }, { unique: true });
    await Provider.collection.createIndex({ status: 1 });
    await Provider.collection.createIndex({ category: 1 });
    await Provider.collection.createIndex({ 'location.coordinates': '2dsphere' });
    
    // Appointment indexes
    await Appointment.collection.createIndex({ providerId: 1, date: 1 });
    await Appointment.collection.createIndex({ customerId: 1, createdAt: -1 });
    await Appointment.collection.createIndex({ status: 1 });
    await Appointment.collection.createIndex({ date: 1, time: 1 });
    
    // Service indexes
    await Service.collection.createIndex({ providerId: 1 });
    await Service.collection.createIndex({ category: 1 });
    await Service.collection.createIndex({ isActive: 1 });
    
    // Payment indexes
    await Payment.collection.createIndex({ orderId: 1 }, { unique: true });
    await Payment.collection.createIndex({ customerId: 1, createdAt: -1 });
    await Payment.collection.createIndex({ providerId: 1, createdAt: -1 });
    await Payment.collection.createIndex({ status: 1 });
    
    logger.info('Database indexes created successfully');
  } catch (error) {
    logger.error('Error creating database indexes:', error);
  }
};

// Socket.io connection handling
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}`);
  
  // Join user-specific rooms for real-time updates
  socket.on('join', (data) => {
    const { userId, userType } = data;
    socket.join(`user_${userId}`);
    socket.join(`${userType}_updates`);
    
    logger.info(`User ${userId} (${userType}) joined real-time updates`);
  });
  
  // Handle provider status updates
  socket.on('provider_status_update', (data) => {
    socket.broadcast.to('admin_updates').emit('provider_status_changed', data);
  });
  
  // Handle new appointment notifications
  socket.on('new_appointment', (data) => {
    socket.to(`user_${data.providerId}`).emit('appointment_received', data);
    socket.broadcast.to('admin_updates').emit('new_booking', data);
  });
  
  // Handle appointment status updates
  socket.on('appointment_status_update', (data) => {
    socket.to(`user_${data.customerId}`).emit('appointment_updated', data);
    socket.to(`user_${data.providerId}`).emit('appointment_updated', data);
  });
  
  // Handle payment notifications
  socket.on('payment_completed', (data) => {
    socket.to(`user_${data.customerId}`).emit('payment_success', data);
    socket.to(`user_${data.providerId}`).emit('payment_received', data);
    socket.broadcast.to('admin_updates').emit('payment_processed', data);
  });
  
  socket.on('disconnect', () => {
    logger.info(`Client disconnected: ${socket.id}`);
  });
});

// Make io available to routes
app.set('io', io);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    version: process.env.npm_package_version || '1.0.0'
  });
});

// API routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/providers', providerRoutes);
app.use('/api/v1/appointments', appointmentRoutes);
app.use('/api/v1/services', serviceRoutes);
app.use('/api/v1/payments', paymentRoutes);
app.use('/api/v1/notifications', notificationRoutes);
app.use('/api/v1/qr', qrRoutes);
app.use('/api/v1/analytics', analyticsRoutes);
app.use('/api/v1/inventory', inventoryRoutes);
app.use('/api/v1/admin', adminRoutes);

// Welcome route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Noo-Q API Server',
    version: '1.0.0',
    documentation: '/api/v1/docs',
    status: 'active',
    endpoints: {
      auth: '/api/v1/auth',
      users: '/api/v1/users',
      providers: '/api/v1/providers',
      appointments: '/api/v1/appointments',
      services: '/api/v1/services',
      payments: '/api/v1/payments',
      notifications: '/api/v1/notifications',
      qr: '/api/v1/qr',
      analytics: '/api/v1/analytics',
      inventory: '/api/v1/inventory',
      admin: '/api/v1/admin'
    }
  });
});

// 404 handler
app.use(notFound);

// Error handling middleware
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received');
  server.close(() => {
    logger.info('Process terminated');
    mongoose.connection.close(false, () => {
      logger.info('MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received');
  server.close(() => {
    logger.info('Process terminated');
    mongoose.connection.close(false, () => {
      logger.info('MongoDB connection closed');
      process.exit(0);
    });
  });
});

// Start server
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    await connectDatabase();
    
    server.listen(PORT, () => {
      logger.info(`🚀 Noo-Q API Server running on port ${PORT}`);
      logger.info(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`🗄️  Database: MongoDB`);
      logger.info(`🔒 Security: Enabled`);
      logger.info(`📡 WebSocket: Enabled`);
      logger.info(`📖 Documentation: http://localhost:${PORT}/api/v1/docs`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

module.exports = { app, server, io };
```

## 📦 Package.json Configuration

```json
{
  "name": "noo-q-backend",
  "version": "1.0.0",
  "description": "Complete backend API for Noo-Q appointment booking platform",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest --coverage",
    "test:watch": "jest --watch",
    "seed": "node scripts/seedDatabase.js",
    "migrate": "node scripts/migrate.js",
    "build": "echo 'No build required for Node.js'",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix",
    "docs": "swagger-jsdoc -d swaggerConfig.js -o swagger.json"
  },
  "keywords": [
    "appointment",
    "booking",
    "noo-q",
    "api",
    "backend",
    "express",
    "mongodb",
    "nodejs"
  ],
  "author": "Noo-Q Development Team",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.8.1",
    "compression": "^1.7.4",
    "morgan": "^1.10.0",
    "dotenv": "^16.3.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "joi": "^17.9.2",
    "multer": "^1.4.5-lts.1",
    "cloudinary": "^1.40.0",
    "nodemailer": "^6.9.4",
    "razorpay": "^2.9.2",
    "twilio": "^4.15.0",
    "axios": "^1.5.0",
    "qrcode": "^1.5.3",
    "uuid": "^9.0.0",
    "moment": "^2.29.4",
    "lodash": "^4.17.21",
    "socket.io": "^4.7.2",
    "winston": "^3.10.0",
    "cron": "^2.4.4",
    "validator": "^13.11.0",
    "crypto": "^1.0.1",
    "sharp": "^0.32.5",
    "csv-parser": "^3.0.0",
    "excel4node": "^1.8.2",
    "pdf-kit": "^0.13.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.6.2",
    "supertest": "^6.3.3",
    "eslint": "^8.47.0",
    "eslint-config-airbnb-base": "^15.0.0",
    "eslint-plugin-import": "^2.28.0",
    "swagger-jsdoc": "^6.2.8",
    "swagger-ui-express": "^5.0.0"
  },
  "engines": {
    "node": ">=16.0.0",
    "npm": ">=8.0.0"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/your-org/noo-q-backend.git"
  },
  "bugs": {
    "url": "https://github.com/your-org/noo-q-backend/issues"
  },
  "homepage": "https://noo-q.com"
}
```

## 🔧 Environment Configuration

```bash
# .env file template

# Server Configuration
NODE_ENV=development
PORT=5000
API_VERSION=v1

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/nooq
# For MongoDB Atlas: mongodb+srv://username:password@cluster.mongodb.net/nooq

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-min-32-characters
JWT_EXPIRE=7d
JWT_REFRESH_SECRET=your-refresh-token-secret
JWT_REFRESH_EXPIRE=30d

# Frontend URLs (comma separated)
FRONTEND_URLS=http://localhost:3000,https://admin.noo-q.com,https://providers.noo-q.com,https://app.noo-q.com,https://noo-q.com

# Payment Gateway (Razorpay)
RAZORPAY_KEY_ID=rzp_test_your_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret

# WhatsApp Business API
WHATSAPP_ACCESS_TOKEN=your_whatsapp_business_access_token
WHATSAPP_PHONE_NUMBER_ID=your_phone_number_id
WHATSAPP_BUSINESS_ACCOUNT_ID=your_business_account_id

# SMS Service (Twilio)
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=+1234567890

# Email Service
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
EMAIL_FROM=noreply@noo-q.com

# File Storage (Cloudinary)
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret

# Redis (for sessions and caching)
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=info
LOG_FILE=logs/app.log

# Security
BCRYPT_SALT_ROUNDS=12
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX_REQUESTS=1000

# Business Configuration
PLATFORM_CONVENIENCE_FEE=5
PLATFORM_COMMISSION=2
DEFAULT_CURRENCY=INR
DEFAULT_TIMEZONE=Asia/Kolkata

# External APIs
GOOGLE_MAPS_API_KEY=your_google_maps_api_key
GOOGLE_ANALYTICS_ID=your_analytics_id

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_FREQUENCY=daily
BACKUP_RETENTION_DAYS=30

# Development Only
DEBUG_MODE=true
SWAGGER_ENABLED=true
```

## 🗄️ Database Models Schema

```javascript
// models/User.js - User model
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(email) {
        return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(email);
      },
      message: 'Please enter a valid email address'
    }
  },
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    validate: {
      validator: function(phone) {
        return /^[+]?[1-9][\d\s\-\(\)]{7,15}$/.test(phone);
      },
      message: 'Please enter a valid phone number'
    }
  },
  password: {
    type: String,
    required: function() {
      return !this.isOAuthUser;
    },
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['customer', 'provider', 'admin'],
    default: 'customer'
  },
  avatar: {
    type: String,
    default: null
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  isPhoneVerified: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isOAuthUser: {
    type: Boolean,
    default: false
  },
  oauthProvider: {
    type: String,
    enum: ['google', 'facebook', 'apple'],
    default: null
  },
  oauthId: {
    type: String,
    default: null
  },
  loyaltyPoints: {
    type: Number,
    default: 0,
    min: 0
  },
  loyaltyTier: {
    type: String,
    enum: ['bronze', 'silver', 'gold', 'platinum'],
    default: 'bronze'
  },
  totalSpent: {
    type: Number,
    default: 0,
    min: 0
  },
  preferences: {
    notifications: {
      whatsapp: { type: Boolean, default: true },
      sms: { type: Boolean, default: true },
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    },
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'Asia/Kolkata' },
    currency: { type: String, default: 'INR' }
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: { type: String, default: 'India' }
  },
  lastLogin: {
    type: Date,
    default: null
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  phoneVerificationOTP: String,
  phoneVerificationExpires: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  refreshTokens: [{
    token: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
    device: String,
    ipAddress: String
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for total appointments
userSchema.virtual('totalAppointments', {
  ref: 'Appointment',
  localField: '_id',
  foreignField: 'customerId',
  count: true
});

// Index for performance
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ role: 1 });
userSchema.index({ loyaltyTier: 1 });
userSchema.index({ createdAt: -1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

// Method to update loyalty tier based on total spent
userSchema.methods.updateLoyaltyTier = function() {
  if (this.totalSpent >= 50000) {
    this.loyaltyTier = 'platinum';
  } else if (this.totalSpent >= 20000) {
    this.loyaltyTier = 'gold';
  } else if (this.totalSpent >= 5000) {
    this.loyaltyTier = 'silver';
  } else {
    this.loyaltyTier = 'bronze';
  }
};

// Method to add loyalty points
userSchema.methods.addLoyaltyPoints = function(points) {
  this.loyaltyPoints += points;
  this.updateLoyaltyTier();
};

// Method to generate email verification token
userSchema.methods.generateEmailVerificationToken = function() {
  const crypto = require('crypto');
  const token = crypto.randomBytes(32).toString('hex');
  this.emailVerificationToken = crypto.createHash('sha256').update(token).digest('hex');
  this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  return token;
};

// Method to generate password reset token
userSchema.methods.generatePasswordResetToken = function() {
  const crypto = require('crypto');
  const token = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(token).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return token;
};

// Method to generate phone OTP
userSchema.methods.generatePhoneOTP = function() {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  this.phoneVerificationOTP = otp;
  this.phoneVerificationExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return otp;
};

// Remove password from JSON output
userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  delete userObject.password;
  delete userObject.emailVerificationToken;
  delete userObject.emailVerificationExpires;
  delete userObject.phoneVerificationOTP;
  delete userObject.phoneVerificationExpires;
  delete userObject.passwordResetToken;
  delete userObject.passwordResetExpires;
  delete userObject.refreshTokens;
  return userObject;
};

module.exports = mongoose.model('User', userSchema);
```

This is the beginning of your complete Noo-Q backend system. I'm building:

1. ✅ **Express.js server** with security, CORS, rate limiting
2. ✅ **MongoDB connection** with automatic indexing
3. ✅ **WebSocket integration** for real-time updates
4. ✅ **Complete User model** with authentication
5. ✅ **Package.json** with all required dependencies
6. ✅ **Environment configuration** template

Let me continue with the database models and API routes...