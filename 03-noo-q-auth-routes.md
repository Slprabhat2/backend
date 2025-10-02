# Noo-Q Backend - Authentication & User Routes

## 🔐 Authentication System

### JWT Authentication Middleware

```javascript
// middleware/auth.js - JWT Authentication middleware
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

// Protect routes - requires valid JWT token
const protect = async (req, res, next) => {
  try {
    let token;

    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    // Make sure token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Not authorized to access this route'
      });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Get user from database
      const user = await User.findById(decoded.id).select('-password');

      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'No user found with this token'
        });
      }

      if (!user.isActive) {
        return res.status(401).json({
          success: false,
          error: 'Account has been deactivated'
        });
      }

      req.user = user;
      next();
    } catch (error) {
      logger.error('JWT verification error:', error);
      return res.status(401).json({
        success: false,
        error: 'Not authorized to access this route'
      });
    }
  } catch (error) {
    logger.error('Auth middleware error:', error);
    return res.status(500).json({
      success: false,
      error: 'Server error in authentication'
    });
  }
};

// Grant access to specific roles
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `User role ${req.user.role} is not authorized to access this route`
      });
    }
    next();
  };
};

// Optional auth - doesn't fail if no token
const optionalAuth = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
      
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (user && user.isActive) {
          req.user = user;
        }
      } catch (error) {
        // Token is invalid, but we continue without user
        logger.warn('Invalid token in optional auth:', error.message);
      }
    }

    next();
  } catch (error) {
    logger.error('Optional auth error:', error);
    next();
  }
};

module.exports = { protect, authorize, optionalAuth };
```

### Authentication Routes

```javascript
// routes/auth.js - Authentication routes
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Joi = require('joi');

const User = require('../models/User');
const { protect } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const emailService = require('../services/emailService');
const smsService = require('../services/smsService');
const logger = require('../utils/logger');

const router = express.Router();

// Validation schemas
const registerSchema = Joi.object({
  firstName: Joi.string().min(2).max(50).required(),
  lastName: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  phone: Joi.string().pattern(/^[+]?[1-9][\d\s\-\(\)]{7,15}$/).required(),
  password: Joi.string().min(6).required(),
  role: Joi.string().valid('customer', 'provider').default('customer')
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required()
});

const resetPasswordSchema = Joi.object({
  token: Joi.string().required(),
  password: Joi.string().min(6).required()
});

const verifyOTPSchema = Joi.object({
  phone: Joi.string().required(),
  otp: Joi.string().length(6).required()
});

// Generate JWT Token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE || '7d'
  });
};

// Generate Refresh Token
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRE || '30d'
  });
};

// @desc    Register user
// @route   POST /api/v1/auth/register
// @access  Public
const register = async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password, role } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({
      $or: [{ email }, { phone }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User already exists with this email or phone number'
      });
    }

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      phone,
      password,
      role
    });

    // Generate email verification token
    const emailVerificationToken = user.generateEmailVerificationToken();
    await user.save();

    // Generate OTP for phone verification
    const otp = user.generatePhoneOTP();
    await user.save();

    // Send verification email
    try {
      await emailService.sendEmailVerification(user.email, emailVerificationToken);
    } catch (error) {
      logger.error('Failed to send verification email:', error);
    }

    // Send OTP via SMS
    try {
      await smsService.sendOTP(user.phone, otp);
    } catch (error) {
      logger.error('Failed to send OTP:', error);
    }

    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshTokens.push({
      token: refreshToken,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      device: req.headers['user-agent'],
      ipAddress: req.ip
    });
    await user.save();

    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please verify your email and phone.',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          phone: user.phone,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          isPhoneVerified: user.isPhoneVerified
        },
        token,
        refreshToken
      }
    });

    // Log registration
    logger.info(`New user registered: ${user.email} (${user.role})`);

  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during registration'
    });
  }
};

// @desc    Login user
// @route   POST /api/v1/auth/login
// @access  Public
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user with password field
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        error: 'Account has been deactivated'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshTokens.push({
      token: refreshToken,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      device: req.headers['user-agent'],
      ipAddress: req.ip
    });

    // Keep only last 5 refresh tokens
    if (user.refreshTokens.length > 5) {
      user.refreshTokens = user.refreshTokens.slice(-5);
    }

    await user.save();

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          phone: user.phone,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          isPhoneVerified: user.isPhoneVerified,
          loyaltyTier: user.loyaltyTier,
          loyaltyPoints: user.loyaltyPoints
        },
        token,
        refreshToken
      }
    });

    logger.info(`User logged in: ${user.email}`);

  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during login'
    });
  }
};

// @desc    Logout user
// @route   POST /api/v1/auth/logout
// @access  Private
const logout = async (req, res) => {
  try {
    const refreshToken = req.body.refreshToken;

    if (refreshToken) {
      // Remove refresh token from user
      await User.findByIdAndUpdate(req.user.id, {
        $pull: { refreshTokens: { token: refreshToken } }
      });
    }

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });

    logger.info(`User logged out: ${req.user.email}`);

  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during logout'
    });
  }
};

// @desc    Refresh access token
// @route   POST /api/v1/auth/refresh
// @access  Public
const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Refresh token is required'
      });
    }

    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
      
      const user = await User.findById(decoded.id);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Invalid refresh token'
        });
      }

      // Check if refresh token exists in user's tokens
      const tokenExists = user.refreshTokens.find(t => 
        t.token === refreshToken && t.expiresAt > new Date()
      );

      if (!tokenExists) {
        return res.status(401).json({
          success: false,
          error: 'Invalid or expired refresh token'
        });
      }

      // Generate new access token
      const newToken = generateToken(user._id);

      res.status(200).json({
        success: true,
        data: {
          token: newToken,
          user: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.role
          }
        }
      });

    } catch (error) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token'
      });
    }

  } catch (error) {
    logger.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during token refresh'
    });
  }
};

// @desc    Send OTP for phone verification
// @route   POST /api/v1/auth/send-otp
// @access  Private
const sendOTP = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (user.isPhoneVerified) {
      return res.status(400).json({
        success: false,
        error: 'Phone number is already verified'
      });
    }

    const otp = user.generatePhoneOTP();
    await user.save();

    await smsService.sendOTP(user.phone, otp);

    res.status(200).json({
      success: true,
      message: 'OTP sent successfully'
    });

    logger.info(`OTP sent to: ${user.phone}`);

  } catch (error) {
    logger.error('Send OTP error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send OTP'
    });
  }
};

// @desc    Verify phone OTP
// @route   POST /api/v1/auth/verify-otp
// @access  Private
const verifyOTP = async (req, res) => {
  try {
    const { otp } = req.body;

    const user = await User.findById(req.user.id);

    if (user.isPhoneVerified) {
      return res.status(400).json({
        success: false,
        error: 'Phone number is already verified'
      });
    }

    if (!user.phoneVerificationOTP || user.phoneVerificationExpires < Date.now()) {
      return res.status(400).json({
        success: false,
        error: 'OTP is invalid or expired'
      });
    }

    if (user.phoneVerificationOTP !== otp) {
      return res.status(400).json({
        success: false,
        error: 'Invalid OTP'
      });
    }

    user.isPhoneVerified = true;
    user.phoneVerificationOTP = undefined;
    user.phoneVerificationExpires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Phone number verified successfully',
      data: {
        user: {
          id: user._id,
          isPhoneVerified: user.isPhoneVerified
        }
      }
    });

    logger.info(`Phone verified: ${user.phone}`);

  } catch (error) {
    logger.error('OTP verification error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during OTP verification'
    });
  }
};

// @desc    Verify email
// @route   GET /api/v1/auth/verify-email/:token
// @access  Public
const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired verification token'
      });
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });

    logger.info(`Email verified: ${user.email}`);

  } catch (error) {
    logger.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during email verification'
    });
  }
};

// @desc    Forgot password
// @route   POST /api/v1/auth/forgot-password
// @access  Public
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'No user found with that email address'
      });
    }

    const resetToken = user.generatePasswordResetToken();
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    try {
      await emailService.sendPasswordReset(user.email, resetUrl);

      res.status(200).json({
        success: true,
        message: 'Password reset email sent'
      });

      logger.info(`Password reset requested: ${user.email}`);

    } catch (error) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      logger.error('Failed to send password reset email:', error);

      return res.status(500).json({
        success: false,
        error: 'Email could not be sent'
      });
    }

  } catch (error) {
    logger.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during forgot password'
    });
  }
};

// @desc    Reset password
// @route   POST /api/v1/auth/reset-password
// @access  Public
const resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired reset token'
      });
    }

    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.refreshTokens = []; // Invalidate all refresh tokens
    await user.save();

    const newToken = generateToken(user._id);

    res.status(200).json({
      success: true,
      message: 'Password reset successful',
      data: {
        token: newToken
      }
    });

    logger.info(`Password reset: ${user.email}`);

  } catch (error) {
    logger.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during password reset'
    });
  }
};

// Apply validation middleware
router.post('/register', validateRequest(registerSchema), register);
router.post('/login', validateRequest(loginSchema), login);
router.post('/logout', protect, logout);
router.post('/refresh', refreshToken);
router.post('/send-otp', protect, sendOTP);
router.post('/verify-otp', protect, validateRequest(verifyOTPSchema), verifyOTP);
router.get('/verify-email/:token', verifyEmail);
router.post('/forgot-password', validateRequest(forgotPasswordSchema), forgotPassword);
router.post('/reset-password', validateRequest(resetPasswordSchema), resetPassword);

module.exports = router;
```