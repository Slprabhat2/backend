# Noo-Q Backend - Payment Integration

## 💳 Razorpay Payment System

### Payment Model

```javascript
// models/Payment.js - Payment transaction model
const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
  orderId: {
    type: String,
    required: [true, 'Order ID is required'],
    unique: true,
    index: true
  },
  razorpayOrderId: {
    type: String,
    required: [true, 'Razorpay order ID is required'],
    index: true
  },
  razorpayPaymentId: String,
  razorpaySignature: String,
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Appointment',
    required: [true, 'Appointment ID is required'],
    index: true
  },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Customer ID is required'],
    index: true
  },
  providerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Provider',
    required: [true, 'Provider ID is required'],
    index: true
  },
  amount: {
    serviceAmount: { type: Number, required: true },
    convenienceFee: { type: Number, default: 0 },
    taxes: { type: Number, default: 0 },
    discount: { type: Number, default: 0 },
    totalAmount: { type: Number, required: true }
  },
  currency: {
    type: String,
    default: 'INR'
  },
  paymentMethod: {
    type: String,
    enum: ['card', 'netbanking', 'wallet', 'upi', 'emi', 'cash_on_delivery'],
    required: true
  },
  status: {
    type: String,
    enum: ['created', 'attempted', 'paid', 'failed', 'cancelled', 'refunded', 'partial_refund'],
    default: 'created',
    index: true
  },
  gatewayResponse: {
    method: String,
    bank: String,
    wallet: String,
    vpa: String, // for UPI
    cardId: String,
    acquirerData: mongoose.Schema.Types.Mixed
  },
  refunds: [{
    refundId: String,
    amount: Number,
    status: String,
    reason: String,
    processedAt: Date,
    notes: String
  }],
  splitSettlement: {
    platformFee: { type: Number, required: true },
    providerAmount: { type: Number, required: true },
    transferId: String,
    transferStatus: {
      type: String,
      enum: ['pending', 'processed', 'failed'],
      default: 'pending'
    },
    processedAt: Date
  },
  metadata: {
    ipAddress: String,
    userAgent: String,
    source: String, // 'web', 'mobile', 'api'
    campaignId: String,
    referrer: String
  },
  failureReason: String,
  attempts: [{
    attemptedAt: { type: Date, default: Date.now },
    status: String,
    failureReason: String,
    gatewayResponse: mongoose.Schema.Types.Mixed
  }],
  webhookEvents: [{
    eventType: String,
    receivedAt: { type: Date, default: Date.now },
    data: mongoose.Schema.Types.Mixed,
    processed: { type: Boolean, default: false }
  }],
  notes: {
    customerNote: String,
    adminNote: String,
    providerNote: String
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for payment success status
paymentSchema.virtual('isSuccessful').get(function() {
  return this.status === 'paid';
});

// Virtual for refund amount
paymentSchema.virtual('refundAmount').get(function() {
  return this.refunds.reduce((total, refund) => {
    return refund.status === 'processed' ? total + refund.amount : total;
  }, 0);
});

// Pre-save middleware to generate order ID
paymentSchema.pre('save', async function(next) {
  if (!this.orderId) {
    const date = new Date();
    const timestamp = date.getTime().toString().slice(-8);
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    this.orderId = `NQ${timestamp}${random}`;
  }
  next();
});

// Indexes for performance
paymentSchema.index({ orderId: 1 });
paymentSchema.index({ razorpayOrderId: 1 });
paymentSchema.index({ customerId: 1, createdAt: -1 });
paymentSchema.index({ providerId: 1, createdAt: -1 });
paymentSchema.index({ status: 1, createdAt: -1 });

module.exports = mongoose.model('Payment', paymentSchema);
```

### Razorpay Service

```javascript
// services/razorpayService.js - Razorpay integration service
const Razorpay = require('razorpay');
const crypto = require('crypto');
const logger = require('../utils/logger');

class RazorpayService {
  constructor() {
    this.instance = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET
    });
  }

  // Create order for appointment payment
  async createOrder(orderData) {
    try {
      const {
        amount,
        customerId,
        appointmentId,
        customerEmail,
        customerPhone,
        description = 'Noo-Q Appointment Booking'
      } = orderData;

      const options = {
        amount: Math.round(amount * 100), // Convert to paisa
        currency: 'INR',
        receipt: `receipt_${appointmentId}`,
        payment_capture: 1,
        notes: {
          customer_id: customerId,
          appointment_id: appointmentId,
          platform: 'noo-q'
        },
        prefill: {
          email: customerEmail,
          contact: customerPhone
        },
        theme: {
          color: '#217d8d'
        }
      };

      const order = await this.instance.orders.create(options);
      
      logger.info(`Razorpay order created: ${order.id} for amount: ₹${amount}`);
      
      return {
        success: true,
        order
      };
    } catch (error) {
      logger.error('Razorpay order creation error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Create order with split settlement
  async createOrderWithSplit(orderData) {
    try {
      const {
        amount,
        customerId,
        appointmentId,
        providerId,
        providerAccountId,
        platformFee,
        customerEmail,
        customerPhone
      } = orderData;

      const providerAmount = amount - platformFee;

      const options = {
        amount: Math.round(amount * 100),
        currency: 'INR',
        receipt: `receipt_${appointmentId}`,
        payment_capture: 1,
        notes: {
          customer_id: customerId,
          appointment_id: appointmentId,
          provider_id: providerId,
          platform_fee: platformFee,
          provider_amount: providerAmount
        },
        transfers: [
          {
            account: providerAccountId,
            amount: Math.round(providerAmount * 100),
            currency: 'INR',
            notes: {
              provider_id: providerId,
              appointment_id: appointmentId
            },
            linked_account_notes: [
              'appointment_payment'
            ]
          }
        ]
      };

      const order = await this.instance.orders.create(options);
      
      logger.info(`Split settlement order created: ${order.id}`);
      
      return {
        success: true,
        order
      };
    } catch (error) {
      logger.error('Split settlement order creation error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Verify payment signature
  verifyPaymentSignature(paymentData) {
    try {
      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      } = paymentData;

      const generated_signature = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(razorpay_order_id + '|' + razorpay_payment_id)
        .digest('hex');

      const isSignatureValid = generated_signature === razorpay_signature;
      
      logger.info(`Payment signature verification: ${isSignatureValid ? 'SUCCESS' : 'FAILED'}`);
      
      return {
        success: isSignatureValid,
        generated_signature,
        provided_signature: razorpay_signature
      };
    } catch (error) {
      logger.error('Payment signature verification error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Get payment details
  async getPaymentDetails(paymentId) {
    try {
      const payment = await this.instance.payments.fetch(paymentId);
      
      return {
        success: true,
        payment
      };
    } catch (error) {
      logger.error('Get payment details error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Initiate refund
  async initiateRefund(paymentId, refundData) {
    try {
      const { amount, reason, notes } = refundData;

      const options = {
        amount: Math.round(amount * 100),
        notes: {
          reason,
          processed_by: 'noo-q_system',
          ...notes
        }
      };

      const refund = await this.instance.payments.refund(paymentId, options);
      
      logger.info(`Refund initiated: ${refund.id} for payment: ${paymentId}`);
      
      return {
        success: true,
        refund
      };
    } catch (error) {
      logger.error('Refund initiation error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Get refund details
  async getRefundDetails(paymentId, refundId) {
    try {
      const refund = await this.instance.refunds.fetch(refundId);
      
      return {
        success: true,
        refund
      };
    } catch (error) {
      logger.error('Get refund details error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Verify webhook signature
  verifyWebhookSignature(webhookBody, webhookSignature) {
    try {
      const generated_signature = crypto
        .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
        .update(webhookBody)
        .digest('hex');

      const isSignatureValid = generated_signature === webhookSignature;
      
      return {
        success: isSignatureValid
      };
    } catch (error) {
      logger.error('Webhook signature verification error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Handle webhook events
  async handleWebhook(event) {
    try {
      const { event: eventType, payload } = event;
      
      logger.info(`Processing webhook event: ${eventType}`);

      switch (eventType) {
        case 'payment.captured':
          return await this.handlePaymentCaptured(payload.payment.entity);
        
        case 'payment.failed':
          return await this.handlePaymentFailed(payload.payment.entity);
        
        case 'refund.processed':
          return await this.handleRefundProcessed(payload.refund.entity);
        
        case 'transfer.processed':
          return await this.handleTransferProcessed(payload.transfer.entity);
        
        default:
          logger.warn(`Unhandled webhook event: ${eventType}`);
          return { success: true, message: 'Event logged but not processed' };
      }
    } catch (error) {
      logger.error('Webhook handling error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Handle payment captured webhook
  async handlePaymentCaptured(paymentEntity) {
    try {
      const Payment = require('../models/Payment');
      const Appointment = require('../models/Appointment');

      // Find payment record
      const payment = await Payment.findOne({
        razorpayPaymentId: paymentEntity.id
      });

      if (!payment) {
        throw new Error(`Payment not found for Razorpay payment ID: ${paymentEntity.id}`);
      }

      // Update payment status
      payment.status = 'paid';
      payment.gatewayResponse = {
        method: paymentEntity.method,
        bank: paymentEntity.bank,
        wallet: paymentEntity.wallet,
        vpa: paymentEntity.vpa,
        cardId: paymentEntity.card_id,
        acquirerData: paymentEntity.acquirer_data
      };
      
      // Add webhook event
      payment.webhookEvents.push({
        eventType: 'payment.captured',
        data: paymentEntity,
        processed: true
      });

      await payment.save();

      // Update appointment payment status
      await Appointment.findByIdAndUpdate(
        payment.appointmentId,
        { paymentStatus: 'paid' }
      );

      logger.info(`Payment captured webhook processed for payment: ${payment.orderId}`);

      return { success: true };
    } catch (error) {
      logger.error('Payment captured webhook error:', error);
      throw error;
    }
  }

  // Handle payment failed webhook
  async handlePaymentFailed(paymentEntity) {
    try {
      const Payment = require('../models/Payment');

      const payment = await Payment.findOne({
        razorpayOrderId: paymentEntity.order_id
      });

      if (payment) {
        payment.status = 'failed';
        payment.failureReason = paymentEntity.error_description;
        payment.attempts.push({
          status: 'failed',
          failureReason: paymentEntity.error_description,
          gatewayResponse: paymentEntity
        });

        payment.webhookEvents.push({
          eventType: 'payment.failed',
          data: paymentEntity,
          processed: true
        });

        await payment.save();
      }

      return { success: true };
    } catch (error) {
      logger.error('Payment failed webhook error:', error);
      throw error;
    }
  }
}

module.exports = new RazorpayService();
```

### Payment Routes

```javascript
// routes/payments.js - Payment processing routes
const express = require('express');
const Joi = require('joi');

const Payment = require('../models/Payment');
const Appointment = require('../models/Appointment');
const User = require('../models/User');
const Provider = require('../models/Provider');
const { protect, authorize } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const razorpayService = require('../services/razorpayService');
const logger = require('../utils/logger');

const router = express.Router();

// Validation schemas
const createOrderSchema = Joi.object({
  appointmentId: Joi.string().required(),
  amount: Joi.number().positive().required()
});

const verifyPaymentSchema = Joi.object({
  razorpay_order_id: Joi.string().required(),
  razorpay_payment_id: Joi.string().required(),
  razorpay_signature: Joi.string().required()
});

// @desc    Create payment order
// @route   POST /api/v1/payments/create-order
// @access  Private (Customer)
const createOrder = async (req, res) => {
  try {
    const { appointmentId, amount } = req.body;
    const customerId = req.user.id;

    // Get appointment details
    const appointment = await Appointment.findById(appointmentId)
      .populate('providerId customerId serviceId');

    if (!appointment) {
      return res.status(404).json({
        success: false,
        error: 'Appointment not found'
      });
    }

    // Verify customer owns the appointment
    if (appointment.customerId._id.toString() !== customerId) {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to pay for this appointment'
      });
    }

    // Check if already paid
    if (appointment.paymentStatus === 'paid') {
      return res.status(400).json({
        success: false,
        error: 'Appointment is already paid'
      });
    }

    // Calculate amounts
    const serviceAmount = appointment.pricing.servicePrice;
    const convenienceFee = Math.round(serviceAmount * 0.05); // 5% convenience fee
    const totalAmount = serviceAmount + convenienceFee;

    // Verify amount matches
    if (Math.abs(totalAmount - amount) > 1) { // Allow ₹1 difference for rounding
      return res.status(400).json({
        success: false,
        error: 'Payment amount does not match appointment total'
      });
    }

    // Create Razorpay order
    const orderResult = await razorpayService.createOrder({
      amount: totalAmount,
      customerId,
      appointmentId,
      customerEmail: appointment.customerDetails.email,
      customerPhone: appointment.customerDetails.phone,
      description: `Appointment booking - ${appointment.serviceId.name}`
    });

    if (!orderResult.success) {
      return res.status(500).json({
        success: false,
        error: 'Failed to create payment order'
      });
    }

    // Save payment record
    const payment = new Payment({
      orderId: `ORDER_${Date.now()}`,
      razorpayOrderId: orderResult.order.id,
      appointmentId,
      customerId,
      providerId: appointment.providerId._id,
      amount: {
        serviceAmount,
        convenienceFee,
        totalAmount
      },
      status: 'created',
      splitSettlement: {
        platformFee: convenienceFee,
        providerAmount: serviceAmount
      }
    });

    await payment.save();

    res.status(201).json({
      success: true,
      message: 'Payment order created successfully',
      data: {
        orderId: payment.orderId,
        razorpayOrderId: orderResult.order.id,
        amount: totalAmount,
        currency: 'INR',
        key: process.env.RAZORPAY_KEY_ID,
        appointment: {
          id: appointment._id,
          service: appointment.serviceId.name,
          provider: appointment.providerId.businessName,
          date: appointment.appointmentDate,
          time: appointment.appointmentTime
        },
        customer: {
          name: appointment.customerDetails.name,
          email: appointment.customerDetails.email,
          phone: appointment.customerDetails.phone
        }
      }
    });

  } catch (error) {
    logger.error('Create order error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during order creation'
    });
  }
};

// @desc    Verify payment
// @route   POST /api/v1/payments/verify
// @access  Private (Customer)
const verifyPayment = async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    // Verify signature
    const verificationResult = razorpayService.verifyPaymentSignature({
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    });

    if (!verificationResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Payment verification failed - invalid signature'
      });
    }

    // Find payment record
    const payment = await Payment.findOne({ razorpayOrderId: razorpay_order_id })
      .populate('appointmentId');

    if (!payment) {
      return res.status(404).json({
        success: false,
        error: 'Payment record not found'
      });
    }

    // Update payment record
    payment.razorpayPaymentId = razorpay_payment_id;
    payment.razorpaySignature = razorpay_signature;
    payment.status = 'paid';
    await payment.save();

    // Update appointment payment status
    await Appointment.findByIdAndUpdate(
      payment.appointmentId._id,
      { 
        paymentStatus: 'paid',
        status: 'confirmed'
      }
    );

    // Update customer loyalty points
    const customer = await User.findById(payment.customerId);
    if (customer) {
      const loyaltyPoints = Math.floor(payment.amount.totalAmount / 100); // 1 point per ₹100
      customer.addLoyaltyPoints(loyaltyPoints);
      customer.totalSpent += payment.amount.totalAmount;
      await customer.save();
    }

    // Send real-time notification
    const io = req.app.get('io');
    if (io) {
      io.to(`user_${payment.customerId}`).emit('payment_success', {
        appointmentId: payment.appointmentId._id,
        orderId: payment.orderId,
        amount: payment.amount.totalAmount
      });

      io.to(`user_${payment.providerId}`).emit('payment_received', {
        appointmentId: payment.appointmentId._id,
        amount: payment.amount.providerAmount
      });
    }

    res.status(200).json({
      success: true,
      message: 'Payment verified successfully',
      data: {
        paymentId: payment._id,
        orderId: payment.orderId,
        status: payment.status,
        amount: payment.amount.totalAmount,
        loyaltyPointsEarned: Math.floor(payment.amount.totalAmount / 100)
      }
    });

    logger.info(`Payment verified: ${payment.orderId} - ₹${payment.amount.totalAmount}`);

  } catch (error) {
    logger.error('Payment verification error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error during payment verification'
    });
  }
};

// Apply routes with validation
router.post('/create-order', protect, authorize('customer'), validateRequest(createOrderSchema), createOrder);
router.post('/verify', protect, authorize('customer'), validateRequest(verifyPaymentSchema), verifyPayment);

module.exports = router;
```