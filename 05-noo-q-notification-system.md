# Noo-Q Backend - Notification System

## 📱 Multi-Channel Notification Service

### Notification Model

```javascript
// models/Notification.js - Notification tracking model
const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  notificationId: {
    type: String,
    unique: true,
    required: true
  },
  recipientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Recipient ID is required'],
    index: true
  },
  recipientType: {
    type: String,
    enum: ['customer', 'provider', 'admin'],
    required: true
  },
  type: {
    type: String,
    enum: [
      'booking_confirmation',
      'booking_reminder',
      'booking_cancellation',
      'payment_confirmation',
      'provider_approval',
      'appointment_update',
      'rating_request',
      'promotional',
      'system_update'
    ],
    required: true,
    index: true
  },
  channels: {
    whatsapp: {
      enabled: { type: Boolean, default: false },
      messageId: String,
      status: {
        type: String,
        enum: ['pending', 'sent', 'delivered', 'read', 'failed'],
        default: 'pending'
      },
      sentAt: Date,
      deliveredAt: Date,
      readAt: Date,
      errorMessage: String
    },
    sms: {
      enabled: { type: Boolean, default: false },
      messageId: String,
      status: {
        type: String,
        enum: ['pending', 'sent', 'delivered', 'failed'],
        default: 'pending'
      },
      sentAt: Date,
      deliveredAt: Date,
      errorMessage: String
    },
    email: {
      enabled: { type: Boolean, default: false },
      messageId: String,
      status: {
        type: String,
        enum: ['pending', 'sent', 'delivered', 'opened', 'clicked', 'failed'],
        default: 'pending'
      },
      sentAt: Date,
      deliveredAt: Date,
      openedAt: Date,
      clickedAt: Date,
      errorMessage: String
    },
    push: {
      enabled: { type: Boolean, default: false },
      messageId: String,
      status: {
        type: String,
        enum: ['pending', 'sent', 'delivered', 'opened', 'failed'],
        default: 'pending'
      },
      sentAt: Date,
      deliveredAt: Date,
      openedAt: Date,
      errorMessage: String
    },
    inApp: {
      enabled: { type: Boolean, default: true },
      readAt: Date,
      isRead: { type: Boolean, default: false }
    }
  },
  content: {
    title: { type: String, required: true },
    message: { type: String, required: true },
    templateId: String,
    templateVariables: mongoose.Schema.Types.Mixed,
    attachments: [{
      name: String,
      url: String,
      type: String
    }]
  },
  metadata: {
    appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' },
    providerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Provider' },
    paymentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Payment' },
    priority: {
      type: String,
      enum: ['low', 'normal', 'high', 'urgent'],
      default: 'normal'
    },
    scheduledFor: Date,
    expiresAt: Date,
    tags: [String]
  },
  overallStatus: {
    type: String,
    enum: ['pending', 'processing', 'sent', 'partially_sent', 'failed', 'expired'],
    default: 'pending',
    index: true
  },
  attempts: [{
    channel: String,
    attemptedAt: Date,
    status: String,
    errorMessage: String
  }],
  isScheduled: { type: Boolean, default: false },
  processedAt: Date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for successful delivery count
notificationSchema.virtual('successfulDeliveries').get(function() {
  let count = 0;
  Object.keys(this.channels).forEach(channel => {
    if (this.channels[channel].enabled && 
        ['sent', 'delivered', 'read', 'opened'].includes(this.channels[channel].status)) {
      count++;
    }
  });
  return count;
});

// Pre-save middleware to generate notification ID
notificationSchema.pre('save', function(next) {
  if (!this.notificationId) {
    const timestamp = Date.now().toString();
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    this.notificationId = `NOTIF_${timestamp}_${random}`;
  }
  next();
});

// Indexes for performance
notificationSchema.index({ recipientId: 1, createdAt: -1 });
notificationSchema.index({ type: 1, overallStatus: 1 });
notificationSchema.index({ 'metadata.scheduledFor': 1 });
notificationSchema.index({ 'metadata.expiresAt': 1 });

module.exports = mongoose.model('Notification', notificationSchema);
```

### WhatsApp Service

```javascript
// services/whatsappService.js - WhatsApp Business API integration
const axios = require('axios');
const logger = require('../utils/logger');

class WhatsAppService {
  constructor() {
    this.accessToken = process.env.WHATSAPP_ACCESS_TOKEN;
    this.phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
    this.businessAccountId = process.env.WHATSAPP_BUSINESS_ACCOUNT_ID;
    this.apiUrl = `https://graph.facebook.com/v17.0/${this.phoneNumberId}/messages`;
  }

  // Send text message
  async sendMessage(phoneNumber, message, context = null) {
    try {
      const payload = {
        messaging_product: 'whatsapp',
        to: this.formatPhoneNumber(phoneNumber),
        type: 'text',
        text: {
          body: message
        }
      };

      // Add context for replies
      if (context) {
        payload.context = {
          message_id: context.messageId
        };
      }

      const response = await axios.post(this.apiUrl, payload, {
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      logger.info(`WhatsApp message sent to ${phoneNumber}: ${response.data.messages[0].id}`);

      return {
        success: true,
        messageId: response.data.messages[0].id,
        status: 'sent'
      };

    } catch (error) {
      logger.error('WhatsApp send message error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.error?.message || error.message
      };
    }
  }

  // Send template message
  async sendTemplate(phoneNumber, templateName, templateVariables = []) {
    try {
      const payload = {
        messaging_product: 'whatsapp',
        to: this.formatPhoneNumber(phoneNumber),
        type: 'template',
        template: {
          name: templateName,
          language: {
            code: 'en_US'
          }
        }
      };

      // Add template parameters if provided
      if (templateVariables.length > 0) {
        payload.template.components = [{
          type: 'body',
          parameters: templateVariables.map(variable => ({
            type: 'text',
            text: variable
          }))
        }];
      }

      const response = await axios.post(this.apiUrl, payload, {
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      logger.info(`WhatsApp template sent to ${phoneNumber}: ${templateName}`);

      return {
        success: true,
        messageId: response.data.messages[0].id,
        status: 'sent'
      };

    } catch (error) {
      logger.error('WhatsApp template send error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.error?.message || error.message
      };
    }
  }

  // Send appointment confirmation
  async sendAppointmentConfirmation(phoneNumber, appointmentData) {
    const message = `🎉 *Appointment Confirmed!*

📅 *Date:* ${appointmentData.date}
🕐 *Time:* ${appointmentData.time}
🏪 *Provider:* ${appointmentData.providerName}
💼 *Service:* ${appointmentData.serviceName}
💰 *Amount:* ₹${appointmentData.amount}

📍 *Address:* ${appointmentData.address}

Your booking reference: *${appointmentData.bookingId}*

Need to reschedule or cancel? Reply to this message or call us.

Thank you for choosing Noo-Q! 🙏`;

    return await this.sendMessage(phoneNumber, message);
  }

  // Send appointment reminder
  async sendAppointmentReminder(phoneNumber, appointmentData) {
    const message = `⏰ *Appointment Reminder*

Hi ${appointmentData.customerName}! 

This is a friendly reminder about your appointment:

📅 *Tomorrow at ${appointmentData.time}*
🏪 *${appointmentData.providerName}*
💼 *${appointmentData.serviceName}*

📍 *Address:* ${appointmentData.address}

Please arrive 10 minutes early. If you need to reschedule, please let us know ASAP.

See you tomorrow! 😊`;

    return await this.sendMessage(phoneNumber, message);
  }

  // Send payment confirmation
  async sendPaymentConfirmation(phoneNumber, paymentData) {
    const message = `💳 *Payment Successful!*

✅ Your payment of *₹${paymentData.amount}* has been confirmed.

🧾 *Transaction ID:* ${paymentData.transactionId}
📅 *Date:* ${paymentData.date}
💼 *Service:* ${paymentData.serviceName}

Your appointment is now confirmed. We'll send you a reminder before your scheduled time.

Thank you for using Noo-Q! 🎉`;

    return await this.sendMessage(phoneNumber, message);
  }

  // Send cancellation notification
  async sendCancellationNotification(phoneNumber, cancellationData) {
    const message = `❌ *Appointment Cancelled*

Your appointment has been cancelled:

📅 *Date:* ${cancellationData.date}
🕐 *Time:* ${cancellationData.time}
🏪 *Provider:* ${cancellationData.providerName}

💰 *Refund:* ₹${cancellationData.refundAmount} will be processed within 3-5 business days.

Need to book again? Visit our website or scan your provider's QR code.

Thank you for understanding! 🙏`;

    return await this.sendMessage(phoneNumber, message);
  }

  // Format phone number for WhatsApp API
  formatPhoneNumber(phoneNumber) {
    // Remove all non-digit characters
    const cleaned = phoneNumber.replace(/\D/g, '');
    
    // Add country code if not present
    if (cleaned.startsWith('91')) {
      return cleaned;
    } else if (cleaned.startsWith('0')) {
      return '91' + cleaned.substring(1);
    } else {
      return '91' + cleaned;
    }
  }

  // Get message status
  async getMessageStatus(messageId) {
    try {
      const response = await axios.get(`https://graph.facebook.com/v17.0/${messageId}`, {
        headers: {
          'Authorization': `Bearer ${this.accessToken}`
        }
      });

      return {
        success: true,
        status: response.data
      };

    } catch (error) {
      logger.error('Get WhatsApp message status error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Handle webhook events
  async handleWebhook(webhookData) {
    try {
      const { entry } = webhookData;

      for (const entryItem of entry) {
        if (entryItem.changes) {
          for (const change of entryItem.changes) {
            if (change.field === 'messages') {
              await this.processMessageStatus(change.value);
            }
          }
        }
      }

      return { success: true };
    } catch (error) {
      logger.error('WhatsApp webhook handling error:', error);
      return { success: false, error: error.message };
    }
  }

  // Process message status updates
  async processMessageStatus(statusData) {
    try {
      const { statuses, messages } = statusData;

      if (statuses) {
        for (const status of statuses) {
          await this.updateMessageStatus(status.id, status.status, status.timestamp);
        }
      }

      if (messages) {
        // Handle incoming messages (customer replies)
        for (const message of messages) {
          await this.handleIncomingMessage(message);
        }
      }

    } catch (error) {
      logger.error('Process WhatsApp message status error:', error);
    }
  }

  // Update message status in database
  async updateMessageStatus(messageId, status, timestamp) {
    try {
      const Notification = require('../models/Notification');

      const notification = await Notification.findOne({
        'channels.whatsapp.messageId': messageId
      });

      if (notification) {
        notification.channels.whatsapp.status = status;
        
        switch (status) {
          case 'sent':
            notification.channels.whatsapp.sentAt = new Date(timestamp * 1000);
            break;
          case 'delivered':
            notification.channels.whatsapp.deliveredAt = new Date(timestamp * 1000);
            break;
          case 'read':
            notification.channels.whatsapp.readAt = new Date(timestamp * 1000);
            break;
        }

        await notification.save();
        logger.info(`Updated WhatsApp message status: ${messageId} -> ${status}`);
      }

    } catch (error) {
      logger.error('Update WhatsApp message status error:', error);
    }
  }

  // Handle incoming customer messages
  async handleIncomingMessage(message) {
    try {
      // Basic auto-reply functionality
      const { from, text, type } = message;
      
      if (type === 'text' && text?.body) {
        const messageText = text.body.toLowerCase();
        
        // Simple keyword-based responses
        if (messageText.includes('cancel') || messageText.includes('reschedule')) {
          await this.sendMessage(from, 
            "Thank you for your message. For cancellations or rescheduling, please contact us at +91-XXXXXXXXXX or visit our website. Our team will assist you promptly.");
        } else if (messageText.includes('help') || messageText.includes('support')) {
          await this.sendMessage(from,
            "Hi! We're here to help. You can:\n📞 Call: +91-XXXXXXXXXX\n💻 Visit: noo-q.com\n📧 Email: support@noo-q.com\n\nOur support hours: 9 AM - 9 PM, Mon-Sat");
        }
      }

      logger.info(`Processed incoming WhatsApp message from: ${from}`);

    } catch (error) {
      logger.error('Handle incoming WhatsApp message error:', error);
    }
  }
}

module.exports = new WhatsAppService();
```

### SMS Service

```javascript
// services/smsService.js - SMS notification service using Twilio
const twilio = require('twilio');
const logger = require('../utils/logger');

class SMSService {
  constructor() {
    this.accountSid = process.env.TWILIO_ACCOUNT_SID;
    this.authToken = process.env.TWILIO_AUTH_TOKEN;
    this.phoneNumber = process.env.TWILIO_PHONE_NUMBER;
    
    if (this.accountSid && this.authToken) {
      this.client = twilio(this.accountSid, this.authToken);
    } else {
      logger.warn('Twilio credentials not configured - SMS service disabled');
    }
  }

  // Send SMS message
  async sendSMS(phoneNumber, message) {
    try {
      if (!this.client) {
        throw new Error('SMS service not configured');
      }

      const result = await this.client.messages.create({
        body: message,
        from: this.phoneNumber,
        to: this.formatPhoneNumber(phoneNumber)
      });

      logger.info(`SMS sent to ${phoneNumber}: ${result.sid}`);

      return {
        success: true,
        messageId: result.sid,
        status: result.status
      };

    } catch (error) {
      logger.error('SMS send error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Send OTP via SMS
  async sendOTP(phoneNumber, otp) {
    const message = `Your Noo-Q verification code is: ${otp}

This code will expire in 10 minutes. Do not share this code with anyone.

If you didn't request this code, please ignore this message.`;

    return await this.sendSMS(phoneNumber, message);
  }

  // Send appointment confirmation SMS
  async sendAppointmentConfirmation(phoneNumber, appointmentData) {
    const message = `Appointment Confirmed!

Date: ${appointmentData.date}
Time: ${appointmentData.time}
Provider: ${appointmentData.providerName}
Service: ${appointmentData.serviceName}
Amount: Rs.${appointmentData.amount}

Booking ID: ${appointmentData.bookingId}

Address: ${appointmentData.address}

For changes, visit noo-q.com or call support.
Thank you for choosing Noo-Q!`;

    return await this.sendSMS(phoneNumber, message);
  }

  // Send appointment reminder SMS
  async sendAppointmentReminder(phoneNumber, appointmentData) {
    const message = `Appointment Reminder

Hi ${appointmentData.customerName}!

Your appointment is tomorrow at ${appointmentData.time}
Provider: ${appointmentData.providerName}
Service: ${appointmentData.serviceName}

Address: ${appointmentData.address}

Please arrive 10 minutes early.
To reschedule, visit noo-q.com

Thank you!`;

    return await this.sendSMS(phoneNumber, message);
  }

  // Format phone number for SMS
  formatPhoneNumber(phoneNumber) {
    const cleaned = phoneNumber.replace(/\D/g, '');
    
    if (cleaned.startsWith('91')) {
      return '+' + cleaned;
    } else if (cleaned.startsWith('0')) {
      return '+91' + cleaned.substring(1);
    } else {
      return '+91' + cleaned;
    }
  }

  // Get message status
  async getMessageStatus(messageId) {
    try {
      if (!this.client) {
        throw new Error('SMS service not configured');
      }

      const message = await this.client.messages(messageId).fetch();
      
      return {
        success: true,
        status: message.status,
        errorCode: message.errorCode,
        errorMessage: message.errorMessage
      };

    } catch (error) {
      logger.error('Get SMS status error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new SMSService();
```