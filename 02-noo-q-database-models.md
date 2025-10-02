# Noo-Q Backend - Complete Database Models

## 🗄️ MongoDB Database Models

### Provider Model

```javascript
// models/Provider.js - Provider business model
const mongoose = require('mongoose');

const providerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required']
  },
  businessName: {
    type: String,
    required: [true, 'Business name is required'],
    trim: true,
    maxlength: [100, 'Business name cannot exceed 100 characters'],
    index: true
  },
  businessType: {
    type: String,
    required: [true, 'Business type is required'],
    enum: ['salon', 'healthcare', 'wellness', 'restaurant', 'fitness', 'automotive', 'pet_care', 'education', 'consulting', 'other'],
    index: true
  },
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  owner: {
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    email: { type: String, required: true, lowercase: true },
    phone: { type: String, required: true }
  },
  contact: {
    email: { type: String, required: true, lowercase: true },
    phone: { type: String, required: true },
    whatsapp: String,
    website: String,
    socialMedia: {
      facebook: String,
      instagram: String,
      twitter: String,
      linkedin: String
    }
  },
  address: {
    street: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    zipCode: { type: String, required: true },
    country: { type: String, default: 'India' },
    coordinates: {
      type: [Number], // [longitude, latitude]
      index: '2dsphere'
    }
  },
  workingHours: {
    monday: { start: String, end: String, isOpen: { type: Boolean, default: true } },
    tuesday: { start: String, end: String, isOpen: { type: Boolean, default: true } },
    wednesday: { start: String, end: String, isOpen: { type: Boolean, default: true } },
    thursday: { start: String, end: String, isOpen: { type: Boolean, default: true } },
    friday: { start: String, end: String, isOpen: { type: Boolean, default: true } },
    saturday: { start: String, end: String, isOpen: { type: Boolean, default: true } },
    sunday: { start: String, end: String, isOpen: { type: Boolean, default: false } }
  },
  businessDocuments: [{
    type: { type: String, required: true }, // license, permit, certificate
    fileName: { type: String, required: true },
    fileUrl: { type: String, required: true },
    uploadedAt: { type: Date, default: Date.now },
    isVerified: { type: Boolean, default: false }
  }],
  images: [{
    url: String,
    caption: String,
    isMainImage: { type: Boolean, default: false }
  }],
  status: {
    type: String,
    enum: ['pending', 'under_review', 'approved', 'rejected', 'suspended'],
    default: 'pending',
    index: true
  },
  rejectionReason: String,
  suspensionReason: String,
  subscriptionTier: {
    type: String,
    enum: ['free', 'pro', 'enterprise'],
    default: 'free'
  },
  subscriptionExpiry: Date,
  features: {
    maxServices: { type: Number, default: 5 },
    maxAppointmentsPerDay: { type: Number, default: 50 },
    advancedAnalytics: { type: Boolean, default: false },
    customBranding: { type: Boolean, default: false },
    apiAccess: { type: Boolean, default: false },
    prioritySupport: { type: Boolean, default: false }
  },
  rating: {
    average: { type: Number, default: 0, min: 0, max: 5 },
    total: { type: Number, default: 0 },
    breakdown: {
      5: { type: Number, default: 0 },
      4: { type: Number, default: 0 },
      3: { type: Number, default: 0 },
      2: { type: Number, default: 0 },
      1: { type: Number, default: 0 }
    }
  },
  stats: {
    totalBookings: { type: Number, default: 0 },
    totalRevenue: { type: Number, default: 0 },
    totalCustomers: { type: Number, default: 0 },
    averageBookingValue: { type: Number, default: 0 },
    completionRate: { type: Number, default: 0 },
    responseTime: { type: Number, default: 0 } // in minutes
  },
  qrCode: {
    url: String,
    publicId: String,
    scans: { type: Number, default: 0 },
    conversions: { type: Number, default: 0 }
  },
  paymentSettings: {
    acceptCashOnArrival: { type: Boolean, default: true },
    requireAdvancePayment: { type: Boolean, default: false },
    cancellationPolicy: {
      allowCancellation: { type: Boolean, default: true },
      cancellationWindow: { type: Number, default: 24 }, // hours
      refundPercentage: { type: Number, default: 100 }
    }
  },
  notificationPreferences: {
    newBooking: { whatsapp: Boolean, sms: Boolean, email: Boolean },
    cancellation: { whatsapp: Boolean, sms: Boolean, email: Boolean },
    review: { whatsapp: Boolean, sms: Boolean, email: Boolean },
    payment: { whatsapp: Boolean, sms: Boolean, email: Boolean }
  },
  holidays: [{
    date: Date,
    name: String,
    type: { type: String, enum: ['public', 'personal', 'business'] }
  }],
  blockedSlots: [{
    date: Date,
    startTime: String,
    endTime: String,
    reason: String,
    type: { type: String, enum: ['maintenance', 'personal', 'emergency'] }
  }],
  isActive: { type: Boolean, default: true },
  lastActiveAt: { type: Date, default: Date.now },
  approvedAt: Date,
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for owner full name
providerSchema.virtual('ownerFullName').get(function() {
  return `${this.owner.firstName} ${this.owner.lastName}`;
});

// Virtual for services count
providerSchema.virtual('servicesCount', {
  ref: 'Service',
  localField: '_id',
  foreignField: 'providerId',
  count: true
});

// Virtual for active services
providerSchema.virtual('activeServices', {
  ref: 'Service',
  localField: '_id',
  foreignField: 'providerId',
  match: { isActive: true }
});

// Indexes for performance
providerSchema.index({ businessName: 'text', description: 'text' });
providerSchema.index({ businessType: 1, status: 1 });
providerSchema.index({ 'address.city': 1, 'address.state': 1 });
providerSchema.index({ 'rating.average': -1 });
providerSchema.index({ createdAt: -1 });

// Method to update rating
providerSchema.methods.updateRating = function(newRating) {
  this.rating.breakdown[newRating]++;
  this.rating.total++;
  
  const totalPoints = Object.keys(this.rating.breakdown).reduce((sum, rating) => {
    return sum + (parseInt(rating) * this.rating.breakdown[rating]);
  }, 0);
  
  this.rating.average = totalPoints / this.rating.total;
};

// Method to check if open now
providerSchema.methods.isOpenNow = function() {
  const now = new Date();
  const dayName = now.toLocaleLowerCase().substr(0, 3); // mon, tue, etc.
  const currentTime = now.toTimeString().substr(0, 5); // HH:MM
  
  const todayHours = this.workingHours[dayName];
  if (!todayHours || !todayHours.isOpen) return false;
  
  return currentTime >= todayHours.start && currentTime <= todayHours.end;
};

// Method to generate QR code URL
providerSchema.methods.generateQRCodeUrl = function() {
  return `${process.env.FRONTEND_URL}/book/${this._id}`;
};

module.exports = mongoose.model('Provider', providerSchema);
```

### Service Model

```javascript
// models/Service.js - Provider services model
const mongoose = require('mongoose');

const serviceSchema = new mongoose.Schema({
  providerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Provider',
    required: [true, 'Provider ID is required'],
    index: true
  },
  name: {
    type: String,
    required: [true, 'Service name is required'],
    trim: true,
    maxlength: [100, 'Service name cannot exceed 100 characters']
  },
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  category: {
    type: String,
    required: [true, 'Service category is required'],
    enum: ['consultation', 'treatment', 'grooming', 'therapy', 'maintenance', 'emergency', 'other'],
    index: true
  },
  subCategory: String,
  duration: {
    type: Number,
    required: [true, 'Service duration is required'],
    min: [5, 'Duration must be at least 5 minutes'],
    max: [480, 'Duration cannot exceed 8 hours']
  },
  price: {
    type: Number,
    required: [true, 'Service price is required'],
    min: [0, 'Price cannot be negative']
  },
  discountPrice: {
    type: Number,
    min: [0, 'Discount price cannot be negative'],
    validate: {
      validator: function(v) {
        return !v || v < this.price;
      },
      message: 'Discount price must be less than regular price'
    }
  },
  currency: {
    type: String,
    default: 'INR'
  },
  images: [{
    url: String,
    caption: String
  }],
  features: [String], // List of service features/benefits
  requirements: [String], // What customer needs to bring/prepare
  contraindications: [String], // When service is not recommended
  aftercare: [String], // Post-service care instructions
  bookingAdvanceTime: {
    type: Number,
    default: 30, // minutes before appointment
    min: [0, 'Advance time cannot be negative']
  },
  maxBookingsPerDay: {
    type: Number,
    default: 10,
    min: [1, 'Must allow at least 1 booking per day']
  },
  availableDays: [{
    type: String,
    enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
  }],
  availableTimeSlots: [{
    start: String, // HH:MM format
    end: String    // HH:MM format
  }],
  isHomeServiceAvailable: {
    type: Boolean,
    default: false
  },
  homeServiceCharge: {
    type: Number,
    default: 0,
    min: [0, 'Home service charge cannot be negative']
  },
  isVideoConsultationAvailable: {
    type: Boolean,
    default: false
  },
  videoConsultationCharge: {
    type: Number,
    default: 0,
    min: [0, 'Video consultation charge cannot be negative']
  },
  isEmergencyServiceAvailable: {
    type: Boolean,
    default: false
  },
  emergencyServiceCharge: {
    type: Number,
    default: 0,
    min: [0, 'Emergency service charge cannot be negative']
  },
  tags: [String], // SEO and search tags
  popularity: {
    bookingCount: { type: Number, default: 0 },
    viewCount: { type: Number, default: 0 },
    favoriteCount: { type: Number, default: 0 }
  },
  rating: {
    average: { type: Number, default: 0, min: 0, max: 5 },
    total: { type: Number, default: 0 }
  },
  seoData: {
    metaTitle: String,
    metaDescription: String,
    keywords: [String]
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  isPromoted: {
    type: Boolean,
    default: false
  },
  promotionExpiry: Date,
  customFields: [{
    name: String,
    type: { type: String, enum: ['text', 'number', 'boolean', 'date', 'select'] },
    required: { type: Boolean, default: false },
    options: [String] // for select type
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for effective price
serviceSchema.virtual('effectivePrice').get(function() {
  return this.discountPrice || this.price;
});

// Virtual for discount percentage
serviceSchema.virtual('discountPercentage').get(function() {
  if (!this.discountPrice) return 0;
  return Math.round((this.price - this.discountPrice) / this.price * 100);
});

// Indexes for performance
serviceSchema.index({ providerId: 1, isActive: 1 });
serviceSchema.index({ category: 1, isActive: 1 });
serviceSchema.index({ name: 'text', description: 'text', tags: 'text' });
serviceSchema.index({ 'popularity.bookingCount': -1 });
serviceSchema.index({ 'rating.average': -1 });
serviceSchema.index({ price: 1 });

// Method to check availability for a specific day
serviceSchema.methods.isAvailableOnDay = function(dayName) {
  return this.availableDays.includes(dayName.toLowerCase());
};

// Method to check if time slot is available
serviceSchema.methods.isTimeSlotAvailable = function(time) {
  return this.availableTimeSlots.some(slot => 
    time >= slot.start && time <= slot.end
  );
};

// Method to update popularity
serviceSchema.methods.incrementView = function() {
  this.popularity.viewCount++;
  return this.save();
};

serviceSchema.methods.incrementBooking = function() {
  this.popularity.bookingCount++;
  return this.save();
};

module.exports = mongoose.model('Service', serviceSchema);
```

### Appointment Model

```javascript
// models/Appointment.js - Appointment booking model
const mongoose = require('mongoose');

const appointmentSchema = new mongoose.Schema({
  appointmentNumber: {
    type: String,
    unique: true,
    required: true
  },
  providerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Provider',
    required: [true, 'Provider ID is required'],
    index: true
  },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Customer ID is required'],
    index: true
  },
  serviceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Service',
    required: [true, 'Service ID is required']
  },
  appointmentDate: {
    type: Date,
    required: [true, 'Appointment date is required'],
    index: true
  },
  appointmentTime: {
    type: String,
    required: [true, 'Appointment time is required']
  },
  endTime: String, // Calculated based on service duration
  timeZone: {
    type: String,
    default: 'Asia/Kolkata'
  },
  duration: {
    type: Number,
    required: true // minutes
  },
  type: {
    type: String,
    enum: ['regular', 'home_service', 'video_consultation', 'emergency'],
    default: 'regular'
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show'],
    default: 'pending',
    index: true
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'partial', 'paid', 'refunded'],
    default: 'pending',
    index: true
  },
  paymentMethod: {
    type: String,
    enum: ['online', 'cash', 'card', 'wallet'],
    default: 'online'
  },
  pricing: {
    servicePrice: { type: Number, required: true },
    additionalCharges: { type: Number, default: 0 }, // home service, emergency, etc.
    discount: { type: Number, default: 0 },
    convenienceFee: { type: Number, default: 0 },
    taxes: { type: Number, default: 0 },
    totalAmount: { type: Number, required: true }
  },
  customerDetails: {
    name: { type: String, required: true },
    email: String,
    phone: { type: String, required: true },
    address: {
      street: String,
      city: String,
      state: String,
      zipCode: String,
      coordinates: [Number] // for home services
    },
    specialRequests: String,
    medicalConditions: [String], // for healthcare services
    allergies: [String],
    previousTreatments: [String]
  },
  providerNotes: String,
  customerNotes: String,
  internalNotes: String, // admin only
  prescriptions: [{
    medication: String,
    dosage: String,
    frequency: String,
    duration: String,
    notes: String
  }],
  treatments: [{
    name: String,
    description: String,
    duration: Number,
    notes: String,
    images: [String]
  }],
  attachments: [{
    fileName: String,
    fileUrl: String,
    fileType: String,
    uploadedBy: { type: String, enum: ['customer', 'provider', 'admin'] },
    uploadedAt: { type: Date, default: Date.now }
  }],
  qrCodeData: {
    qrCodeId: String,
    scannedAt: Date,
    scannedLocation: String
  },
  reminders: [{
    type: { type: String, enum: ['sms', 'whatsapp', 'email', 'push'] },
    sentAt: Date,
    status: { type: String, enum: ['sent', 'delivered', 'failed'] },
    message: String
  }],
  followUp: {
    isRequired: { type: Boolean, default: false },
    scheduledDate: Date,
    notes: String,
    completed: { type: Boolean, default: false }
  },
  cancellation: {
    cancelledBy: { type: String, enum: ['customer', 'provider', 'admin'] },
    cancelledAt: Date,
    reason: String,
    refundAmount: Number,
    refundStatus: { type: String, enum: ['pending', 'processed', 'failed'] }
  },
  rating: {
    score: { type: Number, min: 1, max: 5 },
    review: String,
    reviewDate: Date,
    providerResponse: String,
    providerResponseDate: Date
  },
  metadata: {
    source: { type: String, enum: ['qr_code', 'direct_link', 'search', 'referral'], default: 'qr_code' },
    device: String,
    ipAddress: String,
    userAgent: String,
    referrer: String
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for appointment end time
appointmentSchema.virtual('calculatedEndTime').get(function() {
  if (!this.appointmentTime || !this.duration) return null;
  
  const [hours, minutes] = this.appointmentTime.split(':').map(Number);
  const startMinutes = hours * 60 + minutes;
  const endMinutes = startMinutes + this.duration;
  
  const endHours = Math.floor(endMinutes / 60);
  const endMins = endMinutes % 60;
  
  return `${endHours.toString().padStart(2, '0')}:${endMins.toString().padStart(2, '0')}`;
});

// Virtual for days until appointment
appointmentSchema.virtual('daysUntilAppointment').get(function() {
  const today = new Date();
  const appointmentDate = new Date(this.appointmentDate);
  const diffTime = appointmentDate - today;
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

// Pre-save middleware to generate appointment number
appointmentSchema.pre('save', async function(next) {
  if (!this.appointmentNumber) {
    const date = new Date();
    const year = date.getFullYear().toString().substr(-2);
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    
    const count = await this.constructor.countDocuments({
      createdAt: {
        $gte: new Date(date.getFullYear(), date.getMonth(), date.getDate()),
        $lt: new Date(date.getFullYear(), date.getMonth(), date.getDate() + 1)
      }
    });
    
    this.appointmentNumber = `NQ${year}${month}${day}${(count + 1).toString().padStart(4, '0')}`;
  }
  
  // Calculate end time
  if (this.appointmentTime && this.duration && !this.endTime) {
    this.endTime = this.calculatedEndTime;
  }
  
  next();
});

// Indexes for performance
appointmentSchema.index({ appointmentNumber: 1 });
appointmentSchema.index({ providerId: 1, appointmentDate: 1 });
appointmentSchema.index({ customerId: 1, createdAt: -1 });
appointmentSchema.index({ status: 1, appointmentDate: 1 });
appointmentSchema.index({ paymentStatus: 1 });
appointmentSchema.index({ appointmentDate: 1, appointmentTime: 1 });

// Method to check if appointment can be cancelled
appointmentSchema.methods.canBeCancelled = function() {
  if (['completed', 'cancelled', 'no_show'].includes(this.status)) {
    return false;
  }
  
  const now = new Date();
  const appointmentDateTime = new Date(`${this.appointmentDate.toISOString().split('T')[0]}T${this.appointmentTime}`);
  const hoursUntilAppointment = (appointmentDateTime - now) / (1000 * 60 * 60);
  
  return hoursUntilAppointment > 2; // Can cancel up to 2 hours before
};

// Method to calculate refund amount
appointmentSchema.methods.calculateRefundAmount = function() {
  if (!this.canBeCancelled()) return 0;
  
  const now = new Date();
  const appointmentDateTime = new Date(`${this.appointmentDate.toISOString().split('T')[0]}T${this.appointmentTime}`);
  const hoursUntilAppointment = (appointmentDateTime - now) / (1000 * 60 * 60);
  
  if (hoursUntilAppointment > 24) {
    return this.pricing.totalAmount; // Full refund
  } else if (hoursUntilAppointment > 12) {
    return this.pricing.totalAmount * 0.8; // 80% refund
  } else if (hoursUntilAppointment > 2) {
    return this.pricing.totalAmount * 0.5; // 50% refund
  }
  
  return 0; // No refund
};

module.exports = mongoose.model('Appointment', appointmentSchema);
```