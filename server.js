require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const helmet = require('helmet');
const { body, param, query, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: process.env.FRONTEND_URL || '*',
        methods: ['GET', 'POST']
    }
});

// ============================================
// CONFIGURATION
// ============================================
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh-secret-key';
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';
const QR_TOKEN_EXPIRY = '30d';

// Token blacklist (in-memory, use Redis in production)
const tokenBlacklist = new Set();
const refreshTokenStore = new Map();

// Simple in-memory cache
const cache = {
    events: new Map(),
    guests: new Map(),
    dashboard: new Map(),
    
    get(key) {
        const item = this[key.split(':')[0]].get(key);
        if (item && item.expiry > Date.now()) {
            return item.data;
        }
        this[key.split(':')[0]].delete(key);
        return null;
    },
    
    set(key, data, ttl = 30000) {
        const type = key.split(':')[0];
        this[type].set(key, {
            data,
            expiry: Date.now() + ttl
        });
    },
    
    clear(type = null) {
        if (type) {
            this[type].clear();
        } else {
            Object.keys(this).forEach(key => {
                if (this[key] instanceof Map) {
                    this[key].clear();
                }
            });
        }
    }
};

// Swagger configuration
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'EventPass API',
            version: '2.0.0',
            description: 'Event Guest Management System API',
        },
        servers: [
            {
                url: `http://localhost:${process.env.PORT || 5000}`,
                description: 'Development server',
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
            },
        },
    },
    apis: [],
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);

// ============================================
// MIDDLEWARE SETUP
// ============================================
// CORS must come BEFORE other middleware
// Dynamic CORS configuration for production
const allowedOrigins = process.env.NODE_ENV === 'production' 
    ? [process.env.FRONTEND_URL || 'https://your-frontend-url.onrender.com']
    : ['http://localhost:5173', 'http://localhost:3000'];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV !== 'production') {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests - REMOVE the app.options('*', cors()) line
// Instead, let the cors middleware handle OPTIONS automatically
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb(new Error('Only image files are allowed'));
    }
};

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: fileFilter
});

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { success: false, error: 'Too many attempts, please try again later.' },
    skipSuccessfulRequests: true,
});

app.use('/api/', limiter);

// ============================================
// DATABASE CONNECTION
// ============================================
mongoose.connect(process.env.MONGO_URI)
.then(() => {
    console.log('✅ MongoDB connected successfully');
})
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});

// ============================================
// MODELS
// ============================================

// ----- LOG MODEL -----
const logSchema = new mongoose.Schema({
    type: {
        type: String,
        required: true,
        enum: ['INFO', 'WARNING', 'ERROR', 'AUDIT', 'SCAN', 'AUTH']
    },
    message: String,
    data: mongoose.Schema.Types.Mixed,
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    ip: String,
    userAgent: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Log = mongoose.model('Log', logSchema);

// ----- USER MODEL -----
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\S+@\S+\.\S+$/, 'Invalid email format']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters']
    },
    role: {
        type: String,
        enum: ['admin', 'staff'],
        default: 'staff'
    },
    profileImage: {
        type: String,
        default: null
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: Date,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

userSchema.pre('save', async function() {
    if (!this.isModified('password')) return;
    
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    // If this throws, Mongoose catches it automatically
});
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// ----- EVENT MODEL -----
const eventSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Event title is required'],
        trim: true
    },
    description: String,
    date: {
        type: Date,
        required: [true, 'Event date is required']
    },
    checkInStart: {
        type: Date,
        required: [true, 'Check-in start time is required']
    },
    checkInEnd: {
        type: Date,
        required: [true, 'Check-in end time is required']
    },
    location: {
        type: String,
        required: [true, 'Event location is required']
    },
    eventImage: {
        type: String,
        default: null
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    staff: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    guests: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Guest'
    }],
    isActive: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

eventSchema.virtual('isExpired').get(function() {
    return new Date() > this.date;
});

eventSchema.virtual('canCheckIn').get(function() {
    const now = new Date();
    return now >= this.checkInStart && now <= this.checkInEnd;
});

const Event = mongoose.model('Event', eventSchema);

// ----- GUEST MODEL -----
const guestSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Guest name is required'],
        trim: true
    },
    email: {
        type: String,
        lowercase: true,
        trim: true,
        match: [/^\S+@\S+\.\S+$/, 'Invalid email format']
    },
    phone: {
        type: String,
        trim: true
    },
    profileImage: {
        type: String,
        default: null
    },
    eventId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Event',
        required: true
    },
    tableNumber: {
        type: Number,
        min: 1
    },
    plusOne: {
        type: Boolean,
        default: false
    },
    plusOneName: String,
    qrCode: {
        type: String
    },
    qrToken: {
        type: String
    },
    uniqueCode: {
        type: String,
        unique: true,
        default: uuidv4
    },
    rsvpStatus: {
        type: String,
        enum: ['pending', 'accepted', 'declined'],
        default: 'pending'
    },
    rsvpRespondedAt: Date,
    checkedIn: {
        type: Boolean,
        default: false
    },
    checkedInAt: {
        type: Date
    },
    checkedInBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    // Add validation at schema level instead of pre-save middleware
    validate: {
        validator: function() {
            return !!(this.email || this.phone);
        },
        message: 'Either email or phone is required'
    }
});
const Guest = mongoose.model('Guest', guestSchema);

// ============================================
// CREATE DATABASE INDEXES (After all models are defined)
// ============================================
// ============================================
// CREATE DATABASE INDEXES (After all models are defined)
// ============================================
(async () => {
    try {
        // Wait for mongoose connection to be fully ready
        await mongoose.connection.once('open', async () => {
            try {
                // Only create indexes if collections exist
                const collections = await mongoose.connection.db.listCollections().toArray();
                const collectionNames = collections.map(c => c.name);
                
                if (collectionNames.includes('users')) {
                    await User.collection.createIndex({ email: 1 }, { unique: true });
                    console.log('✅ User indexes created');
                }
                
                if (collectionNames.includes('events')) {
                    await Event.collection.createIndex({ createdBy: 1, date: -1 });
                    await Event.collection.createIndex({ date: -1 });
                    console.log('✅ Event indexes created');
                }
                
                if (collectionNames.includes('guests')) {
                    await Guest.collection.createIndex({ eventId: 1, checkedIn: 1 });
                    await Guest.collection.createIndex({ uniqueCode: 1 }, { unique: true });
                    await Guest.collection.createIndex({ eventId: 1, isActive: 1 });
                    console.log('✅ Guest indexes created');
                }
                
                if (collectionNames.includes('logs')) {
                    await Log.collection.createIndex({ createdAt: -1 });
                    await Log.collection.createIndex({ type: 1, userId: 1 });
                    console.log('✅ Log indexes created');
                }
                
                console.log('✅ Database indexes created');
            } catch (err) {
                console.error('⚠️ Index creation warning:', err.message);
            }
        });
    } catch (error) {
        console.error('⚠️ Index setup error:', error.message);
    }
})();

// ============================================
// UTILITY FUNCTIONS
// ============================================

// ----- PERSISTENT LOGGING FUNCTION -----
const logToDB = async (type, message, data = {}, userId = null, req = null) => {
    try {
        const log = new Log({
            type,
            message,
            data,
            userId,
            ip: req?.ip || req?.connection?.remoteAddress,
            userAgent: req?.get('User-Agent')
        });
        await log.save();
        
        console.log(`[${new Date().toISOString()}] [${type}] ${message}`, data);
    } catch (error) {
        console.error('Logging error:', error);
    }
};

// ----- SECURE QR CODE GENERATION (JWT-based) -----
const generateSecureQRCode = async (guestId, eventId, uniqueCode) => {
    try {
        const qrToken = jwt.sign(
            {
                guestId: guestId.toString(),
                eventId: eventId.toString(),
                uniqueCode: uniqueCode,
                type: 'qr_checkin'
            },
            JWT_SECRET,
            { expiresIn: QR_TOKEN_EXPIRY }
        );
        
        const qrCode = await QRCode.toDataURL(qrToken, {
            errorCorrectionLevel: 'M',
            margin: 1,
            width: 250,
            color: {
                dark: '#000000',
                light: '#FFFFFF'
            }
        });
        
        return { qrCode, qrToken };
    } catch (error) {
        console.error('QR Generation Error:', error);
        throw error;
    }
};

// ----- VERIFY QR TOKEN -----
const verifyQRToken = (token) => {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.type !== 'qr_checkin') {
            throw new Error('Invalid QR token type');
        }
        return decoded;
    } catch (error) {
        throw new Error('Invalid or expired QR code');
    }
};

// ----- EMAIL & SMS MOCK FUNCTIONS -----
const sendEmailInvite = async (email, guestName, eventDetails, inviteLink) => {
    console.log(`📧 Sending email to ${email}:`);
    console.log(`   Subject: You're invited to ${eventDetails.title}!`);
    console.log(`   Body: Hi ${guestName}, you're invited to ${eventDetails.title}...`);
    await logToDB('INFO', 'Email invitation sent', { email, guestName, eventId: eventDetails.id });
    return { success: true, method: 'email' };
};

const sendSMSInvite = async (phone, guestName, eventDetails, inviteLink) => {
    console.log(`📱 Sending SMS to ${phone}:`);
    console.log(`   Message: Hi ${guestName}, you're invited to ${eventDetails.title}! Link: ${inviteLink}`);
    await logToDB('INFO', 'SMS invitation sent', { phone, guestName, eventId: eventDetails.id });
    return { success: true, method: 'sms' };
};

// ============================================
// MIDDLEWARE (AUTH & VALIDATION)
// ============================================

// ----- AUTHENTICATION MIDDLEWARE -----
const authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        
        if (tokenBlacklist.has(token)) {
            return res.status(401).json({ success: false, error: 'Token has been revoked' });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findOne({ 
            _id: decoded.userId, 
            isActive: true 
        });
        
        if (!user) {
            return res.status(401).json({ success: false, error: 'Invalid token' });
        }
        
        req.user = user;
        req.userId = user._id;
        req.token = token;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, error: 'Token expired' });
        }
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
};

// ----- ROLE-BASED ACCESS MIDDLEWARE -----
const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ success: false, error: 'Insufficient permissions' });
        }
        
        next();
    };
};

// ----- EVENT ACCESS VALIDATION -----
const validateEventAccess = async (req, res, next) => {
    try {
        const eventId = req.params.eventId || req.params.id;
        
        const event = await Event.findOne({ 
            _id: eventId, 
            isActive: true,
            $or: [
                { createdBy: req.userId },
                { staff: req.userId }
            ]
        });
        
        if (!event) {
            return res.status(404).json({ success: false, error: 'Event not found or access denied' });
        }
        
        req.event = event;
        next();
    } catch (error) {
        next(error);
    }
};

// ----- VALIDATION ERROR HANDLER -----
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            errors: errors.array().map(err => ({
                field: err.param,
                message: err.msg
            }))
        });
    }
    next();
};

// ============================================
// SOCKET.IO SETUP
// ============================================
io.on('connection', (socket) => {
    console.log('🔌 New client connected:', socket.id);
    
    socket.on('joinEvent', (eventId) => {
        socket.join(`event:${eventId}`);
        console.log(`Client ${socket.id} joined event room: ${eventId}`);
    });
    
    socket.on('leaveEvent', (eventId) => {
        socket.leave(`event:${eventId}`);
        console.log(`Client ${socket.id} left event room: ${eventId}`);
    });
    
    socket.on('disconnect', () => {
        console.log('🔌 Client disconnected:', socket.id);
    });
});

const emitGuestCheckedIn = (eventId, guestData) => {
    io.to(`event:${eventId}`).emit('guestCheckedIn', {
        ...guestData,
        timestamp: new Date()
    });
};

// ============================================
// ROUTES
// ============================================

// ===== SWAGGER DOCS =====
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// ===== AUTH ROUTES =====

// POST /api/auth/signup
app.post('/api/auth/signup',
    [
        body('name').notEmpty().withMessage('Name is required').trim(),
        body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
        body('role').optional().isIn(['admin', 'staff']).withMessage('Invalid role')
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const { name, email, password, role } = req.body;
            
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ success: false, error: 'Email already registered' });
            }
            
            const userRole = role === 'admin' ? 'admin' : 'staff';
            
            const user = new User({
                name,
                email,
                password,
                role: userRole
            });
            
            await user.save();
            
            const accessToken = jwt.sign(
                { userId: user._id, role: user.role },
                JWT_SECRET,
                { expiresIn: ACCESS_TOKEN_EXPIRY }
            );
            
            const refreshToken = jwt.sign(
                { userId: user._id },
                JWT_REFRESH_SECRET,
                { expiresIn: REFRESH_TOKEN_EXPIRY }
            );
            
            refreshTokenStore.set(user._id.toString(), refreshToken);
            
            await logToDB('AUTH', 'User signed up', { email: user.email }, user._id, req);
            
            res.status(201).json({
                success: true,
                message: 'User created successfully',
                accessToken,
                refreshToken,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/auth/login
app.post('/api/auth/login',
    [
        body('email').isEmail().withMessage('Valid email is required'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    handleValidationErrors,
    strictLimiter,
    async (req, res, next) => {
        try {
            const { email, password } = req.body;
            
            const user = await User.findOne({ email, isActive: true });
            if (!user) {
                await logToDB('AUTH', 'Failed login attempt', { email }, null, req);
                return res.status(401).json({ success: false, error: 'Invalid credentials' });
            }
            
            const isMatch = await user.comparePassword(password);
            if (!isMatch) {
                await logToDB('AUTH', 'Failed login attempt - wrong password', { email }, user._id, req);
                return res.status(401).json({ success: false, error: 'Invalid credentials' });
            }
            
            user.lastLogin = new Date();
            await user.save();
            
            const accessToken = jwt.sign(
                { userId: user._id, role: user.role },
                JWT_SECRET,
                { expiresIn: ACCESS_TOKEN_EXPIRY }
            );
            
            const refreshToken = jwt.sign(
                { userId: user._id },
                JWT_REFRESH_SECRET,
                { expiresIn: REFRESH_TOKEN_EXPIRY }
            );
            
            refreshTokenStore.set(user._id.toString(), refreshToken);
            
            await logToDB('AUTH', 'User logged in', { email: user.email }, user._id, req);
            
            res.json({
                success: true,
                message: 'Login successful',
                accessToken,
                refreshToken,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/auth/refresh
app.post('/api/auth/refresh', async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        
        if (!refreshToken) {
            return res.status(400).json({ success: false, error: 'Refresh token required' });
        }
        
        const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
        const storedToken = refreshTokenStore.get(decoded.userId);
        
        if (storedToken !== refreshToken) {
            return res.status(401).json({ success: false, error: 'Invalid refresh token' });
        }
        
        const user = await User.findById(decoded.userId);
        if (!user || !user.isActive) {
            return res.status(401).json({ success: false, error: 'User not found' });
        }
        
        const newAccessToken = jwt.sign(
            { userId: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: ACCESS_TOKEN_EXPIRY }
        );
        
        res.json({
            success: true,
            accessToken: newAccessToken
        });
    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid refresh token' });
    }
});

// POST /api/auth/logout
app.post('/api/auth/logout', authenticate, async (req, res, next) => {
    try {
        tokenBlacklist.add(req.token);
        refreshTokenStore.delete(req.userId.toString());
        
        await logToDB('AUTH', 'User logged out', {}, req.userId, req);
        
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        next(error);
    }
});

// ===== EVENT ROUTES =====

// POST /api/events - Create event
app.post('/api/events',
    authenticate,
    upload.single('eventImage'),
    [
        body('title').notEmpty().withMessage('Event title is required'),
        body('date').isISO8601().withMessage('Valid date is required'),
        body('checkInStart').isISO8601().withMessage('Valid check-in start time is required'),
        body('checkInEnd').isISO8601().withMessage('Valid check-in end time is required'),
        body('location').notEmpty().withMessage('Location is required'),
        body('staff').optional().isArray().withMessage('Staff must be an array of user IDs')
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const { title, description, date, checkInStart, checkInEnd, location, staff } = req.body;
            
            const event = new Event({
                title,
                description,
                date: new Date(date),
                checkInStart: new Date(checkInStart),
                checkInEnd: new Date(checkInEnd),
                location,
                createdBy: req.userId,
                staff: staff || [],
                eventImage: req.file ? `/uploads/${req.file.filename}` : null
            });
            
            await event.save();
            
            cache.clear('events');
            
            await logToDB('INFO', 'Event created', { eventId: event._id, title }, req.userId, req);
            
            res.status(201).json({
                success: true,
                message: 'Event created successfully',
                event
            });
        } catch (error) {
            next(error);
        }
    }
);

// GET /api/events - Get all user events (with pagination)
app.get('/api/events',
    authenticate,
    [
        query('page').optional().isInt({ min: 1 }).toInt(),
        query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
        query('search').optional().isString().trim()
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const search = req.query.search || '';
            const skip = (page - 1) * limit;
            
            const cacheKey = `events:${req.userId}:${page}:${limit}:${search}`;
            const cachedData = cache.get(cacheKey);
            
            if (cachedData) {
                return res.json({ success: true, ...cachedData, cached: true });
            }
            
            const query = {
                $or: [
                    { createdBy: req.userId },
                    { staff: req.userId }
                ],
                isActive: true
            };
            
            if (search) {
                query.$or = [
                    { title: { $regex: search, $options: 'i' } },
                    { location: { $regex: search, $options: 'i' } }
                ];
            }
            
            const [events, total] = await Promise.all([
                Event.find(query)
                    .sort({ date: -1 })
                    .skip(skip)
                    .limit(limit)
                    .populate('createdBy', 'name email'),
                Event.countDocuments(query)
            ]);
            
            const eventsWithStats = await Promise.all(events.map(async (event) => {
                const guestCount = await Guest.countDocuments({ 
                    eventId: event._id, 
                    isActive: true 
                });
                
                return {
                    ...event.toObject(),
                    guestCount,
                    canCheckIn: event.canCheckIn
                };
            }));
            
            const result = {
                events: eventsWithStats,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            };
            
            cache.set(cacheKey, result, 30000);
            
            res.json({ success: true, ...result });
        } catch (error) {
            next(error);
        }
    }
);

// PUT /api/events/:id - Update event
app.put('/api/events/:id',
    authenticate,
    validateEventAccess,
    upload.single('eventImage'),
    [
        param('id').isMongoId().withMessage('Invalid event ID'),
        body('title').optional().notEmpty(),
        body('date').optional().isISO8601(),
        body('checkInStart').optional().isISO8601(),
        body('checkInEnd').optional().isISO8601(),
        body('location').optional().notEmpty()
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const updates = { ...req.body };
            if (req.file) {
                updates.eventImage = `/uploads/${req.file.filename}`;
            }
            
            ['date', 'checkInStart', 'checkInEnd'].forEach(field => {
                if (updates[field]) {
                    updates[field] = new Date(updates[field]);
                }
            });
            
            const event = await Event.findByIdAndUpdate(
                req.params.id,
                updates,
                { new: true, runValidators: true }
            );
            
            cache.clear('events');
            cache.clear('dashboard');
            
            await logToDB('INFO', 'Event updated', { eventId: event._id }, req.userId, req);
            
            res.json({
                success: true,
                message: 'Event updated successfully',
                event
            });
        } catch (error) {
            next(error);
        }
    }
);

// DELETE /api/events/:id - Soft delete event
app.delete('/api/events/:id',
    authenticate,
    validateEventAccess,
    [param('id').isMongoId().withMessage('Invalid event ID')],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            await Event.findByIdAndUpdate(req.params.id, { isActive: false });
            await Guest.updateMany(
                { eventId: req.params.id },
                { isActive: false }
            );
            
            cache.clear('events');
            cache.clear('guests');
            cache.clear('dashboard');
            
            await logToDB('AUDIT', 'Event soft deleted', { eventId: req.params.id }, req.userId, req);
            
            res.json({ success: true, message: 'Event deleted successfully' });
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/events/:id/staff - Add staff to event
app.post('/api/events/:id/staff',
    authenticate,
    requireRole('admin'),
    [
        param('id').isMongoId().withMessage('Invalid event ID'),
        body('staffId').isMongoId().withMessage('Invalid staff ID')
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const event = await Event.findOne({ 
                _id: req.params.id, 
                createdBy: req.userId,
                isActive: true 
            });
            
            if (!event) {
                return res.status(404).json({ success: false, error: 'Event not found' });
            }
            
            const staffUser = await User.findById(req.body.staffId);
            if (!staffUser || staffUser.role !== 'staff') {
                return res.status(400).json({ success: false, error: 'Invalid staff user' });
            }
            
            if (!event.staff.includes(req.body.staffId)) {
                event.staff.push(req.body.staffId);
                await event.save();
            }
            
            await logToDB('AUDIT', 'Staff added to event', { 
                eventId: event._id, 
                staffId: req.body.staffId 
            }, req.userId, req);
            
            res.json({ success: true, message: 'Staff added successfully', event });
        } catch (error) {
            next(error);
        }
    }
);

// ===== GUEST ROUTES =====

// POST /api/guests/:eventId - Add guest to event
app.post('/api/guests/:eventId',
    authenticate,
    validateEventAccess,
    upload.single('profileImage'),
    [
        param('eventId').isMongoId().withMessage('Invalid event ID'),
        body('name').notEmpty().withMessage('Guest name is required'),
        body('email').optional().isEmail().withMessage('Invalid email format'),
        body('phone').optional().isString(),
        body('tableNumber').optional().isInt({ min: 1 }),
        body('plusOne').optional().isBoolean()
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const { name, email, phone, tableNumber, plusOne } = req.body;
            
            if (!email && !phone) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Either email or phone is required' 
                });
            }
            
            const guest = new Guest({
                name,
                email,
                phone,
                eventId: req.params.eventId,
                tableNumber,
                plusOne: plusOne || false,
                profileImage: req.file ? `/uploads/${req.file.filename}` : null
            });
            
            const { qrCode, qrToken } = await generateSecureQRCode(
                guest._id, 
                req.params.eventId, 
                guest.uniqueCode
            );
            
            guest.qrCode = qrCode;
            guest.qrToken = qrToken;
            
            await guest.save();
            
            await Event.findByIdAndUpdate(req.params.eventId, {
                $push: { guests: guest._id }
            });
            
            cache.clear('guests');
            cache.clear('dashboard');
            
            await logToDB('INFO', 'Guest added', { 
                guestId: guest._id, 
                eventId: req.params.eventId 
            }, req.userId, req);
            
            const inviteLink = `${process.env.APP_URL || 'http://localhost:5173'}/invite/${guest.uniqueCode}`;
            
            if (email) {
                await sendEmailInvite(email, name, req.event, inviteLink);
            }
            if (phone) {
                await sendSMSInvite(phone, name, req.event, inviteLink);
            }
            
            res.status(201).json({
                success: true,
                message: 'Guest added successfully',
                guest,
                inviteLink
            });
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/guests/bulk/:eventId - Bulk guest upload
app.post('/api/guests/bulk/:eventId',
    authenticate,
    validateEventAccess,
    async (req, res, next) => {
        try {
            const { guests } = req.body;
            
            if (!Array.isArray(guests) || guests.length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Guests array is required' 
                });
            }
            
            const guestsToInsert = [];
            const errors = [];
            
            for (const guestData of guests) {
                if (!guestData.name || (!guestData.email && !guestData.phone)) {
                    errors.push({ guest: guestData, error: 'Invalid guest data' });
                    continue;
                }
                
                const guest = {
                    ...guestData,
                    eventId: req.params.eventId,
                    uniqueCode: uuidv4()
                };
                
                const { qrCode, qrToken } = await generateSecureQRCode(
                    new mongoose.Types.ObjectId(),
                    req.params.eventId,
                    guest.uniqueCode
                );
                
                guest.qrCode = qrCode;
                guest.qrToken = qrToken;
                guest._id = new mongoose.Types.ObjectId();
                
                guestsToInsert.push(guest);
            }
            
            let insertedGuests = [];
            if (guestsToInsert.length > 0) {
                insertedGuests = await Guest.insertMany(guestsToInsert, { 
                    ordered: false,
                    rawResult: false
                });
                
                await Event.findByIdAndUpdate(req.params.eventId, {
                    $push: { guests: { $each: insertedGuests.map(g => g._id) } }
                });
            }
            
            cache.clear('guests');
            cache.clear('dashboard');
            
            await logToDB('INFO', 'Bulk guests added', { 
                eventId: req.params.eventId, 
                count: insertedGuests.length,
                errors: errors.length
            }, req.userId, req);
            
            res.status(201).json({
                success: true,
                message: `Added ${insertedGuests.length} guests`,
                successCount: insertedGuests.length,
                errorCount: errors.length,
                errors: errors.length > 0 ? errors : undefined
            });
        } catch (error) {
            if (error.writeErrors) {
                return res.status(207).json({
                    success: true,
                    message: 'Partial success',
                    successCount: error.insertedDocs?.length || 0,
                    errorCount: error.writeErrors.length,
                    errors: error.writeErrors.map(e => ({
                        index: e.index,
                        error: e.errmsg
                    }))
                });
            }
            next(error);
        }
    }
);

// GET /api/guests/:eventId - Get all guests for event
app.get('/api/guests/:eventId',
    authenticate,
    validateEventAccess,
    [
        param('eventId').isMongoId().withMessage('Invalid event ID'),
        query('page').optional().isInt({ min: 1 }).toInt(),
        query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
        query('search').optional().isString().trim(),
        query('rsvpStatus').optional().isIn(['pending', 'accepted', 'declined']),
        query('checkedIn').optional().isBoolean()
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 20;
            const search = req.query.search || '';
            const skip = (page - 1) * limit;
            
            const cacheKey = `guests:${req.params.eventId}:${page}:${limit}:${search}`;
            const cachedData = cache.get(cacheKey);
            
            if (cachedData) {
                return res.json({ success: true, ...cachedData, cached: true });
            }
            
            const query = { 
                eventId: req.params.eventId,
                isActive: true 
            };
            
            if (search) {
                query.$or = [
                    { name: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } },
                    { phone: { $regex: search, $options: 'i' } }
                ];
            }
            
            if (req.query.rsvpStatus) {
                query.rsvpStatus = req.query.rsvpStatus;
            }
            
            if (req.query.checkedIn !== undefined) {
                query.checkedIn = req.query.checkedIn === 'true';
            }
            
            const [guests, total] = await Promise.all([
                Guest.find(query)
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit),
                Guest.countDocuments(query)
            ]);
            
            const result = {
                guests,
                stats: {
                    total,
                    checkedIn: await Guest.countDocuments({ ...query, checkedIn: true }),
                    accepted: await Guest.countDocuments({ ...query, rsvpStatus: 'accepted' }),
                    declined: await Guest.countDocuments({ ...query, rsvpStatus: 'declined' })
                },
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit)
                }
            };
            
            cache.set(cacheKey, result, 30000);
            
            res.json({ success: true, ...result });
        } catch (error) {
            next(error);
        }
    }
);

// PUT /api/guests/:id - Edit guest
app.put('/api/guests/:id',
    authenticate,
    upload.single('profileImage'),
    [
        param('id').isMongoId().withMessage('Invalid guest ID'),
        body('name').optional().notEmpty(),
        body('email').optional().isEmail(),
        body('phone').optional().isString(),
        body('tableNumber').optional().isInt({ min: 1 }),
        body('plusOne').optional().isBoolean()
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const guest = await Guest.findById(req.params.id);
            if (!guest || !guest.isActive) {
                return res.status(404).json({ success: false, error: 'Guest not found' });
            }
            
            const event = await Event.findOne({ 
                _id: guest.eventId,
                $or: [
                    { createdBy: req.userId },
                    { staff: req.userId }
                ]
            });
            
            if (!event) {
                return res.status(403).json({ success: false, error: 'Access denied' });
            }
            
            Object.assign(guest, req.body);
            if (req.file) {
                guest.profileImage = `/uploads/${req.file.filename}`;
            }
            
            await guest.save();
            
            cache.clear('guests');
            cache.clear('dashboard');
            
            await logToDB('INFO', 'Guest updated', { guestId: guest._id }, req.userId, req);
            
            res.json({
                success: true,
                message: 'Guest updated successfully',
                guest
            });
        } catch (error) {
            next(error);
        }
    }
);

// DELETE /api/guests/:id - Soft delete guest
app.delete('/api/guests/:id',
    authenticate,
    [param('id').isMongoId().withMessage('Invalid guest ID')],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const guest = await Guest.findById(req.params.id);
            if (!guest) {
                return res.status(404).json({ success: false, error: 'Guest not found' });
            }
            
            const event = await Event.findOne({ 
                _id: guest.eventId,
                $or: [
                    { createdBy: req.userId },
                    { staff: req.userId }
                ]
            });
            
            if (!event) {
                return res.status(403).json({ success: false, error: 'Access denied' });
            }
            
            guest.isActive = false;
            await guest.save();
            
            await Event.findByIdAndUpdate(guest.eventId, {
                $pull: { guests: guest._id }
            });
            
            cache.clear('guests');
            cache.clear('dashboard');
            
            await logToDB('AUDIT', 'Guest soft deleted', { guestId: guest._id }, req.userId, req);
            
            res.json({ success: true, message: 'Guest deleted successfully' });
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/guests/:id/rsvp - RSVP endpoint
app.post('/api/guests/:id/rsvp',
    [
        param('id').notEmpty().withMessage('Guest ID or unique code is required'),
        body('status').isIn(['accepted', 'declined']).withMessage('Invalid RSVP status'),
        body('plusOneName').optional().isString()
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const guest = await Guest.findOne({ 
                $or: [
                    { uniqueCode: req.params.id },
                    { _id: mongoose.isValidObjectId(req.params.id) ? req.params.id : null }
                ],
                isActive: true 
            });
            
            if (!guest) {
                return res.status(404).json({ success: false, error: 'Guest not found' });
            }
            
            const event = await Event.findById(guest.eventId);
            if (!event || !event.isActive) {
                return res.status(400).json({ success: false, error: 'Event not found' });
            }
            
            if (new Date() > event.date) {
                return res.status(400).json({ success: false, error: 'Event has already ended' });
            }
            
            guest.rsvpStatus = req.body.status;
            guest.rsvpRespondedAt = new Date();
            if (req.body.plusOneName) {
                guest.plusOneName = req.body.plusOneName;
            }
            
            await guest.save();
            
            cache.clear('guests');
            cache.clear('dashboard');
            
            await logToDB('INFO', `Guest RSVP ${req.body.status}`, { 
                guestId: guest._id,
                eventId: guest.eventId
            }, null, req);
            
            res.json({
                success: true,
                message: `RSVP ${req.body.status} successfully`,
                guest: {
                    name: guest.name,
                    rsvpStatus: guest.rsvpStatus,
                    event: event.title
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/guests/:id/resend - Resend invitation
app.post('/api/guests/:id/resend',
    authenticate,
    [param('id').isMongoId().withMessage('Invalid guest ID')],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const guest = await Guest.findById(req.params.id);
            if (!guest || !guest.isActive) {
                return res.status(404).json({ success: false, error: 'Guest not found' });
            }
            
            const event = await Event.findOne({ 
                _id: guest.eventId,
                $or: [
                    { createdBy: req.userId },
                    { staff: req.userId }
                ]
            });
            
            if (!event) {
                return res.status(403).json({ success: false, error: 'Access denied' });
            }
            
            guest.uniqueCode = uuidv4();
            const { qrCode, qrToken } = await generateSecureQRCode(
                guest._id, 
                guest.eventId, 
                guest.uniqueCode
            );
            
            guest.qrCode = qrCode;
            guest.qrToken = qrToken;
            await guest.save();
            
            cache.clear('guests');
            
            await logToDB('INFO', 'Invitation resent', { guestId: guest._id }, req.userId, req);
            
            const inviteLink = `${process.env.APP_URL || 'http://localhost:5173'}/invite/${guest.uniqueCode}`;
            const whatsappMessage = encodeURIComponent(
                `You're invited to ${event.title}! 🎉\n\n` +
                `Date: ${new Date(event.date).toLocaleString()}\n` +
                `Location: ${event.location}\n\n` +
                `RSVP here: ${inviteLink}`
            );
            
            res.json({
                success: true,
                message: 'Invitation resent successfully',
                inviteLink,
                whatsappLink: `https://wa.me/?text=${whatsappMessage}`,
                qrCode: guest.qrCode
            });
        } catch (error) {
            next(error);
        }
    }
);

// ===== QR SCANNER / CHECK-IN SYSTEM =====

// POST /api/scan - Scan QR and check-in guest
app.post('/api/scan',
    authenticate,
    requireRole('admin', 'staff'),
    strictLimiter,
    [
        body('qrToken').notEmpty().withMessage('QR token is required')
    ],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const { qrToken } = req.body;
            
            let decodedData;
            try {
                decodedData = verifyQRToken(qrToken);
            } catch (error) {
                await logToDB('SCAN', 'Invalid QR token attempt', { error: error.message }, req.userId, req);
                return res.status(400).json({ 
                    success: false,
                    error: 'Invalid or expired QR code',
                    status: 'invalid'
                });
            }
            
            const { guestId, eventId, uniqueCode } = decodedData;
            
            const guest = await Guest.findOne({ 
                _id: guestId,
                eventId: eventId,
                uniqueCode: uniqueCode,
                isActive: true
            });
            
            if (!guest) {
                await logToDB('SCAN', 'Guest not found', { guestId }, req.userId, req);
                return res.status(404).json({ 
                    success: false,
                    error: 'Guest not found',
                    status: 'invalid'
                });
            }
            
            const event = await Event.findById(eventId);
            if (!event || !event.isActive) {
                await logToDB('SCAN', 'Event not active', { eventId, guestId }, req.userId, req);
                return res.status(400).json({ 
                    success: false,
                    error: 'Event is not active',
                    status: 'invalid'
                });
            }
            
            if (req.user.role === 'staff' && 
                !event.staff.includes(req.userId) && 
                event.createdBy.toString() !== req.userId.toString()) {
                await logToDB('SCAN', 'Staff not authorized for this event', { eventId }, req.userId, req);
                return res.status(403).json({ 
                    success: false,
                    error: 'You are not authorized to scan for this event',
                    status: 'unauthorized'
                });
            }
            
            if (!event.canCheckIn) {
                const now = new Date();
                const message = now < event.checkInStart 
                    ? 'Check-in has not started yet' 
                    : 'Check-in period has ended';
                
                await logToDB('SCAN', 'Check-in outside allowed time', { guestId, eventId }, req.userId, req);
                return res.status(400).json({ 
                    success: false,
                    error: message,
                    status: 'time_invalid',
                    checkInWindow: {
                        start: event.checkInStart,
                        end: event.checkInEnd
                    }
                });
            }
            
            if (event.isExpired) {
                await logToDB('SCAN', 'Event expired', { guestId, eventId }, req.userId, req);
                return res.status(400).json({ 
                    success: false,
                    error: 'Event has already ended',
                    status: 'expired'
                });
            }
            
            if (guest.rsvpStatus === 'declined') {
                await logToDB('SCAN', 'Guest declined RSVP', { guestId }, req.userId, req);
                return res.status(400).json({ 
                    success: false,
                    error: 'Guest has declined the invitation',
                    status: 'declined'
                });
            }
            
            if (guest.checkedIn) {
                await logToDB('SCAN', 'Duplicate check-in attempt', { 
                    guestId, 
                    checkedInAt: guest.checkedInAt 
                }, req.userId, req);
                
                return res.status(400).json({ 
                    success: false,
                    error: 'Guest already checked in',
                    status: 'duplicate',
                    guest: {
                        name: guest.name,
                        tableNumber: guest.tableNumber,
                        checkedInAt: guest.checkedInAt,
                        checkedInBy: guest.checkedInBy
                    }
                });
            }
            
            guest.checkedIn = true;
            guest.checkedInAt = new Date();
            guest.checkedInBy = req.userId;
            await guest.save();
            
            cache.clear('guests');
            cache.clear('dashboard');
            
            await logToDB('SCAN', 'Check-in successful', { 
                guestId, 
                eventId, 
                guestName: guest.name,
                tableNumber: guest.tableNumber
            }, req.userId, req);
            
            emitGuestCheckedIn(eventId, {
                guestId: guest._id,
                name: guest.name,
                tableNumber: guest.tableNumber,
                checkedInAt: guest.checkedInAt,
                checkedInBy: req.user.name
            });
            
            res.json({
                success: true,
                message: 'Check-in successful',
                status: 'valid',
                guest: {
                    id: guest._id,
                    name: guest.name,
                    tableNumber: guest.tableNumber,
                    plusOne: guest.plusOne,
                    plusOneName: guest.plusOneName,
                    checkedInAt: guest.checkedInAt,
                    profileImage: guest.profileImage
                },
                event: {
                    title: event.title,
                    location: event.location
                }
            });
        } catch (error) {
            next(error);
        }
    }
);

// ===== INVITATION ROUTE (Public) =====

// GET /invite/:uniqueCode - Get invitation details
app.get('/invite/:uniqueCode', async (req, res, next) => {
    try {
        const { uniqueCode } = req.params;
        
        const guest = await Guest.findOne({ 
            uniqueCode, 
            isActive: true 
        }).populate('eventId');
        
        if (!guest) {
            return res.status(404).json({ success: false, error: 'Invitation not found' });
        }
        
        const event = guest.eventId;
        
        if (event.isExpired) {
            return res.status(400).json({ success: false, error: 'Event has already ended' });
        }
        
        res.json({
            success: true,
            guest: {
                id: guest._id,
                name: guest.name,
                tableNumber: guest.tableNumber,
                plusOne: guest.plusOne,
                plusOneName: guest.plusOneName,
                rsvpStatus: guest.rsvpStatus,
                checkedIn: guest.checkedIn,
                profileImage: guest.profileImage
            },
            event: {
                id: event._id,
                title: event.title,
                description: event.description,
                date: event.date,
                location: event.location,
                checkInStart: event.checkInStart,
                checkInEnd: event.checkInEnd,
                eventImage: event.eventImage
            },
            qrCode: guest.qrCode
        });
    } catch (error) {
        next(error);
    }
});

// ===== DASHBOARD ANALYTICS =====

// GET /api/dashboard/:eventId - Get dashboard stats
app.get('/api/dashboard/:eventId',
    authenticate,
    validateEventAccess,
    [param('eventId').isMongoId().withMessage('Invalid event ID')],
    handleValidationErrors,
    async (req, res, next) => {
        try {
            const eventId = req.params.eventId;
            
            const cacheKey = `dashboard:${eventId}`;
            const cachedData = cache.get(cacheKey);
            
            if (cachedData) {
                return res.json({ success: true, ...cachedData, cached: true });
            }
            
            const guests = await Guest.find({ 
                eventId, 
                isActive: true 
            });
            
            const totalGuests = guests.length;
            const checkedInGuests = guests.filter(g => g.checkedIn).length;
            const notArrivedGuests = totalGuests - checkedInGuests;
            const attendancePercentage = totalGuests > 0 
                ? ((checkedInGuests / totalGuests) * 100).toFixed(2)
                : 0;
            
            const rsvpStats = {
                accepted: guests.filter(g => g.rsvpStatus === 'accepted').length,
                declined: guests.filter(g => g.rsvpStatus === 'declined').length,
                pending: guests.filter(g => g.rsvpStatus === 'pending').length
            };
            
            const checkInsByHour = {};
            const checkInsToday = guests.filter(g => {
                if (!g.checkedInAt) return false;
                const today = new Date();
                const checkInDate = new Date(g.checkedInAt);
                return checkInDate.toDateString() === today.toDateString();
            });
            
            checkInsToday.forEach(guest => {
                const hour = new Date(guest.checkedInAt).getHours();
                checkInsByHour[hour] = (checkInsByHour[hour] || 0) + 1;
            });
            
            const tableDistribution = {};
            guests.forEach(guest => {
                if (guest.tableNumber) {
                    if (!tableDistribution[guest.tableNumber]) {
                        tableDistribution[guest.tableNumber] = {
                            total: 0,
                            checkedIn: 0
                        };
                    }
                    tableDistribution[guest.tableNumber].total++;
                    if (guest.checkedIn) {
                        tableDistribution[guest.tableNumber].checkedIn++;
                    }
                }
            });
            
            const recentCheckIns = await Guest.find({
                eventId,
                checkedIn: true
            })
            .sort({ checkedInAt: -1 })
            .limit(10)
            .populate('checkedInBy', 'name');
            
            const result = {
                summary: {
                    totalGuests,
                    checkedInGuests,
                    notArrivedGuests,
                    attendancePercentage,
                    rsvpStats
                },
                checkInsByHour,
                tableDistribution,
                recentCheckIns: recentCheckIns.map(g => ({
                    name: g.name,
                    tableNumber: g.tableNumber,
                    checkedInAt: g.checkedInAt,
                    checkedInBy: g.checkedInBy?.name
                })),
                event: {
                    ...req.event.toObject(),
                    canCheckIn: req.event.canCheckIn,
                    isExpired: req.event.isExpired
                }
            };
            
            cache.set(cacheKey, result, 15000);
            
            res.json({ success: true, ...result });
        } catch (error) {
            next(error);
        }
    }
);

// ===== HEALTH CHECK =====
app.get('/api/health', async (req, res) => {
    try {
        const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
        const memoryUsage = process.memoryUsage();
        
        res.json({ 
            success: true,
            status: 'OK', 
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            environment: process.env.NODE_ENV || 'development',
            database: {
                status: dbStatus,
                connections: mongoose.connections.length
            },
            memory: {
                heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)} MB`,
                heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)} MB`,
                rss: `${Math.round(memoryUsage.rss / 1024 / 1024)} MB`
            },
            cache: {
                events: cache.events.size,
                guests: cache.guests.size,
                dashboard: cache.dashboard.size
            },
            activeSocketConnections: io.engine.clientsCount
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            status: 'Error', 
            error: error.message 
        });
    }
});

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// ============================================
// CENTRAL ERROR HANDLER
// ============================================
app.use((err, req, res, next) => {
    console.error('Error:', err);
    
    logToDB('ERROR', err.message, { 
        stack: err.stack,
        url: req.url,
        method: req.method
    }, req.userId || null, req).catch(console.error);
    
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            error: 'Validation Error',
            details: Object.values(err.errors).map(e => e.message)
        });
    }
    
    if (err.name === 'CastError') {
        return res.status(400).json({
            success: false,
            error: 'Invalid ID format'
        });
    }
    
    if (err.code === 11000) {
        return res.status(400).json({
            success: false,
            error: 'Duplicate entry',
            field: Object.keys(err.keyPattern)[0]
        });
    }
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                success: false,
                error: 'File too large. Maximum size is 5MB'
            });
        }
    }
    
    res.status(err.status || 500).json({
        success: false,
        error: err.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Route not found'
    });
});

// ============================================
// SERVER START
// ============================================
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════════════════╗
    ║          🎉 EventPass Backend Server v2.0        ║
    ╠══════════════════════════════════════════════════╣
    ║  Server running on port: ${PORT}                   ║
    ║  Environment: ${process.env.NODE_ENV || 'development'}                       ║
    ║  MongoDB: Connected                               ║
    ║  Socket.IO: Enabled                               ║
    ║  API Docs: http://localhost:${PORT}/api-docs       ║
    ║  Health: http://localhost:${PORT}/api/health       ║
    ╚══════════════════════════════════════════════════╝
    `);
    
    logToDB('INFO', 'Server started', { port: PORT, environment: process.env.NODE_ENV });
});

// Graceful shutdown
const gracefulShutdown = async () => {
    console.log('\n🔄 Graceful shutdown initiated...');
    
    server.close(() => {
        console.log('✅ HTTP server closed');
    });
    
    io.close(() => {
        console.log('✅ Socket.IO server closed');
    });
    
    try {
        await mongoose.connection.close();
        console.log('✅ MongoDB connection closed');
    } catch (error) {
        console.error('❌ Error closing MongoDB connection:', error);
    }
    
    await logToDB('INFO', 'Server shutdown', { reason: 'SIGTERM' });
    
    console.log('👋 Server shutdown complete');
    process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

process.on('unhandledRejection', async (error) => {
    console.error('❌ Unhandled Rejection:', error);
    await logToDB('ERROR', 'Unhandled Rejection', { 
        error: error.message, 
        stack: error.stack 
    });
});

process.on('uncaughtException', async (error) => {
    console.error('❌ Uncaught Exception:', error);
    await logToDB('ERROR', 'Uncaught Exception', { 
        error: error.message, 
        stack: error.stack 
    });
    gracefulShutdown();
});

module.exports = app;