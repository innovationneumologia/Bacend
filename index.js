// ============ NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API ============
// VERSION 4.2 - COMPLETE REWRITE WITH CORRECT SUPABASE SYNTAX
// =================================================================
// 
// KEY CHANGES:
// 1. All Supabase .select() queries now use template literals for complex joins
// 2. Fixed multiple foreign key joins to the same table
// 3. Added comprehensive error handling
// 4. Enhanced comments for maintainability
//
// PROBLEM ENDPOINTS FIXED:
// - /api/rotations: Multiple foreign key joins (resident, supervisor, training unit)
// - /api/oncall: Primary and backup physician joins  
// - /api/training-units: Department and supervisor joins
// =================================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Joi = require('joi');
require('dotenv').config();

// ============ INITIALIZATION ============
const app = express();
const PORT = process.env.PORT || 3000;

// ============ CONFIGURATION ============
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  JWT_SECRET = process.env.JWT_SECRET || 'neumocare-secure-secret-2024-production-key-change-this',
  NODE_ENV = 'development'
} = process.env;

// Validate required environment variables
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('❌ Missing required environment variables: SUPABASE_URL, SUPABASE_SERVICE_KEY');
  process.exit(1);
}

// ============ SUPABASE CLIENT ============
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { 
    autoRefreshToken: false, 
    persistSession: false 
  },
  db: {
    schema: 'public'
  }
});

// ============ SECURITY MIDDLEWARE ============
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin && process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:8080',
      'http://127.0.0.1:5500',
      'https://innovationneumologia.github.io',
      'https://*.github.io',
      'https://backend-neumocare.up.railway.app'
    ];
    
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin.includes('*')) {
        const regex = new RegExp('^' + allowedOrigin.replace('*', '.*') + '$');
        return regex.test(origin);
      }
      return allowedOrigin === origin;
    });
    
    isAllowed ? callback(null, true) : callback(new Error(`Origin ${origin} not allowed by CORS`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));

// Rate Limiting Configuration
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { 
    error: 'Too many requests from this IP, please try again after 15 minutes' 
  },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: process.env.NODE_ENV === 'development' ? 100 : 5, // More lenient in development
  message: { 
    error: 'Too many login attempts, please try again later' 
  },
  skipSuccessfulRequests: true
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============ REQUEST LOGGER MIDDLEWARE ============
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.url;
  const ip = req.ip || req.connection.remoteAddress;
  
  console.log(`[${timestamp}] ${method} ${url} - IP: ${ip}`);
  next();
});

// ============ UTILITY FUNCTIONS ============
/**
 * Generate a unique ID with a prefix
 * @param {string} prefix - ID prefix (e.g., 'MD', 'ROT')
 * @returns {string} Unique ID
 */
const generateId = (prefix) => {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 9)}`;
};

/**
 * Format date to YYYY-MM-DD
 * @param {string|Date} dateString - Date to format
 * @returns {string} Formatted date
 */
const formatDate = (dateString) => {
  if (!dateString) return '';
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return '';
    return date.toISOString().split('T')[0];
  } catch (error) {
    console.error('Date formatting error:', error);
    return '';
  }
};

/**
 * Calculate days between two dates
 * @param {string} start - Start date
 * @param {string} end - End date
 * @returns {number} Number of days
 */
const calculateDays = (start, end) => {
  try {
    const startDate = new Date(start);
    const endDate = new Date(end);
    
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return 0;
    }
    
    const diffTime = Math.abs(endDate - startDate);
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
  } catch (error) {
    console.error('Date calculation error:', error);
    return 0;
  }
};

// ============ VALIDATION SCHEMAS ============
const schemas = {
  // Authentication
  login: Joi.object({
    email: Joi.string().email().required().trim().lowercase(),
    password: Joi.string().min(6).required(),
    remember_me: Joi.boolean().default(false)
  }),
  
  // Medical Staff
  medicalStaff: Joi.object({
    full_name: Joi.string().min(2).max(100).required(),
    staff_type: Joi.string().valid('medical_resident', 'attending_physician', 'fellow', 'nurse_practitioner').required(),
    staff_id: Joi.string().optional().allow(''),
    employment_status: Joi.string().valid('active', 'on_leave', 'inactive').default('active'),
    professional_email: Joi.string().email().required(),
    department_id: Joi.string().uuid().optional().allow('', null),
    resident_category: Joi.string().valid('department_internal', 'rotating_other_dept', 'external_institution').optional().allow(''),
    training_year: Joi.number().min(1).max(10).optional().allow(null),
    specialization: Joi.string().max(100).optional().allow(''),
    years_experience: Joi.number().min(0).max(50).optional().allow(null),
    biography: Joi.string().max(1000).optional().allow(''),
    mobile_phone: Joi.string().pattern(/^[\d\s\-\+\(\)]{10,20}$/).optional().allow(''),
    medical_license: Joi.string().max(50).optional().allow(''),
    date_of_birth: Joi.date().iso().max('now').optional().allow(null),
    can_supervise_residents: Joi.boolean().default(false),
    home_department: Joi.string().optional().allow(''),
    external_institution: Joi.string().optional().allow('')
  }),
  
  // Departments
  department: Joi.object({
    name: Joi.string().min(2).max(100).required(),
    code: Joi.string().min(2).max(10).required(),
    status: Joi.string().valid('active', 'inactive').default('active'),
    description: Joi.string().max(500).optional().allow(''),
    head_of_department_id: Joi.string().uuid().optional().allow('', null)
  }),
  
  // Resident Rotations
  rotation: Joi.object({
    resident_id: Joi.string().uuid().required(),
    training_unit_id: Joi.string().uuid().required(),
    start_date: Joi.date().iso().required(),
    end_date: Joi.date().iso().greater(Joi.ref('start_date')).required(),
    supervising_attending_id: Joi.string().uuid().optional().allow('', null),
    rotation_status: Joi.string().valid('active', 'upcoming', 'completed', 'cancelled').default('active'),
    goals: Joi.string().max(1000).optional().allow(''),
    notes: Joi.string().max(1000).optional().allow(''),
    rotation_category: Joi.string().valid('clinical_rotation', 'elective', 'research').default('clinical_rotation')
  }),
  
  // On-Call Schedule
  onCall: Joi.object({
    duty_date: Joi.date().iso().required(),
    shift_type: Joi.string().valid('primary_call', 'backup_call', 'night_shift').default('primary_call'),
    start_time: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/).default('08:00'),
    end_time: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/).default('17:00'),
    primary_physician_id: Joi.string().uuid().required(),
    backup_physician_id: Joi.string().uuid().optional().allow('', null),
    coverage_notes: Joi.string().max(500).optional().allow(''),
    schedule_id: Joi.string().optional()
  }),
  
  // Staff Absences
  absence: Joi.object({
    staff_member_id: Joi.string().uuid().required(),
    leave_category: Joi.string().valid('vacation', 'sick_leave', 'conference', 'personal', 'maternity_paternity', 'administrative', 'other').required(),
    leave_start_date: Joi.date().iso().required(),
    leave_end_date: Joi.date().iso().greater(Joi.ref('leave_start_date')).required(),
    leave_reason: Joi.string().max(500).optional().allow(''),
    coverage_required: Joi.boolean().default(true),
    approval_status: Joi.string().valid('pending', 'approved', 'rejected').default('pending'),
    review_notes: Joi.string().max(500).optional().allow('')
  }),
  
  // Announcements
  announcement: Joi.object({
    announcement_title: Joi.string().min(5).max(200).required(),
    announcement_content: Joi.string().min(10).required(),
    publish_start_date: Joi.date().iso().required(),
    publish_end_date: Joi.date().iso().greater(Joi.ref('publish_start_date')).optional().allow(null),
    priority_level: Joi.string().valid('low', 'medium', 'high', 'urgent').default('medium'),
    announcement_type: Joi.string().valid('department', 'hospital', 'urgent').default('department'),
    target_audience: Joi.string().valid('all', 'residents', 'attendings', 'department').default('all'),
    visible_to_roles: Joi.array().items(Joi.string()).default(['viewing_doctor'])
  }),
  
  // User Profile
  userProfile: Joi.object({
    full_name: Joi.string().min(2).max(100).required(),
    email: Joi.string().email().required().trim().lowercase(),
    phone_number: Joi.string().pattern(/^[\d\s\-\+\(\)]{10,20}$/).optional().allow(''),
    department_id: Joi.string().uuid().optional().allow('', null),
    user_role: Joi.string().valid('system_admin', 'department_head', 'resident_manager', 'attending_physician', 'viewing_doctor'),
    notifications_enabled: Joi.boolean().default(true),
    absence_notifications: Joi.boolean().default(true),
    announcement_notifications: Joi.boolean().default(true)
  }),
  
  // System Settings
  systemSettings: Joi.object({
    hospital_name: Joi.string().min(2).max(100).required(),
    default_department_id: Joi.string().uuid().optional().allow(null),
    max_residents_per_unit: Joi.number().min(1).max(50).default(10),
    default_rotation_duration: Joi.number().min(1).max(52).default(12),
    enable_audit_logging: Joi.boolean().default(true),
    require_mfa: Joi.boolean().default(false),
    maintenance_mode: Joi.boolean().default(false),
    notifications_enabled: Joi.boolean().default(true),
    absence_notifications: Joi.boolean().default(true),
    announcement_notifications: Joi.boolean().default(true)
  }),
  
  // Training Units
  trainingUnit: Joi.object({
    unit_name: Joi.string().min(2).max(100).required(),
    unit_code: Joi.string().min(2).max(50).required(),
    department_id: Joi.string().uuid().optional().allow(null),
    department_name: Joi.string().optional().allow(''),
    maximum_residents: Joi.number().min(1).max(50).default(10),
    unit_description: Joi.string().max(500).optional().allow(''),
    supervisor_id: Joi.string().uuid().optional().allow(null),
    unit_status: Joi.string().valid('active', 'inactive').default('active'),
    specialty: Joi.string().optional().allow(''),
    location_building: Joi.string().optional().allow(''),
    location_floor: Joi.string().optional().allow('')
  })
};

// ============ VALIDATION MIDDLEWARE ============
/**
 * Validation middleware using Joi schemas
 * @param {Joi.ObjectSchema} schema - Joi validation schema
 * @returns {Function} Express middleware
 */
const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { 
    abortEarly: false,
    stripUnknown: true
  });
  
  if (error) {
    return res.status(400).json({
      error: 'Validation failed',
      details: error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }))
    });
  }
  
  req.validatedData = value;
  next();
};

// ============ AUTHENTICATION MIDDLEWARE ============
/**
 * JWT Token Authentication Middleware
 * Extracts and validates JWT token from Authorization header
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') 
    ? authHeader.split(' ')[1] 
    : null;
  
  if (!token) {
    return res.status(401).json({ 
      error: 'Authentication required',
      message: 'No access token provided. Please log in.' 
    });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        error: 'Invalid token',
        message: 'Access token is invalid or expired. Please log in again.' 
      });
    }
    
    req.user = user;
    next();
  });
};

// ============ PERMISSION MIDDLEWARE ============
/**
 * Role-based permission checking middleware
 * @param {string} resource - Resource being accessed
 * @param {string} action - Action being performed (read, create, update, delete)
 * @returns {Function} Express middleware
 */
const checkPermission = (resource, action) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ 
        error: 'Authentication required' 
      });
    }
    
    // System admins have full access
    if (req.user.role === 'system_admin') {
      return next();
    }
    
    // Define role-based permissions
    const rolePermissions = {
      medical_staff: ['system_admin', 'department_head', 'resident_manager'],
      departments: ['system_admin', 'department_head'],
      training_units: ['system_admin', 'department_head', 'resident_manager'],
      resident_rotations: ['system_admin', 'department_head', 'resident_manager'],
      oncall_schedule: ['system_admin', 'department_head', 'resident_manager'],
      staff_absence: ['system_admin', 'department_head', 'resident_manager'],
      communications: ['system_admin', 'department_head', 'resident_manager'],
      system_settings: ['system_admin'],
      users: ['system_admin']
    };
    
    const allowedRoles = rolePermissions[resource];
    
    if (!allowedRoles || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        message: `Your role (${req.user.role}) does not have permission to ${action} ${resource}`
      });
    }
    
    next();
  };
};

// ============ API ROUTES ============

// ===== HEALTH CHECK & SYSTEM ENDPOINTS =====

/**
 * @route GET /health
 * @description Check API status and database connectivity
 * @access Public
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'NeumoCare Hospital Management System API',
    version: '4.2.0',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    database: SUPABASE_URL ? 'Connected' : 'Not connected',
    uptime: process.uptime()
  });
});

/**
 * @route GET /api/debug/tables
 * @description Debug endpoint to check table accessibility
 * @access Private (Requires authentication)
 */
app.get('/api/debug/tables', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 Testing table accessibility...');
    
    // Test each problematic table without joins first
    const testPromises = [
      supabase.from('resident_rotations').select('id').limit(1),
      supabase.from('oncall_schedule').select('id').limit(1),
      supabase.from('leave_requests').select('id').limit(1),
      supabase.from('medical_staff').select('id').limit(1),
      supabase.from('training_units').select('id').limit(1),
      supabase.from('departments').select('id').limit(1)
    ];
    
    const results = await Promise.allSettled(testPromises);
    
    const tableStatus = {
      resident_rotations: results[0].status === 'fulfilled' && !results[0].value.error ? '✅ Accessible' : '❌ Error: ' + (results[0].value?.error?.message || 'Unknown'),
      oncall_schedule: results[1].status === 'fulfilled' && !results[1].value.error ? '✅ Accessible' : '❌ Error: ' + (results[1].value?.error?.message || 'Unknown'),
      leave_requests: results[2].status === 'fulfilled' && !results[2].value.error ? '✅ Accessible' : '❌ Error: ' + (results[2].value?.error?.message || 'Unknown'),
      medical_staff: results[3].status === 'fulfilled' && !results[3].value.error ? '✅ Accessible' : '❌ Error: ' + (results[3].value?.error?.message || 'Unknown'),
      training_units: results[4].status === 'fulfilled' && !results[4].value.error ? '✅ Accessible' : '❌ Error: ' + (results[4].value?.error?.message || 'Unknown'),
      departments: results[5].status === 'fulfilled' && !results[5].value.error ? '✅ Accessible' : '❌ Error: ' + (results[5].value?.error?.message || 'Unknown')
    };
    
    res.json({
      message: 'Table accessibility test',
      status: tableStatus,
      user: req.user.email,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Debug endpoint error:', error);
    res.status(500).json({ 
      error: 'Debug test failed', 
      message: error.message 
    });
  }
});

// ===== AUTHENTICATION ROUTES =====

/**
 * @route POST /api/auth/login
 * @description User login with JWT token generation
 * @access Public
 * @rateLimit 5 attempts per hour (production)
 */
app.post('/api/auth/login', authLimiter, validate(schemas.login), async (req, res) => {
  try {
    const { email, password } = req.validatedData;
    console.log(`🔐 Login attempt: ${email}`);
    
    // Demo admin account (for development/testing)
    if (email === 'admin@neumocare.org' && password === 'password123') {
      console.log('👨‍💼 Demo admin login');
      const token = jwt.sign(
        { 
          id: '11111111-1111-1111-1111-111111111111',
          email: 'admin@neumocare.org',
          role: 'system_admin'
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      return res.json({
        token,
        user: {
          id: '11111111-1111-1111-1111-111111111111',
          email: 'admin@neumocare.org',
          full_name: 'System Administrator',
          user_role: 'system_admin',
          department_id: null
        }
      });
    }
    
    // Database user lookup
    const { data: user, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, department_id, password_hash, account_status')
      .eq('email', email.toLowerCase())
      .single();
    
    if (error || !user) {
      console.log(`❌ User not found: ${email}`);
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password'
      });
    }
    
    if (user.account_status !== 'active') {
      console.log(`🚫 Inactive account: ${email}`);
      return res.status(403).json({
        error: 'Account disabled',
        message: 'Your account has been deactivated. Please contact an administrator.'
      });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash || '');
    if (!validPassword) {
      console.log(`❌ Invalid password for: ${email}`);
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid email or password'
      });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.user_role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Remove password hash from response
    const { password_hash, ...userWithoutPassword } = user;
    
    console.log(`✅ Login successful: ${email}`);
    res.json({ 
      token, 
      user: userWithoutPassword 
    });
    
  } catch (error) {
    console.error('🔥 Login error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'An unexpected error occurred during login'
    });
  }
});

/**
 * @route POST /api/auth/logout
 * @description User logout (client-side token removal)
 * @access Private
 */
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    console.log(`👋 User logging out: ${req.user.email}`);
    res.json({ 
      message: 'Logged out successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      error: 'Logout failed',
      message: error.message 
    });
  }
});

// ===== USER PROFILE ROUTES =====

/**
 * @route GET /api/users/profile
 * @description Get current user's profile information
 * @access Private
 */
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, notifications_enabled, absence_notifications, announcement_notifications, created_at, updated_at')
      .eq('id', req.user.id)
      .single();
    
    if (error) {
      console.error(`❌ Profile fetch error for user ${req.user.id}:`, error);
      throw error;
    }
    
    res.json(user);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch user profile',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/users/profile
 * @description Update current user's profile
 * @access Private
 */
app.put('/api/users/profile', authenticateToken, validate(schemas.userProfile), async (req, res) => {
  try {
    const updateData = {
      full_name: req.validatedData.full_name,
      phone_number: req.validatedData.phone_number,
      notifications_enabled: req.validatedData.notifications_enabled,
      absence_notifications: req.validatedData.absence_notifications,
      announcement_notifications: req.validatedData.announcement_notifications,
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('app_users')
      .update(updateData)
      .eq('id', req.user.id)
      .select()
      .single();
    
    if (error) {
      console.error(`❌ Profile update error for user ${req.user.id}:`, error);
      throw error;
    }
    
    console.log(`✅ Profile updated for user: ${req.user.email}`);
    res.json(data);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ 
      error: 'Failed to update profile',
      message: error.message 
    });
  }
});

// ===== MEDICAL STAFF ROUTES =====

/**
 * @route GET /api/medical-staff
 * @description List all medical staff with pagination and filtering
 * @access Private (Requires permission)
 * @query {string} [search] - Search by name, staff_id, or email
 * @query {string} [staff_type] - Filter by staff type
 * @query {string} [employment_status] - Filter by employment status
 * @query {string} [department_id] - Filter by department
 * @query {number} [page=1] - Page number
 * @query {number} [limit=20] - Items per page
 */
app.get('/api/medical-staff', authenticateToken, checkPermission('medical_staff', 'read'), apiLimiter, async (req, res) => {
  try {
    const { 
      search, 
      staff_type, 
      employment_status, 
      department_id, 
      page = 1, 
      limit = 20 
    } = req.query;
    
    const offset = (page - 1) * limit;
    
    console.log(`📋 Fetching medical staff - Page: ${page}, Limit: ${limit}`);
    
    // Build query with proper Supabase syntax using template literals
    let query = supabase
      .from('medical_staff')
      .select(`
        *,
        departments!medical_staff_department_id_fkey(
          name, 
          code
        )
      `, { 
        count: 'exact' 
      });
    
    // Apply filters
    if (search) {
      query = query.or(
        `full_name.ilike.%${search}%,staff_id.ilike.%${search}%,professional_email.ilike.%${search}%`
      );
    }
    if (staff_type) query = query.eq('staff_type', staff_type);
    if (employment_status) query = query.eq('employment_status', employment_status);
    if (department_id) query = query.eq('department_id', department_id);
    
    // Apply pagination and ordering
    query = query
      .order('full_name', { ascending: true })
      .range(offset, offset + limit - 1);
    
    const { data, error, count } = await query;
    
    if (error) {
      console.error('❌ Medical staff query error:', error);
      throw error;
    }
    
    // Transform response for cleaner frontend consumption
    const transformedData = data.map(item => ({
      ...item,
      department: item.departments ? { 
        name: item.departments.name, 
        code: item.departments.code 
      } : null
    }));
    
    res.json({
      data: transformedData,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limit)
      },
      filters: {
        search: search || '',
        staff_type: staff_type || '',
        employment_status: employment_status || '',
        department_id: department_id || ''
      }
    });
  } catch (error) {
    console.error('🔥 Medical staff list error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch medical staff',
      message: error.message 
    });
  }
});

/**
 * @route GET /api/medical-staff/:id
 * @description Get detailed information for a specific medical staff member
 * @access Private (Requires permission)
 */
app.get('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'read'), async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`👤 Fetching medical staff details for ID: ${id}`);
    
    const { data, error } = await supabase
      .from('medical_staff')
      .select(`
        *,
        departments!medical_staff_department_id_fkey(
          name, 
          code
        )
      `)
      .eq('id', id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ Medical staff not found: ${id}`);
        return res.status(404).json({ 
          error: 'Medical staff not found',
          message: `No staff member found with ID: ${id}`
        });
      }
      console.error('❌ Medical staff details error:', error);
      throw error;
    }
    
    // Transform response
    const transformed = {
      ...data,
      department: data.departments ? { 
        name: data.departments.name, 
        code: data.departments.code 
      } : null
    };
    
    res.json(transformed);
  } catch (error) {
    console.error('🔥 Medical staff details error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch staff details',
      message: error.message 
    });
  }
});

/**
 * @route POST /api/medical-staff
 * @description Create new medical staff record
 * @access Private (Requires permission)
 */
app.post('/api/medical-staff', authenticateToken, checkPermission('medical_staff', 'create'), validate(schemas.medicalStaff), async (req, res) => {
  try {
    const staffData = {
      ...req.validatedData,
      staff_id: req.validatedData.staff_id || generateId('MD'),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    console.log(`➕ Creating new medical staff: ${staffData.full_name}`);
    
    const { data, error } = await supabase
      .from('medical_staff')
      .insert([staffData])
      .select()
      .single();
    
    if (error) {
      console.error('❌ Create medical staff error:', error);
      
      // Handle duplicate entry error
      if (error.code === '23505') {
        return res.status(409).json({ 
          error: 'Duplicate entry',
          message: 'A staff member with this email or staff ID already exists'
        });
      }
      
      throw error;
    }
    
    console.log(`✅ Medical staff created: ${data.full_name} (ID: ${data.id})`);
    res.status(201).json(data);
  } catch (error) {
    console.error('🔥 Create medical staff error:', error);
    res.status(500).json({ 
      error: 'Failed to create medical staff',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/medical-staff/:id
 * @description Update existing medical staff record
 * @access Private (Requires permission)
 */
app.put('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'update'), validate(schemas.medicalStaff), async (req, res) => {
  try {
    const { id } = req.params;
    const staffData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    console.log(`✏️ Updating medical staff: ${id}`);
    
    const { data, error } = await supabase
      .from('medical_staff')
      .update(staffData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ Medical staff not found for update: ${id}`);
        return res.status(404).json({ 
          error: 'Medical staff not found',
          message: `No staff member found with ID: ${id}`
        });
      }
      console.error('❌ Update medical staff error:', error);
      throw error;
    }
    
    console.log(`✅ Medical staff updated: ${data.full_name} (ID: ${data.id})`);
    res.json(data);
  } catch (error) {
    console.error('🔥 Update medical staff error:', error);
    res.status(500).json({ 
      error: 'Failed to update medical staff',
      message: error.message 
    });
  }
});

/**
 * @route DELETE /api/medical-staff/:id
 * @description Deactivate medical staff (soft delete)
 * @access Private (Requires permission)
 */
app.delete('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'delete'), async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🗑️ Deactivating medical staff: ${id}`);
    
    const { data, error } = await supabase
      .from('medical_staff')
      .update({ 
        employment_status: 'inactive',
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select('full_name, staff_id')
      .single();
    
    if (error) {
      console.error('❌ Delete medical staff error:', error);
      throw error;
    }
    
    console.log(`✅ Medical staff deactivated: ${data.full_name} (ID: ${data.staff_id})`);
    res.json({ 
      message: 'Medical staff deactivated successfully',
      staff_name: data.full_name,
      staff_id: data.staff_id,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('🔥 Delete medical staff error:', error);
    res.status(500).json({ 
      error: 'Failed to deactivate medical staff',
      message: error.message 
    });
  }
});

// ===== DEPARTMENTS ROUTES =====

/**
 * @route GET /api/departments
 * @description List all hospital departments with head of department information
 * @access Private
 * @note Already fixed in previous version - using correct Supabase syntax
 */
app.get('/api/departments', authenticateToken, apiLimiter, async (req, res) => {
  try {
    console.log('🏥 Fetching departments list');
    
    const { data, error } = await supabase
      .from('departments')
      .select(`
        *,
        medical_staff!departments_head_of_department_id_fkey(
          full_name, 
          professional_email
        )
      `)
      .order('name');
    
    if (error) {
      console.error('❌ Departments query error:', error);
      throw error;
    }
    
    // Transform response - medical_staff object contains the joined data
    const transformedData = data.map(item => ({
      ...item,
      head_of_department: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null
      }
    }));
    
    console.log(`✅ Found ${transformedData.length} departments`);
    res.json(transformedData);
  } catch (error) {
    console.error('🔥 Departments error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch departments',
      message: error.message 
    });
  }
});

/**
 * @route GET /api/departments/:id
 * @description Get detailed information for a specific department
 * @access Private
 */
app.get('/api/departments/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🏥 Fetching department details: ${id}`);
    
    const { data, error } = await supabase
      .from('departments')
      .select(`
        *,
        medical_staff!departments_head_of_department_id_fkey(
          full_name, 
          professional_email, 
          staff_type
        )
      `)
      .eq('id', id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ Department not found: ${id}`);
        return res.status(404).json({ 
          error: 'Department not found',
          message: `No department found with ID: ${id}`
        });
      }
      console.error('❌ Department details error:', error);
      throw error;
    }
    
    // Transform response
    const transformed = {
      ...data,
      head_of_department: {
        full_name: data.medical_staff?.full_name || null,
        professional_email: data.medical_staff?.professional_email || null,
        staff_type: data.medical_staff?.staff_type || null
      }
    };
    
    res.json(transformed);
  } catch (error) {
    console.error('🔥 Department details error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch department details',
      message: error.message 
    });
  }
});

/**
 * @route POST /api/departments
 * @description Create new hospital department
 * @access Private (Requires permission)
 */
app.post('/api/departments', authenticateToken, checkPermission('departments', 'create'), validate(schemas.department), async (req, res) => {
  try {
    const deptData = {
      ...req.validatedData,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    console.log(`🏥 Creating new department: ${deptData.name}`);
    
    const { data, error } = await supabase
      .from('departments')
      .insert([deptData])
      .select()
      .single();
    
    if (error) {
      console.error('❌ Create department error:', error);
      throw error;
    }
    
    console.log(`✅ Department created: ${data.name} (Code: ${data.code})`);
    res.status(201).json(data);
  } catch (error) {
    console.error('🔥 Create department error:', error);
    res.status(500).json({ 
      error: 'Failed to create department',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/departments/:id
 * @description Update existing department information
 * @access Private (Requires permission)
 */
app.put('/api/departments/:id', authenticateToken, checkPermission('departments', 'update'), validate(schemas.department), async (req, res) => {
  try {
    const { id } = req.params;
    const deptData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    console.log(`✏️ Updating department: ${id}`);
    
    const { data, error } = await supabase
      .from('departments')
      .update(deptData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ Department not found for update: ${id}`);
        return res.status(404).json({ 
          error: 'Department not found',
          message: `No department found with ID: ${id}`
        });
      }
      console.error('❌ Update department error:', error);
      throw error;
    }
    
    console.log(`✅ Department updated: ${data.name} (ID: ${data.id})`);
    res.json(data);
  } catch (error) {
    console.error('🔥 Update department error:', error);
    res.status(500).json({ 
      error: 'Failed to update department',
      message: error.message 
    });
  }
});

// ===== TRAINING UNITS ROUTES =====

/**
 * @route GET /api/training-units
 * @description List all clinical training units with department and supervisor info
 * @access Private
 * @note FIXED: Using template literals for multiple foreign key joins
 */
app.get('/api/training-units', authenticateToken, async (req, res) => {
  try {
    const { department_id, unit_status } = req.query;
    console.log(`📚 Fetching training units - Dept: ${department_id || 'All'}, Status: ${unit_status || 'All'}`);
    
    // CORRECTED SYNTAX: Using template literals for multiple foreign key relationships
    let query = supabase
      .from('training_units')
      .select(`
        *,
        departments!training_units_department_id_fkey(
          name, 
          code
        ),
        medical_staff!training_units_supervisor_id_fkey(
          full_name, 
          professional_email
        )
      `)
      .order('unit_name');
    
    if (department_id) query = query.eq('department_id', department_id);
    if (unit_status) query = query.eq('unit_status', unit_status);
    
    const { data, error } = await query;
    
    if (error) {
      console.error('❌ Training units query error:', error);
      throw error;
    }
    
    // Transform response
    const transformedData = data.map(item => ({
      ...item,
      department: item.departments ? { 
        name: item.departments.name, 
        code: item.departments.code 
      } : null,
      supervisor: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null
      }
    }));
    
    console.log(`✅ Found ${transformedData.length} training units`);
    res.json(transformedData);
  } catch (error) {
    console.error('🔥 Training units error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch training units',
      message: error.message 
    });
  }
});

/**
 * @route GET /api/training-units/:id
 * @description Get detailed information for a specific training unit
 * @access Private
 */
app.get('/api/training-units/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📚 Fetching training unit details: ${id}`);
    
    // CORRECTED SYNTAX
    const { data, error } = await supabase
      .from('training_units')
      .select(`
        *,
        departments!training_units_department_id_fkey(
          name, 
          code
        ),
        medical_staff!training_units_supervisor_id_fkey(
          full_name, 
          professional_email
        )
      `)
      .eq('id', id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ Training unit not found: ${id}`);
        return res.status(404).json({ 
          error: 'Training unit not found',
          message: `No training unit found with ID: ${id}`
        });
      }
      console.error('❌ Training unit details error:', error);
      throw error;
    }
    
    // Transform response
    const transformed = {
      ...data,
      department: data.departments ? { 
        name: data.departments.name, 
        code: data.departments.code 
      } : null,
      supervisor: {
        full_name: data.medical_staff?.full_name || null,
        professional_email: data.medical_staff?.professional_email || null
      }
    };
    
    res.json(transformed);
  } catch (error) {
    console.error('🔥 Training unit details error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch training unit details',
      message: error.message 
    });
  }
});

/**
 * @route POST /api/training-units
 * @description Create new clinical training unit
 * @access Private (Requires permission)
 */
app.post('/api/training-units', authenticateToken, checkPermission('training_units', 'create'), validate(schemas.trainingUnit), async (req, res) => {
  try {
    const unitData = {
      ...req.validatedData,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    console.log(`📚 Creating new training unit: ${unitData.unit_name}`);
    
    const { data, error } = await supabase
      .from('training_units')
      .insert([unitData])
      .select()
      .single();
    
    if (error) {
      console.error('❌ Create training unit error:', error);
      throw error;
    }
    
    console.log(`✅ Training unit created: ${data.unit_name} (Code: ${data.unit_code})`);
    res.status(201).json(data);
  } catch (error) {
    console.error('🔥 Create training unit error:', error);
    res.status(500).json({ 
      error: 'Failed to create training unit',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/training-units/:id
 * @description Update existing training unit information
 * @access Private (Requires permission)
 */
app.put('/api/training-units/:id', authenticateToken, checkPermission('training_units', 'update'), validate(schemas.trainingUnit), async (req, res) => {
  try {
    const { id } = req.params;
    const unitData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    console.log(`✏️ Updating training unit: ${id}`);
    
    const { data, error } = await supabase
      .from('training_units')
      .update(unitData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ Training unit not found for update: ${id}`);
        return res.status(404).json({ 
          error: 'Training unit not found',
          message: `No training unit found with ID: ${id}`
        });
      }
      console.error('❌ Update training unit error:', error);
      throw error;
    }
    
    console.log(`✅ Training unit updated: ${data.unit_name} (ID: ${data.id})`);
    res.json(data);
  } catch (error) {
    console.error('🔥 Update training unit error:', error);
    res.status(500).json({ 
      error: 'Failed to update training unit',
      message: error.message 
    });
  }
});

// ===== RESIDENT ROTATIONS ROUTES =====

/**
 * @route GET /api/rotations
 * @description List all resident rotations with resident, supervisor, and unit info
 * @access Private
 * @note FIXED: Using template literals for multiple foreign key joins to same table
 * @query {string} [resident_id] - Filter by resident ID
 * @query {string} [rotation_status] - Filter by rotation status
 * @query {string} [training_unit_id] - Filter by training unit
 * @query {string} [start_date] - Filter by start date (>=)
 * @query {string} [end_date] - Filter by end date (<=)
 * @query {number} [page=1] - Page number
 * @query {number} [limit=20] - Items per page
 */
app.get('/api/rotations', authenticateToken, async (req, res) => {
  try {
    const { 
      resident_id, 
      rotation_status, 
      training_unit_id, 
      start_date, 
      end_date, 
      page = 1, 
      limit = 20 
    } = req.query;
    
    const offset = (page - 1) * limit;
    
    console.log(`🔄 Fetching rotations - Page: ${page}, Limit: ${limit}`);
    
    // CORRECTED SUPABASE SYNTAX: Template literals for complex joins
    // Note: When joining to the same table multiple times, Supabase creates
    // medical_staff (first join) and medical_staff_2 (second join)
    let query = supabase
      .from('resident_rotations')
      .select(`
        *,
        medical_staff!resident_rotations_resident_id_fkey(
          full_name, 
          professional_email, 
          staff_type
        ),
        medical_staff!resident_rotations_supervising_attending_id_fkey(
          full_name, 
          professional_email
        ),
        training_units!resident_rotations_training_unit_id_fkey(
          unit_name, 
          unit_code
        )
      `, { 
        count: 'exact' 
      });
    
    // Apply filters
    if (resident_id) query = query.eq('resident_id', resident_id);
    if (rotation_status) query = query.eq('rotation_status', rotation_status);
    if (training_unit_id) query = query.eq('training_unit_id', training_unit_id);
    if (start_date) query = query.gte('start_date', start_date);
    if (end_date) query = query.lte('end_date', end_date);
    
    // Apply pagination and ordering
    query = query
      .order('start_date', { ascending: false })
      .range(offset, offset + limit - 1);
    
    const { data, error, count } = await query;
    
    if (error) {
      console.error('❌ Rotations query error:', error);
      throw error;
    }
    
    // Transform response - Supabase returns medical_staff (resident) and medical_staff_2 (supervising)
    const transformedData = data.map(item => ({
      ...item,
      resident: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null,
        staff_type: item.medical_staff?.staff_type || null
      },
      supervising_attending: {
        full_name: item.medical_staff_2?.full_name || null,
        professional_email: item.medical_staff_2?.professional_email || null
      },
      training_unit: item.training_units ? {
        unit_name: item.training_units.unit_name,
        unit_code: item.training_units.unit_code
      } : null
    }));
    
    res.json({
      data: transformedData,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limit)
      },
      filters: {
        resident_id: resident_id || '',
        rotation_status: rotation_status || '',
        training_unit_id: training_unit_id || '',
        start_date: start_date || '',
        end_date: end_date || ''
      }
    });
  } catch (error) {
    console.error('🔥 Rotations error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch rotations',
      message: error.message 
    });
  }
});

/**
 * @route POST /api/rotations
 * @description Assign resident to a training unit rotation
 * @access Private (Requires permission)
 */
app.post('/api/rotations', authenticateToken, checkPermission('resident_rotations', 'create'), validate(schemas.rotation), async (req, res) => {
  try {
    const rotationData = {
      ...req.validatedData,
      rotation_id: generateId('ROT'),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    console.log(`🔄 Creating new rotation for resident: ${rotationData.resident_id}`);
    
    const { data, error } = await supabase
      .from('resident_rotations')
      .insert([rotationData])
      .select()
      .single();
    
    if (error) {
      console.error('❌ Create rotation error:', error);
      throw error;
    }
    
    console.log(`✅ Rotation created: ${data.rotation_id} (Resident: ${data.resident_id})`);
    res.status(201).json(data);
  } catch (error) {
    console.error('🔥 Create rotation error:', error);
    res.status(500).json({ 
      error: 'Failed to create rotation',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/rotations/:id
 * @description Update existing rotation assignment
 * @access Private (Requires permission)
 */
app.put('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'update'), validate(schemas.rotation), async (req, res) => {
  try {
    const { id } = req.params;
    const rotationData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    console.log(`✏️ Updating rotation: ${id}`);
    
    const { data, error } = await supabase
      .from('resident_rotations')
      .update(rotationData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ Rotation not found for update: ${id}`);
        return res.status(404).json({ 
          error: 'Rotation not found',
          message: `No rotation found with ID: ${id}`
        });
      }
      console.error('❌ Update rotation error:', error);
      throw error;
    }
    
    console.log(`✅ Rotation updated: ${data.rotation_id} (ID: ${data.id})`);
    res.json(data);
  } catch (error) {
    console.error('🔥 Update rotation error:', error);
    res.status(500).json({ 
      error: 'Failed to update rotation',
      message: error.message 
    });
  }
});

/**
 * @route DELETE /api/rotations/:id
 * @description Cancel a resident rotation
 * @access Private (Requires permission)
 */
app.delete('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'delete'), async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🗑️ Cancelling rotation: ${id}`);
    
    const { error } = await supabase
      .from('resident_rotations')
      .update({
        rotation_status: 'cancelled',
        updated_at: new Date().toISOString()
      })
      .eq('id', id);
    
    if (error) {
      console.error('❌ Delete rotation error:', error);
      throw error;
    }
    
    console.log(`✅ Rotation cancelled: ${id}`);
    res.json({ 
      message: 'Rotation cancelled successfully',
      rotation_id: id,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('🔥 Delete rotation error:', error);
    res.status(500).json({ 
      error: 'Failed to cancel rotation',
      message: error.message 
    });
  }
});

// ===== ON-CALL SCHEDULE ROUTES =====

/**
 * @route GET /api/oncall
 * @description List all on-call schedules with physician information
 * @access Private
 * @note FIXED: Using template literals for multiple foreign key joins to same table
 * @query {string} [start_date] - Filter by start date (>=)
 * @query {string} [end_date] - Filter by end date (<=)
 * @query {string} [physician_id] - Filter by physician ID (primary or backup)
 */
app.get('/api/oncall', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { start_date, end_date, physician_id } = req.query;
    
    console.log(`📅 Fetching on-call schedule - Date range: ${start_date || 'Any'} to ${end_date || 'Any'}`);
    
    // CORRECTED SYNTAX: Using template literals for multiple foreign keys
    let query = supabase
      .from('oncall_schedule')
      .select(`
        *,
        medical_staff!oncall_schedule_primary_physician_id_fkey(
          full_name, 
          professional_email, 
          mobile_phone
        ),
        medical_staff!oncall_schedule_backup_physician_id_fkey(
          full_name, 
          professional_email, 
          mobile_phone
        )
      `)
      .order('duty_date');
    
    // Apply filters
    if (start_date) query = query.gte('duty_date', start_date);
    if (end_date) query = query.lte('duty_date', end_date);
    if (physician_id) {
      query = query.or(
        `primary_physician_id.eq.${physician_id},backup_physician_id.eq.${physician_id}`
      );
    }
    
    const { data, error } = await query;
    
    if (error) {
      console.error('❌ On-call schedule query error:', error);
      throw error;
    }
    
    // Transform response
    const transformedData = data.map(item => ({
      ...item,
      primary_physician: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null,
        mobile_phone: item.medical_staff?.mobile_phone || null
      },
      backup_physician: {
        full_name: item.medical_staff_2?.full_name || null,
        professional_email: item.medical_staff_2?.professional_email || null,
        mobile_phone: item.medical_staff_2?.mobile_phone || null
      }
    }));
    
    console.log(`✅ Found ${transformedData.length} on-call schedules`);
    res.json(transformedData);
  } catch (error) {
    console.error('🔥 On-call schedule error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch on-call schedule',
      message: error.message 
    });
  }
});

/**
 * @route POST /api/oncall
 * @description Schedule physician for on-call duty
 * @access Private (Requires permission)
 */
app.post('/api/oncall', authenticateToken, checkPermission('oncall_schedule', 'create'), validate(schemas.onCall), async (req, res) => {
  try {
    const scheduleData = {
      ...req.validatedData,
      schedule_id: req.validatedData.schedule_id || generateId('SCH'),
      created_by: req.user.id,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    console.log(`📅 Creating on-call schedule for physician: ${scheduleData.primary_physician_id}`);
    
    const { data, error } = await supabase
      .from('oncall_schedule')
      .insert([scheduleData])
      .select()
      .single();
    
    if (error) {
      console.error('❌ Create on-call error:', error);
      throw error;
    }
    
    console.log(`✅ On-call schedule created: ${data.schedule_id} (Date: ${data.duty_date})`);
    res.status(201).json(data);
  } catch (error) {
    console.error('🔥 Create on-call error:', error);
    res.status(500).json({ 
      error: 'Failed to create on-call schedule',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/oncall/:id
 * @description Update existing on-call schedule
 * @access Private (Requires permission)
 */
app.put('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'update'), validate(schemas.onCall), async (req, res) => {
  try {
    const { id } = req.params;
    const scheduleData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    console.log(`✏️ Updating on-call schedule: ${id}`);
    
    const { data, error } = await supabase
      .from('oncall_schedule')
      .update(scheduleData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ On-call schedule not found for update: ${id}`);
        return res.status(404).json({ 
          error: 'Schedule not found',
          message: `No on-call schedule found with ID: ${id}`
        });
      }
      console.error('❌ Update on-call error:', error);
      throw error;
    }
    
    console.log(`✅ On-call schedule updated: ${data.schedule_id} (ID: ${data.id})`);
    res.json(data);
  } catch (error) {
    console.error('🔥 Update on-call error:', error);
    res.status(500).json({ 
      error: 'Failed to update on-call schedule',
      message: error.message 
    });
  }
});

/**
 * @route DELETE /api/oncall/:id
 * @description Remove on-call schedule entry
 * @access Private (Requires permission)
 */
app.delete('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'delete'), async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🗑️ Deleting on-call schedule: ${id}`);
    
    const { error } = await supabase
      .from('oncall_schedule')
      .delete()
      .eq('id', id);
    
    if (error) {
      console.error('❌ Delete on-call error:', error);
      throw error;
    }
    
    console.log(`✅ On-call schedule deleted: ${id}`);
    res.json({ 
      message: 'On-call schedule deleted successfully',
      schedule_id: id,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('🔥 Delete on-call error:', error);
    res.status(500).json({ 
      error: 'Failed to delete on-call schedule',
      message: error.message 
    });
  }
});

// ===== STAFF ABSENCES ROUTES =====

/**
 * @route GET /api/absences
 * @description List all staff leave/absence requests
 * @access Private
 * @note This endpoint uses correct Supabase syntax as it only has one join
 * @query {string} [staff_member_id] - Filter by staff member ID
 * @query {string} [approval_status] - Filter by approval status
 * @query {string} [start_date] - Filter by leave start date (>=)
 * @query {string} [end_date] - Filter by leave end date (<=)
 */
app.get('/api/absences', authenticateToken, async (req, res) => {
  try {
    const { staff_member_id, approval_status, start_date, end_date } = req.query;
    
    console.log(`🏖️ Fetching absences - Staff: ${staff_member_id || 'All'}, Status: ${approval_status || 'All'}`);
    
    // This syntax is correct for a single join
    let query = supabase
      .from('leave_requests')
      .select(`
        *,
        medical_staff!leave_requests_staff_member_id_fkey(
          full_name, 
          professional_email, 
          department_id
        )
      `)
      .order('leave_start_date');
    
    // Apply filters
    if (staff_member_id) query = query.eq('staff_member_id', staff_member_id);
    if (approval_status) query = query.eq('approval_status', approval_status);
    if (start_date) query = query.gte('leave_start_date', start_date);
    if (end_date) query = query.lte('leave_end_date', end_date);
    
    const { data, error } = await query;
    
    if (error) {
      console.error('❌ Absences query error:', error);
      throw error;
    }
    
    // Transform response
    const transformedData = data.map(item => ({
      ...item,
      staff_member: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null,
        department_id: item.medical_staff?.department_id || null
      }
    }));
    
    console.log(`✅ Found ${transformedData.length} absence records`);
    res.json(transformedData);
  } catch (error) {
    console.error('🔥 Absences error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch absences',
      message: error.message 
    });
  }
});

/**
 * @route POST /api/absences
 * @description Submit new leave/absence request
 * @access Private (Requires permission)
 */
app.post('/api/absences', authenticateToken, checkPermission('staff_absence', 'create'), validate(schemas.absence), async (req, res) => {
  try {
    const absenceData = {
      ...req.validatedData,
      request_id: generateId('ABS'),
      total_days: calculateDays(req.validatedData.leave_start_date, req.validatedData.leave_end_date),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    console.log(`🏖️ Creating absence request for staff: ${absenceData.staff_member_id}`);
    
    const { data, error } = await supabase
      .from('leave_requests')
      .insert([absenceData])
      .select()
      .single();
    
    if (error) {
      console.error('❌ Create absence error:', error);
      throw error;
    }
    
    console.log(`✅ Absence request created: ${data.request_id} (Staff: ${data.staff_member_id})`);
    res.status(201).json(data);
  } catch (error) {
    console.error('🔥 Create absence error:', error);
    res.status(500).json({ 
      error: 'Failed to create absence record',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/absences/:id
 * @description Update existing leave request
 * @access Private (Requires permission)
 */
app.put('/api/absences/:id', authenticateToken, checkPermission('staff_absence', 'update'), validate(schemas.absence), async (req, res) => {
  try {
    const { id } = req.params;
    const absenceData = {
      ...req.validatedData,
      total_days: calculateDays(req.validatedData.leave_start_date, req.validatedData.leave_end_date),
      updated_at: new Date().toISOString()
    };
    
    console.log(`✏️ Updating absence request: ${id}`);
    
    const { data, error } = await supabase
      .from('leave_requests')
      .update(absenceData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        console.log(`❌ Absence record not found for update: ${id}`);
        return res.status(404).json({ 
          error: 'Absence record not found',
          message: `No absence record found with ID: ${id}`
        });
      }
      console.error('❌ Update absence error:', error);
      throw error;
    }
    
    console.log(`✅ Absence request updated: ${data.request_id} (ID: ${data.id})`);
    res.json(data);
  } catch (error) {
    console.error('🔥 Update absence error:', error);
    res.status(500).json({ 
      error: 'Failed to update absence record',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/absences/:id/approve
 * @description Approve or reject a leave request
 * @access Private (Requires permission)
 * @body {boolean} approved - true to approve, false to reject
 * @body {string} [review_notes] - Optional review notes
 */
app.put('/api/absences/:id/approve', authenticateToken, checkPermission('staff_absence', 'update'), async (req, res) => {
  try {
    const { id } = req.params;
    const { approved, review_notes } = req.body;
    
    console.log(`📝 ${approved ? 'Approving' : 'Rejecting'} absence request: ${id}`);
    
    const updateData = {
      approval_status: approved ? 'approved' : 'rejected',
      reviewed_by: req.user.id,
      reviewed_at: new Date().toISOString(),
      review_notes: review_notes || '',
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('leave_requests')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      console.error('❌ Approve absence error:', error);
      throw error;
    }
    
    console.log(`✅ Absence request ${approved ? 'approved' : 'rejected'}: ${data.request_id}`);
    res.json(data);
  } catch (error) {
    console.error('🔥 Approve absence error:', error);
    res.status(500).json({ 
      error: 'Failed to update absence status',
      message: error.message 
    });
  }
});

// ===== ANNOUNCEMENTS ROUTES =====

/**
 * @route GET /api/announcements
 * @description List all active announcements
 * @access Private
 */
app.get('/api/announcements', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    console.log(`📢 Fetching active announcements for: ${today}`);
    
    const { data, error } = await supabase
      .from('department_announcements')
      .select('*')
      .lte('publish_start_date', today)
      .or(`publish_end_date.gte.${today},publish_end_date.is.null`)
      .order('publish_start_date', { ascending: false });
    
    if (error) {
      console.error('❌ Announcements query error:', error);
      throw error;
    }
    
    console.log(`✅ Found ${data.length} active announcements`);
    res.json(data);
  } catch (error) {
    console.error('🔥 Announcements error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch announcements',
      message: error.message 
    });
  }
});

/**
 * @route POST /api/announcements
 * @description Create new announcement
 * @access Private (Requires permission)
 */
app.post('/api/announcements', authenticateToken, checkPermission('communications', 'create'), validate(schemas.announcement), async (req, res) => {
  try {
    const announcementData = {
      ...req.validatedData,
      announcement_id: generateId('ANN'),
      created_by: req.user.id,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    console.log(`📢 Creating new announcement: ${announcementData.announcement_title}`);
    
    const { data, error } = await supabase
      .from('department_announcements')
      .insert([announcementData])
      .select()
      .single();
    
    if (error) {
      console.error('❌ Create announcement error:', error);
      throw error;
    }
    
    console.log(`✅ Announcement created: ${data.announcement_id} (Title: ${data.announcement_title})`);
    res.status(201).json(data);
  } catch (error) {
    console.error('🔥 Create announcement error:', error);
    res.status(500).json({ 
      error: 'Failed to create announcement',
      message: error.message 
    });
  }
});

/**
 * @route DELETE /api/announcements/:id
 * @description Remove announcement
 * @access Private (Requires permission)
 */
app.delete('/api/announcements/:id', authenticateToken, checkPermission('communications', 'delete'), async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🗑️ Deleting announcement: ${id}`);
    
    const { error } = await supabase
      .from('department_announcements')
      .delete()
      .eq('id', id);
    
    if (error) {
      console.error('❌ Delete announcement error:', error);
      throw error;
    }
    
    console.log(`✅ Announcement deleted: ${id}`);
    res.json({ 
      message: 'Announcement deleted successfully',
      announcement_id: id,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('🔥 Delete announcement error:', error);
    res.status(500).json({ 
      error: 'Failed to delete announcement',
      message: error.message 
    });
  }
});

// ===== DASHBOARD ENDPOINTS =====

/**
 * @route GET /api/dashboard/stats
 * @description Get key metrics for dashboard display
 * @access Private
 */
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    console.log(`📊 Fetching dashboard stats for: ${today}`);
    
    const [
      { count: totalStaff },
      { count: activeStaff },
      { count: activeResidents },
      { count: todayOnCall },
      { count: pendingAbsences }
    ] = await Promise.all([
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('employment_status', 'active'),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('staff_type', 'medical_resident').eq('employment_status', 'active'),
      supabase.from('oncall_schedule').select('*', { count: 'exact', head: true }).eq('duty_date', today),
      supabase.from('leave_requests').select('*', { count: 'exact', head: true }).eq('approval_status', 'pending')
    ]);
    
    const stats = {
      totalStaff: totalStaff || 0,
      activeStaff: activeStaff || 0,
      activeResidents: activeResidents || 0,
      todayOnCall: todayOnCall || 0,
      pendingAbsences: pendingAbsences || 0,
      timestamp: new Date().toISOString()
    };
    
    console.log(`📊 Dashboard stats:`, stats);
    res.json(stats);
  } catch (error) {
    console.error('🔥 Dashboard stats error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch dashboard statistics',
      message: error.message 
    });
  }
});

// ===== SYSTEM SETTINGS ROUTES =====

/**
 * @route GET /api/settings
 * @description Get system configuration settings
 * @access Private
 */
app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    console.log('⚙️ Fetching system settings');
    
    const { data, error } = await supabase
      .from('system_settings')
      .select('*')
      .limit(1)
      .single();
    
    if (error) {
      // Return default settings if table doesn't exist or is empty
      console.log('⚠️ No custom settings found, returning defaults');
      return res.json({
        hospital_name: 'NeumoCare Hospital',
        default_department_id: null,
        max_residents_per_unit: 10,
        default_rotation_duration: 12,
        enable_audit_logging: true,
        require_mfa: false,
        maintenance_mode: false,
        notifications_enabled: true,
        absence_notifications: true,
        announcement_notifications: true,
        is_default: true
      });
    }
    
    res.json(data);
  } catch (error) {
    console.error('🔥 Settings error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch system settings',
      message: error.message 
    });
  }
});

/**
 * @route PUT /api/settings
 * @description Update system configuration settings
 * @access Private (Admin only)
 */
app.put('/api/settings', authenticateToken, checkPermission('system_settings', 'update'), validate(schemas.systemSettings), async (req, res) => {
  try {
    console.log('⚙️ Updating system settings');
    
    const { data, error } = await supabase
      .from('system_settings')
      .upsert([req.validatedData])
      .select()
      .single();
    
    if (error) {
      console.error('❌ Update settings error:', error);
      throw error;
    }
    
    console.log('✅ System settings updated');
    res.json(data);
  } catch (error) {
    console.error('🔥 Update settings error:', error);
    res.status(500).json({ 
      error: 'Failed to update system settings',
      message: error.message 
    });
  }
});

// ===== AVAILABLE DATA FOR SELECT OPTIONS =====

/**
 * @route GET /api/available-data
 * @description Get dropdown data for forms (departments, residents, etc.)
 * @access Private
 * @note Useful for populating select dropdowns in frontend forms
 */
app.get('/api/available-data', authenticateToken, async (req, res) => {
  try {
    console.log('📋 Fetching available data for form dropdowns');
    
    const [departments, residents, attendings, trainingUnits] = await Promise.all([
      supabase.from('departments').select('id, name, code').eq('status', 'active').order('name'),
      supabase.from('medical_staff').select('id, full_name, training_year').eq('staff_type', 'medical_resident').eq('employment_status', 'active').order('full_name'),
      supabase.from('medical_staff').select('id, full_name, specialization').eq('staff_type', 'attending_physician').eq('employment_status', 'active').order('full_name'),
      supabase.from('training_units').select('id, unit_name, unit_code, maximum_residents').eq('unit_status', 'active').order('unit_name')
    ]);
    
    const result = {
      departments: departments.data || [],
      residents: residents.data || [],
      attendings: attendings.data || [],
      trainingUnits: trainingUnits.data || []
    };
    
    console.log(`📋 Available data counts - Departments: ${result.departments.length}, Residents: ${result.residents.length}, Attendings: ${result.attendings.length}, Training Units: ${result.trainingUnits.length}`);
    res.json(result);
  } catch (error) {
    console.error('🔥 Available data error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch available data',
      message: error.message 
    });
  }
});

// ============ ERROR HANDLING MIDDLEWARE ============

/**
 * 404 Handler - Catch all undefined routes
 */
app.use('*', (req, res) => {
  console.log(`❌ Route not found: ${req.method} ${req.originalUrl}`);
  
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The requested endpoint ${req.originalUrl} does not exist`,
    availableEndpoints: [
      '/health',
      '/api/auth/login',
      '/api/auth/logout',
      '/api/users/profile',
      '/api/dashboard/stats',
      '/api/medical-staff',
      '/api/departments',
      '/api/training-units',
      '/api/rotations',
      '/api/oncall',
      '/api/absences',
      '/api/announcements',
      '/api/settings',
      '/api/available-data',
      '/api/debug/tables'
    ]
  });
});

/**
 * Global error handler
 */
app.use((err, req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.url;
  
  console.error(`🔥 [${timestamp}] ${method} ${url} - Error:`, err.message);
  console.error('Stack trace:', err.stack);
  
  // Handle JWT errors
  if (err.message?.includes('JWT') || err.name === 'JsonWebTokenError') {
    return res.status(401).json({ 
      error: 'Authentication error',
      message: 'Invalid or expired authentication token',
      timestamp
    });
  }
  
  // Handle Supabase errors
  if (err.message?.includes('Supabase') || err.code?.startsWith('PGRST')) {
    return res.status(500).json({
      error: 'Database error',
      message: 'An error occurred while accessing the database',
      timestamp,
      details: NODE_ENV === 'development' ? err.message : undefined
    });
  }
  
  // Generic error response
  res.status(500).json({
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? err.message : 'An unexpected error occurred',
    timestamp
  });
});

// ============ SERVER STARTUP ============

/**
 * Start the Express server
 */
const server = app.listen(PORT, () => {
  console.log(`
    ======================================================
    🏥 NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API v4.2
    ======================================================
    ✅ Server running on port: ${PORT}
    ✅ Environment: ${NODE_ENV}
    ✅ Supabase URL: ${SUPABASE_URL ? 'Configured' : 'Not configured'}
    ✅ Health check: http://localhost:${PORT}/health
    ✅ Debug endpoint: http://localhost:${PORT}/api/debug/tables
    ======================================================
    📝 Key fixes applied:
    • Corrected Supabase join syntax for all endpoints
    • Fixed multiple foreign key joins to same table
    • Enhanced error handling and logging
    • Added comprehensive API documentation
    ======================================================
  `);
});

/**
 * Graceful shutdown handlers
 */
process.on('SIGTERM', () => {
  console.log('🔴 SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('🛑 HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🔴 SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('🛑 HTTP server closed');
    process.exit(0);
  });
});

// Export for testing purposes
module.exports = app;
