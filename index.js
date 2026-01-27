// ============ NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API ============
// COMPLETE PRODUCTION-READY REST API
// VERSION 2.0 - READY FOR RAILWAY DEPLOYMENT
// == ===================== ========================== ===============

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Joi = require('joi');
require('dotenv').config();

// Initialize Express App
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
  console.error('Missing required environment variables: SUPABASE_URL, SUPABASE_SERVICE_KEY');
  process.exit(1);
}

// ============ SUPABASE CLIENT ============
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

// ============ SECURITY MIDDLEWARE ============
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// In your server.js, update the CORS configuration:
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:5500',
  'https://innovationneumologia.github.io',
  'https://*.github.io',
  'https://*.vercel.app',
  'https://*.netlify.app',
  'https://*.railway.app',
  // Add these for debugging and specific domains:
  'https://innovationneumologia.github.io/Neumocare-Hospital-Management/',
  'https://bacend-production.up.railway.app',
  'http://bacend-production.up.railway.app',
  // Allow any origin for testing (remove in production):
  ...(process.env.NODE_ENV === 'development' ? ['*'] : [])
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // For development/testing, allow all origins
    if (process.env.NODE_ENV === 'development') {
      console.log('Development mode: Allowing origin:', origin);
      return callback(null, true);
    }
    
    // Check if origin matches allowed origins
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin === '*') return true;
      if (allowedOrigin.includes('*')) {
        const regex = new RegExp('^' + allowedOrigin.replace('*', '.*') + '$');
        return regex.test(origin);
      }
      return allowedOrigin === origin;
    });
    
    if (isAllowed) {
      console.log('CORS: Allowed origin:', origin);
      callback(null, true);
    } else {
      console.log('CORS: Blocked origin:', origin);
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));

// Rate Limiting
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
  max: process.env.NODE_ENV === 'development' ? 100 : 5, // Higher limit for dev
  message: {
    error: 'Too many login attempts, please try again later'
  },
  skipSuccessfulRequests: true
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request Logger Middleware
app.use((req, res, next) => {
  const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2);
  req.requestId = requestId;
  
  console.log(`[${new Date().toISOString()}] [${requestId}] ${req.method} ${req.url}`);
  next();
});

// ============ VALIDATION SCHEMAS ============
const schemas = {
  login: Joi.object({
    email: Joi.string().email().required().trim().lowercase(),
    password: Joi.string().min(6).required(),
    remember_me: Joi.boolean().default(false)
  }),
  
  medicalStaff: Joi.object({
    full_name: Joi.string().min(2).max(100).required(),
    staff_type: Joi.string().valid('medical_resident', 'attending_physician', 'fellow', 'nurse_practitioner').required(),
    staff_id: Joi.string().optional().allow(''),
    employment_status: Joi.string().valid('active', 'on_leave', 'inactive').default('active'),
    professional_email: Joi.string().email().required(),
    department_id: Joi.string().uuid().optional().allow('', null),
    resident_category: Joi.string().valid('department_internal', 'rotating_other_dept', 'external_institution').optional().allow(''),
    training_level: Joi.string().valid('pgy1', 'pgy2', 'pgy3', 'pgy4', 'other').optional().allow(''),
    specialization: Joi.string().max(100).optional().allow(''),
    years_experience: Joi.number().min(0).max(50).optional().allow(''),
    biography: Joi.string().max(1000).optional().allow(''),
    office_phone: Joi.string().pattern(/^[\d\s\-\+\(\)]{10,20}$/).optional().allow(''),
    mobile_phone: Joi.string().pattern(/^[\d\s\-\+\(\)]{10,20}$/).optional().allow(''),
    medical_license: Joi.string().max(50).optional().allow(''),
    date_of_birth: Joi.date().iso().max('now').optional().allow('')
  }),
  
  department: Joi.object({
    name: Joi.string().min(2).max(100).required(),
    code: Joi.string().min(2).max(10).required(),
    status: Joi.string().valid('active', 'inactive').default('active'),
    description: Joi.string().max(500).optional().allow(''),
    head_of_department_id: Joi.string().uuid().optional().allow('', null)
  }),
  
  rotation: Joi.object({
    resident_id: Joi.string().uuid().required(),
    training_unit_id: Joi.string().uuid().required(),
    start_date: Joi.date().iso().required(),
    end_date: Joi.date().iso().greater(Joi.ref('start_date')).required(),
    supervisor_id: Joi.string().uuid().optional().allow('', null),
    status: Joi.string().valid('active', 'upcoming', 'completed', 'cancelled').default('active'),
    goals: Joi.string().max(1000).optional().allow(''),
    notes: Joi.string().max(1000).optional().allow('')
  }),
  
  onCall: Joi.object({
    duty_date: Joi.date().iso().required(),
    shift_type: Joi.string().valid('primary_call', 'backup_call', 'night_shift').default('primary_call'),
    start_time: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/).default('08:00'),
    end_time: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/).default('17:00'),
    primary_physician_id: Joi.string().uuid().required(),
    backup_physician_id: Joi.string().uuid().optional().allow('', null),
    coverage_notes: Joi.string().max(500).optional().allow(''),
    status: Joi.string().valid('scheduled', 'completed', 'cancelled').default('scheduled')
  }),
  
  absence: Joi.object({
    staff_member_id: Joi.string().uuid().required(),
    absence_reason: Joi.string().valid('vacation', 'sick_leave', 'conference', 'personal', 'maternity_paternity', 'administrative', 'other').required(),
    start_date: Joi.date().iso().required(),
    end_date: Joi.date().iso().greater(Joi.ref('start_date')).required(),
    notes: Joi.string().max(500).optional().allow(''),
    replacement_staff_id: Joi.string().uuid().optional().allow('', null),
    coverage_instructions: Joi.string().max(500).optional().allow('')
  }),
  
  announcement: Joi.object({
    announcement_title: Joi.string().min(5).max(200).required(),
    announcement_content: Joi.string().min(10).required(),
    publish_start_date: Joi.date().iso().required(),
    publish_end_date: Joi.date().iso().greater(Joi.ref('publish_start_date')).optional().allow('', null),
    priority_level: Joi.string().valid('low', 'medium', 'high', 'urgent').default('medium'),
    target_audience: Joi.string().valid('all', 'residents', 'attendings', 'department').default('all')
  }),
  
  userProfile: Joi.object({
    full_name: Joi.string().min(2).max(100).required(),
    email: Joi.string().email().required().trim().lowercase(),
    phone: Joi.string().pattern(/^[\d\s\-\+\(\)]{10,20}$/).optional().allow(''),
    department_id: Joi.string().uuid().optional().allow('', null),
    notifications_enabled: Joi.boolean().default(true),
    absence_notifications: Joi.boolean().default(true),
    announcement_notifications: Joi.boolean().default(true)
  }),
  
  systemSettings: Joi.object({
    hospital_name: Joi.string().min(2).max(100).required(),
    default_department_id: Joi.string().uuid().optional().allow('', null),
    max_residents_per_unit: Joi.number().min(1).max(50).default(10),
    default_rotation_duration: Joi.number().min(1).max(52).default(12),
    enable_audit_logging: Joi.boolean().default(true),
    require_mfa: Joi.boolean().default(false),
    maintenance_mode: Joi.boolean().default(false),
    notifications_enabled: Joi.boolean().default(true),
    absence_notifications: Joi.boolean().default(true),
    announcement_notifications: Joi.boolean().default(true)
  })
};

// Validation Middleware
const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { abortEarly: false });
  
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
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  
  if (!token) {
    return res.status(401).json({ 
      error: 'Authentication required',
      message: 'No access token provided' 
    });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        error: 'Invalid token',
        message: 'Access token is invalid or expired' 
      });
    }
    
    req.user = user;
    next();
  });
};

// ============ PERMISSION SYSTEM ============
const PERMISSIONS = {
  system_admin: {
    name: 'System Administrator',
    permissions: {
      medical_staff: { create: true, read: true, update: true, delete: true },
      training_units: { create: true, read: true, update: true, delete: true, assign: true },
      resident_rotations: { create: true, read: true, update: true, delete: true, extend: true },
      oncall_schedule: { create: true, read: true, update: true, delete: true },
      staff_absence: { create: true, read: true, update: true, delete: true },
      communications: { create: true, read: true, update: true, delete: true },
      audit: { read: true },
      system: { read: true, update: true },
      permissions: { manage: true },
      placements: { create: true }
    }
  },
  department_head: {
    name: 'Head of Department',
    permissions: {
      medical_staff: { create: true, read: true, update: true, delete: false },
      training_units: { create: true, read: true, update: true, delete: false, assign: true },
      resident_rotations: { create: true, read: true, update: true, delete: false, extend: true },
      oncall_schedule: { create: true, read: true, update: true, delete: false },
      staff_absence: { create: true, read: true, update: true, delete: true },
      communications: { create: true, read: true, update: true, delete: true },
      audit: { read: true },
      system: { read: true, update: false },
      permissions: { manage: false },
      placements: { create: true }
    }
  },
  resident_manager: {
    name: 'Resident Manager',
    permissions: {
      medical_staff: { create: true, read: true, update: true, delete: false },
      training_units: { create: true, read: true, update: true, delete: false, assign: true },
      resident_rotations: { create: true, read: true, update: true, delete: false, extend: true },
      oncall_schedule: { create: false, read: true, update: false, delete: false },
      staff_absence: { create: true, read: true, update: false, delete: false },
      communications: { create: false, read: true, update: false, delete: false },
      audit: { read: false },
      system: { read: false, update: false },
      permissions: { manage: false },
      placements: { create: true }
    }
  },
  attending_physician: {
    name: 'Attending Physician',
    permissions: {
      medical_staff: { create: false, read: true, update: false, delete: false },
      training_units: { create: false, read: true, update: false, delete: false, assign: false },
      resident_rotations: { create: false, read: true, update: false, delete: false, extend: false },
      oncall_schedule: { create: false, read: true, update: false, delete: false },
      staff_absence: { create: true, read: true, update: false, delete: false },
      communications: { create: false, read: true, update: false, delete: false },
      audit: { read: false },
      system: { read: false, update: false },
      permissions: { manage: false },
      placements: { create: false }
    }
  },
  viewing_doctor: {
    name: 'Viewing Doctor',
    permissions: {
      medical_staff: { create: false, read: true, update: false, delete: false },
      training_units: { create: false, read: true, update: false, delete: false, assign: false },
      resident_rotations: { create: false, read: true, update: false, delete: false, extend: false },
      oncall_schedule: { create: false, read: true, update: false, delete: false },
      staff_absence: { create: false, read: true, update: false, delete: false },
      communications: { create: false, read: true, update: false, delete: false },
      audit: { read: false },
      system: { read: false, update: false },
      permissions: { manage: false },
      placements: { create: false }
    }
  }
};

// Permission Middleware
const checkPermission = (resource, action) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const userRole = req.user.role;
    const rolePermissions = PERMISSIONS[userRole];
    
    if (!rolePermissions) {
      return res.status(403).json({ error: 'Invalid user role' });
    }
    
    // System admin has all permissions
    if (userRole === 'system_admin') return next();
    
    const resourcePerms = rolePermissions.permissions[resource];
    
    if (!resourcePerms || !resourcePerms[action]) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        message: `You need ${action} permission for ${resource}`
      });
    }
    
    next();
  };
};

// ============ AUDIT LOGGING ============
const auditLog = async (req, action, resource, details = {}) => {
  try {
    const auditData = {
      user_id: req.user?.id || 'anonymous',
      user_name: req.user?.email || 'system',
      user_role: req.user?.role || 'system',
      action,
      resource,
      details: JSON.stringify(details),
      ip_address: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      user_agent: req.get('User-Agent') || 'unknown',
      request_id: req.requestId,
      created_at: new Date().toISOString()
    };
    
    const { error } = await supabase
      .from('audit_logs')
      .insert([auditData]);
    
    if (error) {
      console.error('Audit log error:', error.message);
    }
  } catch (error) {
    console.error('Failed to log audit:', error.message);
  }
};

// Audit Middleware
const withAudit = (action, resource) => async (req, res, next) => {
  const originalJson = res.json;
  
  res.json = function(data) {
    // Log successful responses
    if (res.statusCode >= 200 && res.statusCode < 300) {
      auditLog(req, action, resource, { 
        resourceId: req.params.id,
        status: res.statusCode 
      }).catch(console.error);
    }
    
    originalJson.call(this, data);
  };
  
  next();
};

// ============ UTILITY FUNCTIONS ============
const generateId = (prefix) => {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 9)}`;
};

const formatDate = (dateString) => {
  if (!dateString) return '';
  try {
    const date = new Date(dateString);
    return date.toISOString().split('T')[0];
  } catch {
    return '';
  }
};

// ============ ROUTES ============

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'NeumoCare Hospital API',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    uptime: process.uptime()
  });
});

// ===== AUTHENTICATION =====
app.post('/api/auth/login', authLimiter, validate(schemas.login), async (req, res) => {
  try {
    const { email, password } = req.validatedData;
    
    // Demo admin account (remove in production)
    if (email === 'admin@neumocare.org' && password === 'password123') {
      const token = jwt.sign(
        { 
          id: 'admin-001',
          email: 'admin@neumocare.org',
          role: 'system_admin'
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      return res.json({
        token,
        user: {
          id: 'admin-001',
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
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password'
      });
    }
    
    if (user.account_status !== 'active') {
      return res.status(403).json({
        error: 'Account disabled',
        message: 'Your account has been deactivated'
      });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash || '');
    if (!validPassword) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid email or password'
      });
    }
    
    // Generate JWT
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
    
    res.json({
      token,
      user: userWithoutPassword
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    await auditLog(req, 'LOGOUT', 'auth');
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== USER PROFILE =====
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, notifications_enabled, absence_notifications, announcement_notifications, created_at')
      .eq('id', req.user.id)
      .single();
    
    if (error) throw error;
    
    res.json(user);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

app.put('/api/users/profile', authenticateToken, validate(schemas.userProfile), async (req, res) => {
  try {
    const updateData = {
      full_name: req.validatedData.full_name,
      phone_number: req.validatedData.phone,
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
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ===== DASHBOARD ENDPOINTS =====
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    
    // Get all counts in parallel
    const [
      { count: totalStaff = 0 },
      { count: activeStaff = 0 },
      { count: activeResidents = 0 },
      { count: todayOnCall = 0 },
      { count: pendingAbsences = 0 },
      { count: activeAlerts = 0 }
    ] = await Promise.all([
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('employment_status', 'active'),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('staff_type', 'medical_resident').eq('employment_status', 'active'),
      supabase.from('oncall_schedule').select('*', { count: 'exact', head: true }).eq('duty_date', today),
      supabase.from('leave_requests').select('*', { count: 'exact', head: true }).eq('approval_status', 'pending'),
      supabase.from('system_alerts').select('*', { count: 'exact', head: true }).eq('status', 'active')
    ]);
    
    res.json({
      totalStaff,
      activeStaff,
      activeResidents,
      todayOnCall,
      pendingAbsences,
      activeAlerts,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

app.get('/api/dashboard/oncall-today', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    
    const { data, error } = await supabase
      .from('oncall_schedule')
      .select(`
        *,
        primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, staff_type, professional_email),
        backup_physician:medical_staff!oncall_schedule_backup_physician_id_fkey(full_name, staff_type, professional_email)
      `)
      .eq('duty_date', today)
      .order('start_time');
    
    if (error) throw error;
    
    const formatted = (data || []).map(item => ({
      id: item.id,
      duty_date: item.duty_date,
      shift_type: item.shift_type,
      start_time: item.start_time,
      end_time: item.end_time,
      primary_physician: item.primary_physician,
      backup_physician: item.backup_physician,
      coverage_notes: item.coverage_notes,
      status: item.status,
      role: item.shift_type === 'primary_call' ? 'Primary' : 
            item.shift_type === 'backup_call' ? 'Backup' : 'Night Shift'
    }));
    
    res.json(formatted);
  } catch (error) {
    console.error('On-call today error:', error);
    res.status(500).json({ error: 'Failed to fetch today\'s on-call schedule' });
  }
});

app.get('/api/dashboard/calendar', authenticateToken, async (req, res) => {
  try {
    const { start, end } = req.query;
    if (!start || !end) {
      return res.status(400).json({ error: 'Start and end dates required' });
    }
    
    const [absences, rotations, oncall] = await Promise.all([
      supabase
        .from('leave_requests')
        .select(`
          leave_start_date as start_date,
          leave_end_date as end_date,
          leave_category as type,
          medical_staff!leave_requests_staff_member_id_fkey(full_name, professional_email)
        `)
        .eq('approval_status', 'approved')
        .gte('leave_start_date', start)
        .lte('leave_end_date', end),
      
      supabase
        .from('resident_rotations')
        .select(`
          start_date,
          end_date,
          status,
          medical_staff!resident_rotations_resident_id_fkey(full_name, professional_email),
          training_units(unit_name, unit_code)
        `)
        .in('status', ['active', 'upcoming'])
        .gte('start_date', start)
        .lte('end_date', end),
      
      supabase
        .from('oncall_schedule')
        .select(`
          duty_date,
          shift_type,
          medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email)
        `)
        .gte('duty_date', start)
        .lte('duty_date', end)
    ]);
    
    res.json({
      absences: absences.data || [],
      rotations: rotations.data || [],
      oncall: oncall.data || []
    });
  } catch (error) {
    console.error('Calendar error:', error);
    res.status(500).json({ error: 'Failed to fetch calendar events' });
  }
});

// ===== MEDICAL STAFF =====
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
    
    let query = supabase
      .from('medical_staff')
      .select(`
        *,
        department:departments(name, code)
      `, { count: 'exact' });
    
    // Apply filters
    if (search) {
      query = query.or(`full_name.ilike.%${search}%,staff_id.ilike.%${search}%,professional_email.ilike.%${search}%`);
    }
    if (staff_type) query = query.eq('staff_type', staff_type);
    if (employment_status) query = query.eq('employment_status', employment_status);
    if (department_id) query = query.eq('department_id', department_id);
    
    // Apply pagination
    query = query.order('full_name').range(offset, offset + limit - 1);
    
    const { data, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      data: data || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limit)
      }
    });
  } catch (error) {
    console.error('Medical staff list error:', error);
    res.status(500).json({ error: 'Failed to fetch medical staff' });
  }
});

app.get('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'read'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('medical_staff')
      .select(`
        *,
        department:departments(name, code),
        rotations:resident_rotations!resident_rotations_resident_id_fkey(*, training_units(unit_name, unit_code)),
        supervised_rotations:resident_rotations!resident_rotations_supervisor_id_fkey(*, medical_staff!resident_rotations_resident_id_fkey(full_name)),
        absences:leave_requests!leave_requests_staff_member_id_fkey(*)
      `)
      .eq('id', req.params.id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Medical staff not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Medical staff details error:', error);
    res.status(500).json({ error: 'Failed to fetch staff details' });
  }
});

app.post('/api/medical-staff', authenticateToken, checkPermission('medical_staff', 'create'), validate(schemas.medicalStaff), withAudit('CREATE', 'medical_staff'), async (req, res) => {
  try {
    const staffData = {
      ...req.validatedData,
      staff_id: req.validatedData.staff_id || generateId('MD'),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('medical_staff')
      .insert([staffData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Create medical staff error:', error);
    
    if (error.code === '23505') { // Unique violation
      return res.status(409).json({ 
        error: 'Duplicate entry',
        message: 'A staff member with this email or staff ID already exists'
      });
    }
    
    res.status(500).json({ error: 'Failed to create medical staff' });
  }
});

app.put('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'update'), validate(schemas.medicalStaff), withAudit('UPDATE', 'medical_staff'), async (req, res) => {
  try {
    const staffData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('medical_staff')
      .update(staffData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Medical staff not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update medical staff error:', error);
    res.status(500).json({ error: 'Failed to update medical staff' });
  }
});

app.delete('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'delete'), withAudit('DELETE', 'medical_staff'), async (req, res) => {
  try {
    // First, check if staff exists
    const { data: staff, error: checkError } = await supabase
      .from('medical_staff')
      .select('id, full_name')
      .eq('id', req.params.id)
      .single();
    
    if (checkError) {
      return res.status(404).json({ error: 'Medical staff not found' });
    }
    
    // Soft delete by setting status to inactive
    const { error } = await supabase
      .from('medical_staff')
      .update({ 
        employment_status: 'inactive',
        updated_at: new Date().toISOString()
      })
      .eq('id', req.params.id);
    
    if (error) throw error;
    
    res.json({ 
      message: 'Medical staff deactivated successfully',
      staff: { id: staff.id, name: staff.full_name }
    });
  } catch (error) {
    console.error('Delete medical staff error:', error);
    res.status(500).json({ error: 'Failed to deactivate medical staff' });
  }
});

// ===== DEPARTMENTS =====
app.get('/api/departments', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('departments')
      .select(`
        *,
        head_of_department:medical_staff!departments_head_of_department_id_fkey(full_name, professional_email),
        clinical_units:clinical_units(*),
        training_units:training_units(*)
      `)
      .order('name');
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('Departments error:', error);
    res.status(500).json({ error: 'Failed to fetch departments' });
  }
});

app.get('/api/departments/:id', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('departments')
      .select(`
        *,
        head_of_department:medical_staff!departments_head_of_department_id_fkey(full_name, professional_email, staff_type),
        clinical_units:clinical_units(*),
        training_units:training_units(*),
        medical_staff:medical_staff(*)
      `)
      .eq('id', req.params.id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Department not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Department details error:', error);
    res.status(500).json({ error: 'Failed to fetch department details' });
  }
});

app.post('/api/departments', authenticateToken, checkPermission('system', 'update'), validate(schemas.department), withAudit('CREATE', 'departments'), async (req, res) => {
  try {
    const deptData = {
      ...req.validatedData,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('departments')
      .insert([deptData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Create department error:', error);
    res.status(500).json({ error: 'Failed to create department' });
  }
});

app.put('/api/departments/:id', authenticateToken, checkPermission('system', 'update'), validate(schemas.department), withAudit('UPDATE', 'departments'), async (req, res) => {
  try {
    const deptData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('departments')
      .update(deptData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Department not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update department error:', error);
    res.status(500).json({ error: 'Failed to update department' });
  }
});

app.delete('/api/departments/:id', authenticateToken, checkPermission('system', 'update'), withAudit('DELETE', 'departments'), async (req, res) => {
  try {
    // Check if department has staff or units
    const [{ count: staffCount }, { count: unitsCount }] = await Promise.all([
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('department_id', req.params.id),
      supabase.from('clinical_units').select('*', { count: 'exact', head: true }).eq('department_id', req.params.id)
    ]);
    
    if (staffCount > 0 || unitsCount > 0) {
      return res.status(400).json({
        error: 'Cannot delete department',
        message: 'Department has staff members or clinical units assigned'
      });
    }
    
    const { error } = await supabase
      .from('departments')
      .delete()
      .eq('id', req.params.id);
    
    if (error) throw error;
    
    res.json({ message: 'Department deleted successfully' });
  } catch (error) {
    console.error('Delete department error:', error);
    res.status(500).json({ error: 'Failed to delete department' });
  }
});

// ===== CLINICAL UNITS =====
app.get('/api/clinical-units', authenticateToken, async (req, res) => {
  try {
    const { department_id } = req.query;
    
    let query = supabase
      .from('clinical_units')
      .select(`
        *,
        department:departments(name, code),
        supervisor:medical_staff(full_name, professional_email)
      `)
      .order('name');
    
    if (department_id) {
      query = query.eq('department_id', department_id);
    }
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('Clinical units error:', error);
    res.status(500).json({ error: 'Failed to fetch clinical units' });
  }
});

// ===== TRAINING UNITS =====
app.get('/api/training-units', authenticateToken, async (req, res) => {
  try {
    const { department_id, status } = req.query;
    
    let query = supabase
      .from('training_units')
      .select(`
        *,
        department:departments(name, code),
        supervisor:medical_staff(full_name, professional_email),
        resident_rotations!resident_rotations_training_unit_id_fkey(
          *,
          medical_staff!resident_rotations_resident_id_fkey(full_name, training_level)
        )
      `)
      .order('unit_name');
    
    if (department_id) query = query.eq('department_id', department_id);
    if (status) query = query.eq('status', status);
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    // Add current resident count
    const unitsWithCount = (data || []).map(unit => ({
      ...unit,
      current_residents: unit.resident_rotations?.filter(r => r.status === 'active').length || 0
    }));
    
    res.json(unitsWithCount);
  } catch (error) {
    console.error('Training units error:', error);
    res.status(500).json({ error: 'Failed to fetch training units' });
  }
});

app.get('/api/training-units/:id/residents', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('resident_rotations')
      .select(`
        *,
        medical_staff!resident_rotations_resident_id_fkey(
          id,
          full_name,
          training_level,
          professional_email
        )
      `)
      .eq('training_unit_id', req.params.id)
      .eq('status', 'active');
    
    if (error) throw error;
    
    const residents = (data || []).map(rotation => ({
      ...rotation.medical_staff,
      rotation_id: rotation.id,
      rotation_start_date: rotation.start_date,
      rotation_end_date: rotation.end_date,
      supervisor_id: rotation.supervisor_id
    }));
    
    res.json(residents);
  } catch (error) {
    console.error('Training unit residents error:', error);
    res.status(500).json({ error: 'Failed to fetch unit residents' });
  }
});

app.post('/api/training-units', authenticateToken, checkPermission('training_units', 'create'), withAudit('CREATE', 'training_units'), async (req, res) => {
  try {
    const unitData = {
      ...req.body,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('training_units')
      .insert([unitData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Create training unit error:', error);
    res.status(500).json({ error: 'Failed to create training unit' });
  }
});

app.put('/api/training-units/:id', authenticateToken, checkPermission('training_units', 'update'), withAudit('UPDATE', 'training_units'), async (req, res) => {
  try {
    const unitData = {
      ...req.body,
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('training_units')
      .update(unitData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Training unit not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update training unit error:', error);
    res.status(500).json({ error: 'Failed to update training unit' });
  }
});

// ===== RESIDENT ROTATIONS =====
app.get('/api/rotations', authenticateToken, async (req, res) => {
  try {
    const { 
      resident_id, 
      status, 
      training_unit_id,
      start_date,
      end_date,
      page = 1,
      limit = 20
    } = req.query;
    
    const offset = (page - 1) * limit;
    
    let query = supabase
      .from('resident_rotations')
      .select(`
        *,
        resident:medical_staff!resident_rotations_resident_id_fkey(full_name, training_level, professional_email),
        supervisor:medical_staff!resident_rotations_supervisor_id_fkey(full_name, professional_email),
        training_unit:training_units(unit_name, unit_code, department_id),
        department:training_units!inner(departments(name, code))
      `, { count: 'exact' });
    
    if (resident_id) query = query.eq('resident_id', resident_id);
    if (status) query = query.eq('status', status);
    if (training_unit_id) query = query.eq('training_unit_id', training_unit_id);
    if (start_date) query = query.gte('start_date', start_date);
    if (end_date) query = query.lte('end_date', end_date);
    
    query = query.order('start_date', { ascending: false }).range(offset, offset + limit - 1);
    
    const { data, error, count } = await query;
    
    if (error) throw error;
    
    // Calculate duration for each rotation
    const rotationsWithDuration = (data || []).map(rotation => {
      const start = new Date(rotation.start_date);
      const end = new Date(rotation.end_date);
      const durationWeeks = Math.ceil((end - start) / (1000 * 60 * 60 * 24 * 7));
      
      return {
        ...rotation,
        duration_weeks: durationWeeks,
        department_name: rotation.department?.departments?.name
      };
    });
    
    res.json({
      data: rotationsWithDuration,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limit)
      }
    });
  } catch (error) {
    console.error('Rotations error:', error);
    res.status(500).json({ error: 'Failed to fetch rotations' });
  }
});

app.get('/api/rotations/:id', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('resident_rotations')
      .select(`
        *,
        resident:medical_staff!resident_rotations_resident_id_fkey(*),
        supervisor:medical_staff!resident_rotations_supervisor_id_fkey(full_name, professional_email),
        training_unit:training_units(*)
      `)
      .eq('id', req.params.id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Rotation not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Rotation details error:', error);
    res.status(500).json({ error: 'Failed to fetch rotation details' });
  }
});

app.post('/api/rotations', authenticateToken, checkPermission('resident_rotations', 'create'), validate(schemas.rotation), withAudit('CREATE', 'resident_rotations'), async (req, res) => {
  try {
    const rotationData = {
      ...req.validatedData,
      rotation_id: generateId('ROT'),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('resident_rotations')
      .insert([rotationData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Create rotation error:', error);
    res.status(500).json({ error: 'Failed to create rotation' });
  }
});

app.post('/api/rotations/quick-placement', authenticateToken, checkPermission('placements', 'create'), withAudit('CREATE', 'resident_rotations'), async (req, res) => {
  try {
    const { resident_id, training_unit_id, start_date, duration = 4, supervisor_id, notes } = req.body;
    
    // Validate required fields
    if (!resident_id || !training_unit_id || !start_date) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        message: 'Resident, training unit, and start date are required'
      });
    }
    
    const endDate = new Date(start_date);
    endDate.setDate(endDate.getDate() + (duration * 7));
    
    const rotationData = {
      rotation_id: generateId('ROT'),
      resident_id,
      training_unit_id,
      start_date,
      end_date: endDate.toISOString().split('T')[0],
      supervisor_id: supervisor_id || null,
      notes: notes || '',
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('resident_rotations')
      .insert([rotationData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Quick placement error:', error);
    res.status(500).json({ error: 'Failed to create quick placement' });
  }
});

app.post('/api/rotations/bulk-assign', authenticateToken, checkPermission('training_units', 'assign'), withAudit('CREATE', 'resident_rotations'), async (req, res) => {
  try {
    const { selectedResidents, training_unit_id, start_date, duration = 4, supervisor_id } = req.body;
    
    if (!selectedResidents || !Array.isArray(selectedResidents) || selectedResidents.length === 0) {
      return res.status(400).json({ 
        error: 'Invalid selection',
        message: 'Please select at least one resident' 
      });
    }
    
    if (!training_unit_id || !start_date) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        message: 'Training unit and start date are required' 
      });
    }
    
    const endDate = new Date(start_date);
    endDate.setDate(endDate.getDate() + (duration * 7));
    
    const rotations = selectedResidents.map(residentId => ({
      rotation_id: generateId('ROT'),
      resident_id: residentId,
      training_unit_id,
      start_date,
      end_date: endDate.toISOString().split('T')[0],
      supervisor_id: supervisor_id || null,
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }));
    
    const { data, error } = await supabase
      .from('resident_rotations')
      .insert(rotations)
      .select();
    
    if (error) throw error;
    
    res.status(201).json({
      message: `${rotations.length} resident${rotations.length === 1 ? '' : 's'} assigned successfully`,
      rotations: data
    });
  } catch (error) {
    console.error('Bulk assign error:', error);
    res.status(500).json({ error: 'Failed to assign residents' });
  }
});

app.put('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'update'), validate(schemas.rotation), withAudit('UPDATE', 'resident_rotations'), async (req, res) => {
  try {
    const rotationData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('resident_rotations')
      .update(rotationData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Rotation not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update rotation error:', error);
    res.status(500).json({ error: 'Failed to update rotation' });
  }
});

app.delete('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'delete'), withAudit('DELETE', 'resident_rotations'), async (req, res) => {
  try {
    const { error } = await supabase
      .from('resident_rotations')
      .update({
        status: 'cancelled',
        updated_at: new Date().toISOString()
      })
      .eq('id', req.params.id);
    
    if (error) throw error;
    
    res.json({ message: 'Rotation cancelled successfully' });
  } catch (error) {
    console.error('Delete rotation error:', error);
    res.status(500).json({ error: 'Failed to cancel rotation' });
  }
});

// ===== ON-CALL SCHEDULE =====
app.get('/api/oncall', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { start_date, end_date, physician_id } = req.query;
    
    let query = supabase
      .from('oncall_schedule')
      .select(`
        *,
        primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email, mobile_phone),
        backup_physician:medical_staff!oncall_schedule_backup_physician_id_fkey(full_name, professional_email, mobile_phone),
        scheduled_by:app_users(full_name, email)
      `)
      .order('duty_date');
    
    if (start_date) query = query.gte('duty_date', start_date);
    if (end_date) query = query.lte('duty_date', end_date);
    if (physician_id) {
      query = query.or(`primary_physician_id.eq.${physician_id},backup_physician_id.eq.${physician_id}`);
    }
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('On-call schedule error:', error);
    res.status(500).json({ error: 'Failed to fetch on-call schedule' });
  }
});

app.post('/api/oncall', authenticateToken, checkPermission('oncall_schedule', 'create'), validate(schemas.onCall), withAudit('CREATE', 'oncall_schedule'), async (req, res) => {
  try {
    const scheduleData = {
      ...req.validatedData,
      scheduled_by: req.user.id,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('oncall_schedule')
      .insert([scheduleData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Create on-call error:', error);
    res.status(500).json({ error: 'Failed to create on-call schedule' });
  }
});

app.put('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'update'), validate(schemas.onCall), withAudit('UPDATE', 'oncall_schedule'), async (req, res) => {
  try {
    const scheduleData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('oncall_schedule')
      .update(scheduleData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Schedule not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update on-call error:', error);
    res.status(500).json({ error: 'Failed to update on-call schedule' });
  }
});

app.delete('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'delete'), withAudit('DELETE', 'oncall_schedule'), async (req, res) => {
  try {
    const { error } = await supabase
      .from('oncall_schedule')
      .delete()
      .eq('id', req.params.id);
    
    if (error) throw error;
    
    res.json({ message: 'On-call schedule deleted successfully' });
  } catch (error) {
    console.error('Delete on-call error:', error);
    res.status(500).json({ error: 'Failed to delete on-call schedule' });
  }
});

// ===== STAFF ABSENCES =====
app.get('/api/absences', authenticateToken, async (req, res) => {
  try {
    const { staff_id, status, start_date, end_date } = req.query;
    
    let query = supabase
      .from('leave_requests')
      .select(`
        *,
        staff_member:medical_staff!leave_requests_staff_member_id_fkey(full_name, professional_email, department_id),
        replacement_staff:medical_staff!leave_requests_replacement_staff_id_fkey(full_name, professional_email),
        documented_by:app_users(full_name, email)
      `)
      .order('leave_start_date');
    
    if (staff_id) query = query.eq('staff_member_id', staff_id);
    if (status) query = query.eq('approval_status', status);
    if (start_date) query = query.gte('leave_start_date', start_date);
    if (end_date) query = query.lte('leave_end_date', end_date);
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    // Calculate duration for each absence
    const absencesWithDuration = (data || []).map(absence => {
      const start = new Date(absence.leave_start_date);
      const end = new Date(absence.leave_end_date);
      const durationDays = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;
      
      return {
        ...absence,
        duration_days: durationDays
      };
    });
    
    res.json(absencesWithDuration);
  } catch (error) {
    console.error('Absences error:', error);
    res.status(500).json({ error: 'Failed to fetch absences' });
  }
});

app.get('/api/absences/:id', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('leave_requests')
      .select(`
        *,
        staff_member:medical_staff!leave_requests_staff_member_id_fkey(*),
        replacement_staff:medical_staff!leave_requests_replacement_staff_id_fkey(full_name, professional_email),
        documented_by:app_users(full_name, email)
      `)
      .eq('id', req.params.id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Absence record not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Absence details error:', error);
    res.status(500).json({ error: 'Failed to fetch absence details' });
  }
});

app.post('/api/absences', authenticateToken, checkPermission('staff_absence', 'create'), validate(schemas.absence), withAudit('CREATE', 'staff_absence'), async (req, res) => {
  try {
    const absenceData = {
      ...req.validatedData,
      leave_category: req.validatedData.absence_reason,
      leave_start_date: req.validatedData.start_date,
      leave_end_date: req.validatedData.end_date,
      documented_by: req.user.id,
      approval_status: req.user.role === 'system_admin' ? 'approved' : 'pending',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('leave_requests')
      .insert([absenceData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Create absence error:', error);
    res.status(500).json({ error: 'Failed to create absence record' });
  }
});

app.put('/api/absences/:id', authenticateToken, checkPermission('staff_absence', 'update'), validate(schemas.absence), withAudit('UPDATE', 'staff_absence'), async (req, res) => {
  try {
    const absenceData = {
      ...req.validatedData,
      leave_category: req.validatedData.absence_reason,
      leave_start_date: req.validatedData.start_date,
      leave_end_date: req.validatedData.end_date,
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('leave_requests')
      .update(absenceData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Absence record not found' });
      }
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update absence error:', error);
    res.status(500).json({ error: 'Failed to update absence record' });
  }
});

app.put('/api/absences/:id/approve', authenticateToken, checkPermission('staff_absence', 'update'), async (req, res) => {
  try {
    const { approved, rejection_reason } = req.body;
    
    const updateData = {
      approval_status: approved ? 'approved' : 'rejected',
      rejection_reason: !approved ? rejection_reason : null,
      reviewed_by: req.user.id,
      reviewed_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('leave_requests')
      .update(updateData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) throw error;
    
    await auditLog(req, 'APPROVE', 'staff_absence', { 
      absenceId: req.params.id, 
      status: updateData.approval_status 
    });
    
    res.json(data);
  } catch (error) {
    console.error('Approve absence error:', error);
    res.status(500).json({ error: 'Failed to update absence status' });
  }
});

app.put('/api/absences/:id/coverage', authenticateToken, checkPermission('staff_absence', 'update'), async (req, res) => {
  try {
    const { replacement_staff_id, coverage_instructions } = req.body;
    
    const coverageData = {
      replacement_staff_id: replacement_staff_id || null,
      coverage_instructions: coverage_instructions || '',
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('leave_requests')
      .update(coverageData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Update coverage error:', error);
    res.status(500).json({ error: 'Failed to update coverage' });
  }
});

app.delete('/api/absences/:id', authenticateToken, checkPermission('staff_absence', 'delete'), withAudit('DELETE', 'staff_absence'), async (req, res) => {
  try {
    const { error } = await supabase
      .from('leave_requests')
      .delete()
      .eq('id', req.params.id);
    
    if (error) throw error;
    
    res.json({ message: 'Absence record deleted successfully' });
  } catch (error) {
    console.error('Delete absence error:', error);
    res.status(500).json({ error: 'Failed to delete absence record' });
  }
});

// ===== COMMUNICATIONS =====
app.get('/api/announcements', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    
    const { data, error } = await supabase
      .from('department_announcements')
      .select(`
        *,
        created_by_user:app_users(full_name, email)
      `)
      .lte('publish_start_date', today)
      .or(`publish_end_date.gte.${today},publish_end_date.is.null`)
      .order('publish_start_date', { ascending: false });
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('Announcements error:', error);
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

app.post('/api/announcements', authenticateToken, checkPermission('communications', 'create'), validate(schemas.announcement), withAudit('CREATE', 'communications'), async (req, res) => {
  try {
    const announcementData = {
      ...req.validatedData,
      announcement_id: generateId('ANN'),
      announcement_type: 'department',
      created_by: req.user.id,
      created_by_name: req.user.email,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('department_announcements')
      .insert([announcementData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Create announcement error:', error);
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

app.delete('/api/announcements/:id', authenticateToken, checkPermission('communications', 'delete'), withAudit('DELETE', 'communications'), async (req, res) => {
  try {
    const { error } = await supabase
      .from('department_announcements')
      .delete()
      .eq('id', req.params.id);
    
    if (error) throw error;
    
    res.json({ message: 'Announcement deleted successfully' });
  } catch (error) {
    console.error('Delete announcement error:', error);
    res.status(500).json({ error: 'Failed to delete announcement' });
  }
});

// ===== AUDIT LOGS =====
app.get('/api/audit-logs', authenticateToken, checkPermission('audit', 'read'), async (req, res) => {
  try {
    const { 
      dateRange, 
      actionType, 
      userId,
      resource,
      page = 1,
      limit = 50
    } = req.query;
    
    const offset = (page - 1) * limit;
    
    let query = supabase
      .from('audit_logs')
      .select(`
        *,
        user:app_users(full_name, email)
      `, { count: 'exact' })
      .order('created_at', { ascending: false });
    
    if (dateRange) {
      const startDate = new Date(dateRange);
      const endDate = new Date(dateRange);
      endDate.setDate(endDate.getDate() + 1);
      query = query.gte('created_at', startDate.toISOString())
                   .lt('created_at', endDate.toISOString());
    }
    if (actionType) query = query.eq('action', actionType);
    if (userId) query = query.eq('user_id', userId);
    if (resource) query = query.eq('resource', resource);
    
    query = query.range(offset, offset + limit - 1);
    
    const { data, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      data: data || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limit)
      }
    });
  } catch (error) {
    console.error('Audit logs error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// ===== SYSTEM SETTINGS =====
app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('system_settings')
      .select('*')
      .limit(1)
      .single();
    
    if (error) {
      // Return default settings if none exist
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
        announcement_notifications: true
      });
    }
    
    res.json(data);
  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).json({ error: 'Failed to fetch system settings' });
  }
});

app.put('/api/settings', authenticateToken, checkPermission('system', 'update'), validate(schemas.systemSettings), withAudit('UPDATE', 'system_settings'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('system_settings')
      .upsert([req.validatedData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ error: 'Failed to update system settings' });
  }
});

// ===== PERMISSIONS =====
app.get('/api/permissions', authenticateToken, checkPermission('permissions', 'manage'), async (req, res) => {
  try {
    const { data: roles, error } = await supabase
      .from('system_roles')
      .select('*');
    
    if (error) throw error;
    
    const availablePermissions = Object.entries(PERMISSIONS).map(([roleKey, role]) => ({
      role: roleKey,
      name: role.name,
      permissions: role.permissions
    }));
    
    res.json({
      roles: roles || [],
      availablePermissions,
      defaultRoles: Object.keys(PERMISSIONS)
    });
  } catch (error) {
    console.error('Permissions error:', error);
    res.status(500).json({ error: 'Failed to fetch permissions' });
  }
});

// ===== USERS MANAGEMENT =====
app.get('/api/users', authenticateToken, checkPermission('permissions', 'manage'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('app_users')
      .select(`
        id,
        email,
        full_name,
        user_role,
        department_id,
        phone_number,
        account_status,
        last_login,
        created_at,
        departments(name)
      `)
      .order('full_name');
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('Users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ===== NOTIFICATIONS =====
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('user_notifications')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('read', false)
      .order('created_at', { ascending: false })
      .limit(20);
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const { error } = await supabase
      .from('user_notifications')
      .update({ 
        read: true, 
        read_at: new Date().toISOString() 
      })
      .eq('id', req.params.id)
      .eq('user_id', req.user.id);
    
    if (error) throw error;
    
    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ error: 'Failed to update notification' });
  }
});

// ===== EXPORT DATA =====
app.get('/api/export/:table', authenticateToken, async (req, res) => {
  try {
    const { table } = req.params;
    const { format = 'json', start_date, end_date } = req.query;
    
    // Allowed tables for export
    const allowedTables = [
      'medical_staff', 'resident_rotations', 'leave_requests',
      'oncall_schedule', 'department_announcements', 'audit_logs'
    ];
    
    if (!allowedTables.includes(table)) {
      return res.status(400).json({ 
        error: 'Invalid table',
        message: `Export not allowed for table: ${table}` 
      });
    }
    
    let query = supabase.from(table).select('*');
    
    if (start_date && end_date) {
      // Determine date field based on table
      const dateField = table === 'audit_logs' ? 'created_at' :
                       table === 'leave_requests' ? 'leave_start_date' :
                       table === 'oncall_schedule' ? 'duty_date' :
                       table === 'resident_rotations' ? 'start_date' :
                       'created_at';
      
      query = query.gte(dateField, start_date).lte(dateField, end_date);
    }
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    if (format === 'csv') {
      // For CSV, you'd need a library like json2csv
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${table}_export_${Date.now()}.csv"`);
      
      // Simple CSV conversion
      if (data && data.length > 0) {
        const headers = Object.keys(data[0]).join(',');
        const rows = data.map(row => 
          Object.values(row).map(value => 
            typeof value === 'string' ? `"${value.replace(/"/g, '""')}"` : value
          ).join(',')
        );
        res.send([headers, ...rows].join('\n'));
      } else {
        res.send('');
      }
    } else {
      res.json(data || []);
    }
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Failed to export data' });
  }
});

// ===== LIVE STATS =====
app.get('/api/live-stats', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    
    const [
      occupancyResult,
      staffResult,
      pendingResult,
      onCallResult
    ] = await Promise.all([
      supabase.from('patient_census').select('current_occupancy, max_capacity').single(),
      supabase.from('medical_staff').select('id', { count: 'exact', head: true }).eq('employment_status', 'active'),
      supabase.from('leave_requests').select('id', { count: 'exact', head: true }).eq('approval_status', 'pending'),
      supabase.from('oncall_schedule').select('id', { count: 'exact', head: true }).eq('duty_date', today)
    ]);
    
    const occupancy = occupancyResult.data 
      ? Math.round((occupancyResult.data.current_occupancy / occupancyResult.data.max_capacity) * 100)
      : 65;
    
    res.json({
      occupancy,
      occupancyTrend: 2, // This could be calculated from historical data
      onDutyStaff: staffResult.count || 0,
      staffTrend: 0,
      pendingRequests: pendingResult.count || 0,
      erCapacity: { current: 12, max: 20, status: 'medium' },
      icuCapacity: { current: 6, max: 10, status: 'low' },
      todayOnCall: onCallResult.count || 0,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Live stats error:', error);
    res.status(500).json({ error: 'Failed to fetch live statistics' });
  }
});

// ===== AVAILABLE DATA FOR SELECT OPTIONS =====
app.get('/api/available-data', authenticateToken, async (req, res) => {
  try {
    const [departments, residents, attendings, trainingUnits] = await Promise.all([
      supabase.from('departments').select('id, name, code').eq('status', 'active').order('name'),
      supabase.from('medical_staff').select('id, full_name, training_level').eq('staff_type', 'medical_resident').eq('employment_status', 'active').order('full_name'),
      supabase.from('medical_staff').select('id, full_name, specialization').eq('staff_type', 'attending_physician').eq('employment_status', 'active').order('full_name'),
      supabase.from('training_units').select('id, unit_name, unit_code, max_capacity').eq('status', 'active').order('unit_name')
    ]);
    
    res.json({
      departments: departments.data || [],
      residents: residents.data || [],
      attendings: attendings.data || [],
      trainingUnits: trainingUnits.data || []
    });
  } catch (error) {
    console.error('Available data error:', error);
    res.status(500).json({ error: 'Failed to fetch available data' });
  }
});

// ============ ERROR HANDLING ============
// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The requested endpoint ${req.originalUrl} does not exist`,
    availableEndpoints: [
      '/api/auth/login',
      '/api/dashboard/stats',
      '/api/medical-staff',
      '/api/departments',
      '/api/training-units',
      '/api/rotations',
      '/api/oncall',
      '/api/absences',
      '/api/announcements',
      '/api/settings',
      '/api/health'
    ]
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] [${req.requestId || 'unknown'}] Error:`, {
    message: err.message,
    stack: NODE_ENV === 'development' ? err.stack : undefined,
    url: req.url,
    method: req.method,
    user: req.user?.id
  });
  
  // Supabase errors
  if (err.message?.includes('JWT')) {
    return res.status(401).json({ 
      error: 'Authentication error',
      message: 'Invalid or expired authentication token' 
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ 
      error: 'Invalid token',
      message: 'Authentication token is invalid' 
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ 
      error: 'Token expired',
      message: 'Authentication token has expired' 
    });
  }
  
  // Default error
  res.status(500).json({
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? err.message : 'An unexpected error occurred',
    requestId: req.requestId
  });
});

// ============ SERVER START ============
const server = app.listen(PORT, () => {
  console.log(`
    ============================================
    🏥 NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API
    ============================================
    ✅ Server running on port: ${PORT}
    ✅ Environment: ${NODE_ENV}
    ✅ Supabase connected: ${SUPABASE_URL ? 'Yes' : 'No'}
    ✅ Health check: http://localhost:${PORT}/health
    ============================================
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

module.exports = app;
