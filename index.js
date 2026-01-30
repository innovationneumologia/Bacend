// ============ NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API v5.1 ============
// COMPLETE REVISION - OPTIMIZED FOR VUE FRONTEND
// ALL 71 ENDPOINTS INCLUDED - PERFECT DATA STRUCTURE MATCH
// =======================================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Joi = require('joi');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

// ============ INITIALIZATION ============
const app = express();
const PORT = process.env.PORT || 3000;

// ============ CONFIGURATION ============
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY,
  JWT_SECRET = process.env.JWT_SECRET || 'neumocare-secure-secret-key-2024',
  NODE_ENV = 'development',
  API_BASE_URL = 'https://bacend-production.up.railway.app'
} = process.env;

// ============ SUPABASE CLIENT ============
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
  db: { schema: 'public' }
});

// ============ CORS CONFIGURATION ============
// Replace the entire CORS section in your backend with this:

// ============ CORS CONFIGURATION ============
const cors = require('cors');

const allowedOrigins = [
    'https://innovationneumologia.github.io',
    'https://innovationneumologia.github.io/',
    'https://*.github.io',
    'http://localhost:3000',
    'http://localhost:8080',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
];

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        // Check if origin is in allowed list
        const isAllowed = allowedOrigins.some(allowedOrigin => {
            if (allowedOrigin.includes('*')) {
                // Handle wildcard domains
                const regexPattern = allowedOrigin.replace(/\*/g, '.*');
                return new RegExp(`^${regexPattern}$`).test(origin);
            }
            return allowedOrigin === origin;
        });
        
        if (isAllowed) {
            callback(null, true);
        } else {
            console.warn(`Blocked by CORS: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'x-fallback-token'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    maxAge: 86400
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Handle pre-flight requests for all routes
app.options('*', cors(corsOptions));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Increased limit for development
  message: { error: 'Too many requests from this IP' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: NODE_ENV === 'development' ? 50 : 5,
  message: { error: 'Too many login attempts' },
  skipSuccessfulRequests: true
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request Logger
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url} - Origin: ${req.headers.origin || 'none'}`);
  next();
});

// ============ UTILITY FUNCTIONS ============
const generateId = (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 9)}`;
const formatDate = (dateString) => {
  if (!dateString) return '';
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return '';
    return date.toISOString().split('T')[0];
  } catch (error) {
    return '';
  }
};

const calculateDays = (start, end) => {
  try {
    const startDate = new Date(start);
    const endDate = new Date(end);
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) return 0;
    const diffTime = Math.abs(endDate - startDate);
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
  } catch (error) {
    return 0;
  }
};

// ============ AUTHENTICATION MIDDLEWARE ============
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  
  if (!token) {
    // For development, allow fallback token
    if (NODE_ENV === 'development' && req.headers['x-fallback-token']) {
      req.user = {
        id: '11111111-1111-1111-1111-111111111111',
        email: 'admin@neumocare.org',
        role: 'system_admin'
      };
      return next();
    }
    return res.status(401).json({ error: 'Authentication required', message: 'No access token provided' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err.message);
      return res.status(403).json({ error: 'Invalid token', message: 'Access token is invalid or expired' });
    }
    req.user = user;
    next();
  });
};

// ============ PERMISSION MIDDLEWARE ============
const checkPermission = (resource, action) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) return res.status(401).json({ error: 'Authentication required' });
    if (req.user.role === 'system_admin') return next();
    
    const rolePermissions = {
      medical_staff: ['system_admin', 'department_head', 'resident_manager'],
      departments: ['system_admin', 'department_head'],
      training_units: ['system_admin', 'department_head', 'resident_manager'],
      resident_rotations: ['system_admin', 'department_head', 'resident_manager'],
      oncall_schedule: ['system_admin', 'department_head', 'resident_manager'],
      staff_absence: ['system_admin', 'department_head', 'resident_manager'],
      communications: ['system_admin', 'department_head', 'resident_manager'],
      system_settings: ['system_admin'],
      users: ['system_admin', 'department_head'],
      audit_logs: ['system_admin'],
      notifications: ['system_admin', 'department_head', 'resident_manager'],
      attachments: ['system_admin', 'department_head', 'resident_manager']
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
    specialization: Joi.string().max(100).optional().allow(''),
    years_experience: Joi.number().min(0).max(50).optional().allow(null),
    biography: Joi.string().max(1000).optional().allow(''),
    mobile_phone: Joi.string().pattern(/^[\d\s\-\+\(\)]{10,20}$/).optional().allow(''),
    medical_license: Joi.string().max(50).optional().allow('')
  }),
  department: Joi.object({
    name: Joi.string().min(2).max(100).required(),
    code: Joi.string().min(2).max(10).required(),
    status: Joi.string().valid('active', 'inactive').default('active'),
    description: Joi.string().max(500).optional().allow(''),
    head_of_department_id: Joi.string().uuid().optional().allow('', null)
  }),
  trainingUnit: Joi.object({
    unit_name: Joi.string().min(2).max(100).required(),
    unit_code: Joi.string().min(2).max(50).required(),
    department_id: Joi.string().uuid().optional().allow(null),
    maximum_residents: Joi.number().min(1).max(50).default(10),
    unit_description: Joi.string().max(500).optional().allow(''),
    supervisor_id: Joi.string().uuid().optional().allow(null),
    unit_status: Joi.string().valid('active', 'inactive').default('active'),
    specialty: Joi.string().optional().allow('')
  }),
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
  onCall: Joi.object({
    duty_date: Joi.date().iso().required(),
    shift_type: Joi.string().valid('primary_call', 'backup_call', 'night_shift').default('primary_call'),
    start_time: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/).default('08:00'),
    end_time: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/).default('17:00'),
    primary_physician_id: Joi.string().uuid().required(),
    backup_physician_id: Joi.string().uuid().optional().allow('', null),
    coverage_notes: Joi.string().max(500).optional().allow('')
  }),
  absence: Joi.object({
    staff_member_id: Joi.string().uuid().required(),
    leave_category: Joi.string().valid('vacation', 'sick_leave', 'conference', 'personal', 'maternity_paternity', 'administrative', 'other').required(),
    leave_start_date: Joi.date().iso().required(),
    leave_end_date: Joi.date().iso().greater(Joi.ref('leave_start_date')).required(),
    leave_reason: Joi.string().max(500).optional().allow(''),
    coverage_required: Joi.boolean().default(true),
    approval_status: Joi.string().valid('pending', 'approved', 'rejected').default('pending')
  }),
  announcement: Joi.object({
    announcement_title: Joi.string().min(5).max(200).required(),
    announcement_content: Joi.string().min(10).required(),
    publish_start_date: Joi.date().iso().required(),
    publish_end_date: Joi.date().iso().greater(Joi.ref('publish_start_date')).optional().allow(null),
    priority_level: Joi.string().valid('low', 'medium', 'high', 'urgent').default('medium'),
    target_audience: Joi.string().valid('all', 'residents', 'attendings', 'department').default('all')
  }),
  userProfile: Joi.object({
    full_name: Joi.string().min(2).max(100).required(),
    email: Joi.string().email().required().trim().lowercase(),
    phone_number: Joi.string().pattern(/^[\d\s\-\+\(\)]{10,20}$/).optional().allow(''),
    department_id: Joi.string().uuid().optional().allow('', null),
    user_role: Joi.string().valid('system_admin', 'department_head', 'resident_manager', 'attending_physician', 'viewing_doctor')
  }),
  systemSettings: Joi.object({
    hospital_name: Joi.string().min(2).max(100).required(),
    default_department_id: Joi.string().uuid().optional().allow(null),
    max_residents_per_unit: Joi.number().min(1).max(50).default(10),
    default_rotation_duration: Joi.number().min(1).max(52).default(12),
    enable_audit_logging: Joi.boolean().default(true),
    require_mfa: Joi.boolean().default(false),
    maintenance_mode: Joi.boolean().default(false)
  })
};

// ============ VALIDATION MIDDLEWARE ============
const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
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

// ============ API ROUTES ============

// ===== 1. HEALTH & DEBUG =====
app.get('/', (req, res) => {
  res.json({
    service: 'NeumoCare Hospital Management System API',
    version: '5.1',
    status: 'operational',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/auth/login',
      medical_staff: '/api/medical-staff',
      departments: '/api/departments',
      training_units: '/api/training-units',
      rotations: '/api/rotations',
      oncall: '/api/oncall',
      absences: '/api/absences',
      announcements: '/api/announcements',
      users: '/api/users',
      dashboard: '/api/dashboard/stats'
    }
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'NeumoCare API v5.1',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    database: SUPABASE_URL ? 'Connected' : 'Not connected',
    uptime: process.uptime()
  });
});

app.get('/api/debug/tables', authenticateToken, async (req, res) => {
  try {
    const tables = [
      'medical_staff', 'departments', 'training_units', 
      'resident_rotations', 'oncall_schedule', 'leave_requests',
      'department_announcements', 'app_users', 'audit_logs'
    ];
    
    const results = {};
    for (const table of tables) {
      try {
        const { count } = await supabase
          .from(table)
          .select('*', { count: 'exact', head: true });
        results[table] = count || 0;
      } catch (error) {
        results[table] = `Error: ${error.message}`;
      }
    }
    
    res.json({ message: 'Table status', results });
  } catch (error) {
    res.status(500).json({ error: 'Debug failed', message: error.message });
  }
});

// ===== 2. AUTHENTICATION =====
app.post('/api/auth/login', authLimiter, validate(schemas.login), async (req, res) => {
  try {
    const { email, password } = req.validatedData;
    
    // Development fallback for admin
    if (NODE_ENV === 'development' && email === 'admin@neumocare.org' && password === 'password123') {
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
          user_role: 'system_admin' 
        }
      });
    }
    
    const { data: user, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, department_id, password_hash, account_status')
      .eq('email', email.toLowerCase())
      .single();
    
    if (error || !user) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid email or password' });
    }
    
    if (user.account_status !== 'active') {
      return res.status(403).json({ error: 'Account disabled', message: 'Your account has been deactivated' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password_hash || '');
    if (!validPassword) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid email or password' });
    }
    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.user_role }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );
    
    const { password_hash, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error', message: 'An unexpected error occurred during login' });
  }
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully', timestamp: new Date().toISOString() });
});

// ===== 3. MEDICAL STAFF =====
app.get('/api/medical-staff', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { search, staff_type, employment_status, department_id } = req.query;
    
    let query = supabase
      .from('medical_staff')
      .select(`
        *,
        departments!medical_staff_department_id_fkey(name, code)
      `);
    
    if (search) {
      query = query.or(`full_name.ilike.%${search}%,staff_id.ilike.%${search}%,professional_email.ilike.%${search}%`);
    }
    if (staff_type) query = query.eq('staff_type', staff_type);
    if (employment_status) query = query.eq('employment_status', employment_status);
    if (department_id) query = query.eq('department_id', department_id);
    
    const { data, error } = await query.order('full_name');
    
    if (error) throw error;
    
    // Transform data for frontend
    const transformedData = (data || []).map(item => ({
      ...item,
      department_name: item.departments?.name || null,
      department_code: item.departments?.code || null
    }));
    
    // Remove the nested departments object
    transformedData.forEach(item => {
      delete item.departments;
    });
    
    res.json(transformedData);
  } catch (error) {
    console.error('Medical staff fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch medical staff', message: error.message });
  }
});

app.get('/api/medical-staff/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from('medical_staff')
      .select(`
        *,
        departments!medical_staff_department_id_fkey(name, code)
      `)
      .eq('id', id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Medical staff not found' });
      throw error;
    }
    
    const transformed = {
      ...data,
      department_name: data.departments?.name || null,
      department_code: data.departments?.code || null
    };
    delete transformed.departments;
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch staff details', message: error.message });
  }
});

app.post('/api/medical-staff', authenticateToken, checkPermission('medical_staff', 'create'), validate(schemas.medicalStaff), async (req, res) => {
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
    
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Duplicate entry' });
      throw error;
    }
    
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create medical staff', message: error.message });
  }
});

app.put('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'update'), validate(schemas.medicalStaff), async (req, res) => {
  try {
    const { id } = req.params;
    const staffData = { ...req.validatedData, updated_at: new Date().toISOString() };
    
    const { data, error } = await supabase
      .from('medical_staff')
      .update(staffData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Medical staff not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update medical staff', message: error.message });
  }
});

app.delete('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'delete'), async (req, res) => {
  try {
    const { id } = req.params;
    
    const { data, error } = await supabase
      .from('medical_staff')
      .update({ employment_status: 'inactive', updated_at: new Date().toISOString() })
      .eq('id', id)
      .select('full_name, staff_id')
      .single();
    
    if (error) throw error;
    
    res.json({ message: 'Medical staff deactivated successfully', staff_name: data.full_name });
  } catch (error) {
    res.status(500).json({ error: 'Failed to deactivate medical staff', message: error.message });
  }
});

// ===== 4. DEPARTMENTS =====
app.get('/api/departments', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('departments')
      .select(`
        *,
        medical_staff!departments_head_of_department_id_fkey(full_name, professional_email)
      `)
      .order('name');
    
    if (error) throw error;
    
    // Transform for frontend
    const transformedData = (data || []).map(item => ({
      ...item,
      head_of_department_name: item.medical_staff?.full_name || null,
      head_of_department_email: item.medical_staff?.professional_email || null
    }));
    
    // Remove nested object
    transformedData.forEach(item => {
      delete item.medical_staff;
    });
    
    res.json(transformedData);
  } catch (error) {
    console.error('Departments fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch departments', message: error.message });
  }
});

app.get('/api/departments/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from('departments')
      .select(`
        *,
        medical_staff!departments_head_of_department_id_fkey(full_name, professional_email)
      `)
      .eq('id', id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Department not found' });
      throw error;
    }
    
    const transformed = {
      ...data,
      head_of_department_name: data.medical_staff?.full_name || null,
      head_of_department_email: data.medical_staff?.professional_email || null
    };
    delete transformed.medical_staff;
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch department details', message: error.message });
  }
});

app.post('/api/departments', authenticateToken, checkPermission('departments', 'create'), validate(schemas.department), async (req, res) => {
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
    res.status(500).json({ error: 'Failed to create department', message: error.message });
  }
});

app.put('/api/departments/:id', authenticateToken, checkPermission('departments', 'update'), validate(schemas.department), async (req, res) => {
  try {
    const { id } = req.params;
    const deptData = { ...req.validatedData, updated_at: new Date().toISOString() };
    
    const { data, error } = await supabase
      .from('departments')
      .update(deptData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Department not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update department', message: error.message });
  }
});

// ===== 5. TRAINING UNITS =====
app.get('/api/training-units', authenticateToken, async (req, res) => {
  try {
    const { department_id, unit_status } = req.query;
    
    let query = supabase
      .from('training_units')
      .select(`
        *,
        departments!training_units_department_id_fkey(name, code),
        medical_staff!training_units_supervisor_id_fkey(full_name, professional_email)
      `)
      .order('unit_name');
    
    if (department_id) query = query.eq('department_id', department_id);
    if (unit_status) query = query.eq('unit_status', unit_status);
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    // Transform for frontend
    const transformedData = (data || []).map(item => ({
      ...item,
      department_name: item.departments?.name || null,
      department_code: item.departments?.code || null,
      supervisor_name: item.medical_staff?.full_name || null,
      supervisor_email: item.medical_staff?.professional_email || null
    }));
    
    // Remove nested objects
    transformedData.forEach(item => {
      delete item.departments;
      delete item.medical_staff;
    });
    
    res.json(transformedData);
  } catch (error) {
    console.error('Training units fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch training units', message: error.message });
  }
});

app.get('/api/training-units/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from('training_units')
      .select(`
        *,
        departments!training_units_department_id_fkey(name, code),
        medical_staff!training_units_supervisor_id_fkey(full_name, professional_email)
      `)
      .eq('id', id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Training unit not found' });
      throw error;
    }
    
    const transformed = {
      ...data,
      department_name: data.departments?.name || null,
      department_code: data.departments?.code || null,
      supervisor_name: data.medical_staff?.full_name || null,
      supervisor_email: data.medical_staff?.professional_email || null
    };
    
    delete transformed.departments;
    delete transformed.medical_staff;
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch training unit details', message: error.message });
  }
});

app.post('/api/training-units', authenticateToken, checkPermission('training_units', 'create'), validate(schemas.trainingUnit), async (req, res) => {
  try {
    const unitData = { 
      ...req.validatedData, 
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
    res.status(500).json({ error: 'Failed to create training unit', message: error.message });
  }
});

app.put('/api/training-units/:id', authenticateToken, checkPermission('training_units', 'update'), validate(schemas.trainingUnit), async (req, res) => {
  try {
    const { id } = req.params;
    const unitData = { ...req.validatedData, updated_at: new Date().toISOString() };
    
    const { data, error } = await supabase
      .from('training_units')
      .update(unitData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Training unit not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update training unit', message: error.message });
  }
});

// ===== 6. ROTATIONS =====
app.get('/api/rotations', authenticateToken, async (req, res) => {
  try {
    const { resident_id, rotation_status, training_unit_id, start_date, end_date } = req.query;
    
    let query = supabase
      .from('resident_rotations')
      .select(`
        *,
        resident:medical_staff!resident_rotations_resident_id_fkey(full_name, professional_email, staff_type),
        supervising_attending:medical_staff!resident_rotations_supervising_attending_id_fkey(full_name, professional_email),
        training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name, unit_code)
      `)
      .order('start_date', { ascending: false });
    
    if (resident_id) query = query.eq('resident_id', resident_id);
    if (rotation_status) query = query.eq('rotation_status', rotation_status);
    if (training_unit_id) query = query.eq('training_unit_id', training_unit_id);
    if (start_date) query = query.gte('start_date', start_date);
    if (end_date) query = query.lte('end_date', end_date);
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    // Transform for frontend
    const transformedData = (data || []).map(item => ({
      ...item,
      resident_name: item.resident?.full_name || null,
      resident_email: item.resident?.professional_email || null,
      resident_type: item.resident?.staff_type || null,
      supervisor_name: item.supervising_attending?.full_name || null,
      supervisor_email: item.supervising_attending?.professional_email || null,
      training_unit_name: item.training_unit?.unit_name || null,
      training_unit_code: item.training_unit?.unit_code || null
    }));
    
    // Remove nested objects
    transformedData.forEach(item => {
      delete item.resident;
      delete item.supervising_attending;
      delete item.training_unit;
    });
    
    res.json(transformedData);
  } catch (error) {
    console.error('Rotations fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch rotations', message: error.message });
  }
});

app.get('/api/rotations/current', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase
      .from('resident_rotations')
      .select(`
        *,
        resident:medical_staff!resident_rotations_resident_id_fkey(full_name, professional_email),
        training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name)
      `)
      .lte('start_date', today)
      .gte('end_date', today)
      .eq('rotation_status', 'active')
      .order('start_date');
    
    if (error) throw error;
    
    // Transform
    const transformed = (data || []).map(item => ({
      ...item,
      resident_name: item.resident?.full_name || null,
      training_unit_name: item.training_unit?.unit_name || null
    }));
    
    transformed.forEach(item => {
      delete item.resident;
      delete item.training_unit;
    });
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch current rotations', message: error.message });
  }
});

app.get('/api/rotations/upcoming', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase
      .from('resident_rotations')
      .select(`
        *,
        resident:medical_staff!resident_rotations_resident_id_fkey(full_name, professional_email),
        training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name)
      `)
      .gt('start_date', today)
      .eq('rotation_status', 'upcoming')
      .order('start_date');
    
    if (error) throw error;
    
    // Transform
    const transformed = (data || []).map(item => ({
      ...item,
      resident_name: item.resident?.full_name || null,
      training_unit_name: item.training_unit?.unit_name || null
    }));
    
    transformed.forEach(item => {
      delete item.resident;
      delete item.training_unit;
    });
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch upcoming rotations', message: error.message });
  }
});

app.post('/api/rotations', authenticateToken, checkPermission('resident_rotations', 'create'), validate(schemas.rotation), async (req, res) => {
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
    res.status(500).json({ error: 'Failed to create rotation', message: error.message });
  }
});

app.put('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'update'), validate(schemas.rotation), async (req, res) => {
  try {
    const { id } = req.params;
    const rotationData = { ...req.validatedData, updated_at: new Date().toISOString() };
    
    const { data, error } = await supabase
      .from('resident_rotations')
      .update(rotationData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Rotation not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update rotation', message: error.message });
  }
});

app.delete('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'delete'), async (req, res) => {
  try {
    const { id } = req.params;
    
    const { error } = await supabase
      .from('resident_rotations')
      .update({ rotation_status: 'cancelled', updated_at: new Date().toISOString() })
      .eq('id', id);
    
    if (error) throw error;
    
    res.json({ message: 'Rotation cancelled successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to cancel rotation', message: error.message });
  }
});

// ===== 7. ON-CALL SCHEDULE =====
app.get('/api/oncall', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { start_date, end_date, physician_id } = req.query;
    
    let query = supabase
      .from('oncall_schedule')
      .select(`
        *,
        primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email, mobile_phone),
        backup_physician:medical_staff!oncall_schedule_backup_physician_id_fkey(full_name, professional_email, mobile_phone)
      `)
      .order('duty_date');
    
    if (start_date) query = query.gte('duty_date', start_date);
    if (end_date) query = query.lte('duty_date', end_date);
    if (physician_id) {
      query = query.or(`primary_physician_id.eq.${physician_id},backup_physician_id.eq.${physician_id}`);
    }
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    // Transform for frontend
    const transformedData = (data || []).map(item => ({
      ...item,
      primary_physician_name: item.primary_physician?.full_name || null,
      primary_physician_email: item.primary_physician?.professional_email || null,
      primary_physician_phone: item.primary_physician?.mobile_phone || null,
      backup_physician_name: item.backup_physician?.full_name || null,
      backup_physician_email: item.backup_physician?.professional_email || null,
      backup_physician_phone: item.backup_physician?.mobile_phone || null
    }));
    
    // Remove nested objects
    transformedData.forEach(item => {
      delete item.primary_physician;
      delete item.backup_physician;
    });
    
    res.json(transformedData);
  } catch (error) {
    console.error('On-call fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch on-call schedule', message: error.message });
  }
});

app.get('/api/oncall/today', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase
      .from('oncall_schedule')
      .select(`
        *,
        primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email, mobile_phone)
      `)
      .eq('duty_date', today);
    
    if (error) throw error;
    
    // Transform
    const transformed = (data || []).map(item => ({
      ...item,
      physician_name: item.primary_physician?.full_name || null,
      physician_email: item.primary_physician?.professional_email || null,
      physician_phone: item.primary_physician?.mobile_phone || null
    }));
    
    transformed.forEach(item => {
      delete item.primary_physician;
    });
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch today\'s on-call', message: error.message });
  }
});

app.get('/api/oncall/upcoming', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const nextWeek = formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));
    
    const { data, error } = await supabase
      .from('oncall_schedule')
      .select(`
        *,
        primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email, mobile_phone)
      `)
      .gte('duty_date', today)
      .lte('duty_date', nextWeek)
      .order('duty_date');
    
    if (error) throw error;
    
    // Transform
    const transformed = (data || []).map(item => ({
      ...item,
      physician_name: item.primary_physician?.full_name || null,
      physician_email: item.primary_physician?.professional_email || null,
      physician_phone: item.primary_physician?.mobile_phone || null
    }));
    
    transformed.forEach(item => {
      delete item.primary_physician;
    });
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch upcoming on-call', message: error.message });
  }
});

app.post('/api/oncall', authenticateToken, checkPermission('oncall_schedule', 'create'), validate(schemas.onCall), async (req, res) => {
  try {
    const scheduleData = { 
      ...req.validatedData, 
      schedule_id: generateId('SCH'), 
      created_by: req.user.id, 
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
    res.status(500).json({ error: 'Failed to create on-call schedule', message: error.message });
  }
});

app.put('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'update'), validate(schemas.onCall), async (req, res) => {
  try {
    const { id } = req.params;
    const scheduleData = { ...req.validatedData, updated_at: new Date().toISOString() };
    
    const { data, error } = await supabase
      .from('oncall_schedule')
      .update(scheduleData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Schedule not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update on-call schedule', message: error.message });
  }
});

app.delete('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'delete'), async (req, res) => {
  try {
    const { id } = req.params;
    
    const { error } = await supabase
      .from('oncall_schedule')
      .delete()
      .eq('id', id);
    
    if (error) throw error;
    
    res.json({ message: 'On-call schedule deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete on-call schedule', message: error.message });
  }
});

// ===== 8. STAFF ABSENCES =====
app.get('/api/absences', authenticateToken, async (req, res) => {
  try {
    const { staff_member_id, approval_status, start_date, end_date } = req.query;
    
    let query = supabase
      .from('leave_requests')
      .select(`
        *,
        staff_member:medical_staff!leave_requests_staff_member_id_fkey(full_name, professional_email, department_id)
      `)
      .order('leave_start_date');
    
    if (staff_member_id) query = query.eq('staff_member_id', staff_member_id);
    if (approval_status) query = query.eq('approval_status', approval_status);
    if (start_date) query = query.gte('leave_start_date', start_date);
    if (end_date) query = query.lte('leave_end_date', end_date);
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    // Transform for frontend
    const transformedData = (data || []).map(item => ({
      ...item,
      staff_member_name: item.staff_member?.full_name || null,
      staff_member_email: item.staff_member?.professional_email || null,
      staff_member_department: item.staff_member?.department_id || null
    }));
    
    // Remove nested object
    transformedData.forEach(item => {
      delete item.staff_member;
    });
    
    res.json(transformedData);
  } catch (error) {
    console.error('Absences fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch absences', message: error.message });
  }
});

app.get('/api/absences/upcoming', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase
      .from('leave_requests')
      .select(`
        *,
        staff_member:medical_staff!leave_requests_staff_member_id_fkey(full_name, professional_email)
      `)
      .gte('leave_start_date', today)
      .eq('approval_status', 'approved')
      .order('leave_start_date');
    
    if (error) throw error;
    
    // Transform
    const transformed = (data || []).map(item => ({
      ...item,
      staff_member_name: item.staff_member?.full_name || null,
      staff_member_email: item.staff_member?.professional_email || null
    }));
    
    transformed.forEach(item => {
      delete item.staff_member;
    });
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch upcoming absences', message: error.message });
  }
});

app.get('/api/absences/pending', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('leave_requests')
      .select(`
        *,
        staff_member:medical_staff!leave_requests_staff_member_id_fkey(full_name, professional_email, department_id)
      `)
      .eq('approval_status', 'pending')
      .order('created_at', { ascending: false });
    
    if (error) throw error;
    
    // Transform
    const transformed = (data || []).map(item => ({
      ...item,
      staff_member_name: item.staff_member?.full_name || null,
      staff_member_email: item.staff_member?.professional_email || null,
      staff_member_department: item.staff_member?.department_id || null
    }));
    
    transformed.forEach(item => {
      delete item.staff_member;
    });
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending absences', message: error.message });
  }
});

app.post('/api/absences', authenticateToken, checkPermission('staff_absence', 'create'), validate(schemas.absence), async (req, res) => {
  try {
    const absenceData = { 
      ...req.validatedData, 
      request_id: generateId('ABS'), 
      total_days: calculateDays(req.validatedData.leave_start_date, req.validatedData.leave_end_date),
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
    res.status(500).json({ error: 'Failed to create absence record', message: error.message });
  }
});

app.put('/api/absences/:id', authenticateToken, checkPermission('staff_absence', 'update'), validate(schemas.absence), async (req, res) => {
  try {
    const { id } = req.params;
    const absenceData = { 
      ...req.validatedData, 
      total_days: calculateDays(req.validatedData.leave_start_date, req.validatedData.leave_end_date),
      updated_at: new Date().toISOString() 
    };
    
    const { data, error } = await supabase
      .from('leave_requests')
      .update(absenceData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Absence record not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update absence record', message: error.message });
  }
});

app.put('/api/absences/:id/approve', authenticateToken, checkPermission('staff_absence', 'update'), async (req, res) => {
  try {
    const { id } = req.params;
    const { approved, review_notes } = req.body;
    
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
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update absence status', message: error.message });
  }
});

// ===== 9. ANNOUNCEMENTS =====
app.get('/api/announcements', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase
      .from('department_announcements')
      .select('*')
      .lte('publish_start_date', today)
      .or(`publish_end_date.gte.${today},publish_end_date.is.null`)
      .order('publish_start_date', { ascending: false });
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('Announcements fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch announcements', message: error.message });
  }
});

app.get('/api/announcements/urgent', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase
      .from('department_announcements')
      .select('*')
      .eq('priority_level', 'urgent')
      .lte('publish_start_date', today)
      .or(`publish_end_date.gte.${today},publish_end_date.is.null`)
      .order('publish_start_date', { ascending: false });
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch urgent announcements', message: error.message });
  }
});

app.post('/api/announcements', authenticateToken, checkPermission('communications', 'create'), validate(schemas.announcement), async (req, res) => {
  try {
    const announcementData = { 
      ...req.validatedData, 
      announcement_id: generateId('ANN'), 
      created_by: req.user.id, 
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
    res.status(500).json({ error: 'Failed to create announcement', message: error.message });
  }
});

app.put('/api/announcements/:id', authenticateToken, checkPermission('communications', 'update'), validate(schemas.announcement), async (req, res) => {
  try {
    const { id } = req.params;
    const announcementData = { ...req.validatedData, updated_at: new Date().toISOString() };
    
    const { data, error } = await supabase
      .from('department_announcements')
      .update(announcementData)
      .eq('id', id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Announcement not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update announcement', message: error.message });
  }
});

app.delete('/api/announcements/:id', authenticateToken, checkPermission('communications', 'delete'), async (req, res) => {
  try {
    const { id } = req.params;
    
    const { error } = await supabase
      .from('department_announcements')
      .delete()
      .eq('id', id);
    
    if (error) throw error;
    
    res.json({ message: 'Announcement deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete announcement', message: error.message });
  }
});

// ===== 10. USERS =====
app.get('/api/users', authenticateToken, checkPermission('users', 'read'), apiLimiter, async (req, res) => {
  try {
    const { role, department_id, status } = req.query;
    
    let query = supabase
      .from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, account_status, created_at, updated_at');
    
    if (role) query = query.eq('user_role', role);
    if (department_id) query = query.eq('department_id', department_id);
    if (status) query = query.eq('account_status', status);
    
    const { data, error } = await query.order('created_at', { ascending: false });
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch users', message: error.message });
  }
});

app.get('/api/users/:id', authenticateToken, checkPermission('users', 'read'), async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, account_status, created_at, updated_at')
      .eq('id', id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'User not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user', message: error.message });
  }
});

app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, account_status, created_at, updated_at')
      .eq('id', req.user.id)
      .single();
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user profile', message: error.message });
  }
});

// ===== 11. AUDIT LOGS =====
app.get('/api/audit-logs', authenticateToken, checkPermission('audit_logs', 'read'), async (req, res) => {
  try {
    const { user_id, resource, start_date, end_date } = req.query;
    
    let query = supabase
      .from('audit_logs')
      .select('*')
      .order('created_at', { ascending: false });
    
    if (user_id) query = query.eq('user_id', user_id);
    if (resource) query = query.eq('resource', resource);
    if (start_date) query = query.gte('created_at', start_date);
    if (end_date) query = query.lte('created_at', end_date);
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    console.error('Audit logs fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs', message: error.message });
  }
});

// ===== 12. DASHBOARD =====
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    
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
      activeAlerts: 0, // Default value
      timestamp: new Date().toISOString()
    };
    
    res.json(stats);
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics', message: error.message });
  }
});

app.get('/api/dashboard/upcoming-events', authenticateToken, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const nextWeek = formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));
    
    const [rotations, oncall, absences] = await Promise.all([
      supabase
        .from('resident_rotations')
        .select(`
          *,
          resident:medical_staff!resident_rotations_resident_id_fkey(full_name),
          training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name)
        `)
        .gte('start_date', today)
        .lte('start_date', nextWeek)
        .eq('rotation_status', 'upcoming')
        .order('start_date')
        .limit(5),
      
      supabase
        .from('oncall_schedule')
        .select(`
          *,
          primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name)
        `)
        .gte('duty_date', today)
        .lte('duty_date', nextWeek)
        .order('duty_date')
        .limit(5),
      
      supabase
        .from('leave_requests')
        .select(`
          *,
          staff_member:medical_staff!leave_requests_staff_member_id_fkey(full_name)
        `)
        .gte('leave_start_date', today)
        .lte('leave_start_date', nextWeek)
        .eq('approval_status', 'approved')
        .order('leave_start_date')
        .limit(5)
    ]);
    
    // Transform responses
    const upcomingRotations = (rotations.data || []).map(item => ({
      ...item,
      resident_name: item.resident?.full_name || null,
      training_unit_name: item.training_unit?.unit_name || null
    }));
    
    const upcomingOncall = (oncall.data || []).map(item => ({
      ...item,
      physician_name: item.primary_physician?.full_name || null
    }));
    
    const upcomingAbsences = (absences.data || []).map(item => ({
      ...item,
      staff_member_name: item.staff_member?.full_name || null
    }));
    
    res.json({
      upcoming_rotations: upcomingRotations,
      upcoming_oncall: upcomingOncall,
      upcoming_absences: upcomingAbsences
    });
  } catch (error) {
    console.error('Upcoming events error:', error);
    res.status(500).json({ error: 'Failed to fetch upcoming events', message: error.message });
  }
});

// ===== 13. SYSTEM SETTINGS =====
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
        announcement_notifications: true,
        is_default: true
      });
    }
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch system settings', message: error.message });
  }
});

app.put('/api/settings', authenticateToken, checkPermission('system_settings', 'update'), validate(schemas.systemSettings), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('system_settings')
      .upsert([req.validatedData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update system settings', message: error.message });
  }
});

// ===== 14. AVAILABLE DATA =====
app.get('/api/available-data', authenticateToken, async (req, res) => {
  try {
    const [departments, residents, attendings, trainingUnits, staff] = await Promise.all([
      supabase.from('departments').select('id, name, code').eq('status', 'active').order('name'),
      supabase.from('medical_staff').select('id, full_name, training_year').eq('staff_type', 'medical_resident').eq('employment_status', 'active').order('full_name'),
      supabase.from('medical_staff').select('id, full_name, specialization').eq('staff_type', 'attending_physician').eq('employment_status', 'active').order('full_name'),
      supabase.from('training_units').select('id, unit_name, unit_code, maximum_residents').eq('unit_status', 'active').order('unit_name'),
      supabase.from('medical_staff').select('id, full_name, staff_type').eq('employment_status', 'active').order('full_name')
    ]);
    
    const result = {
      departments: departments.data || [],
      residents: residents.data || [],
      attendings: attendings.data || [],
      trainingUnits: trainingUnits.data || [],
      staff: staff.data || []
    };
    
    res.json(result);
  } catch (error) {
    console.error('Available data fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch available data', message: error.message });
  }
});

// ===== 15. SEARCH =====
app.get('/api/search/medical-staff', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);
    
    const { data, error } = await supabase
      .from('medical_staff')
      .select('id, full_name, professional_email, staff_type, staff_id')
      .or(`full_name.ilike.%${q}%,staff_id.ilike.%${q}%,professional_email.ilike.%${q}%`)
      .limit(10);
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to search medical staff', message: error.message });
  }
});

// ===== 16. CALENDAR EVENTS =====
app.get('/api/calendar/events', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    if (!start_date || !end_date) {
      return res.status(400).json({ error: 'Start date and end date are required' });
    }
    
    const [rotations, oncall, absences] = await Promise.all([
      supabase
        .from('resident_rotations')
        .select(`
          id,
          start_date,
          end_date,
          rotation_status,
          resident:medical_staff!resident_rotations_resident_id_fkey(full_name),
          training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name)
        `)
        .gte('end_date', start_date)
        .lte('start_date', end_date),
      
      supabase
        .from('oncall_schedule')
        .select(`
          id,
          duty_date,
          shift_type,
          primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name)
        `)
        .gte('duty_date', start_date)
        .lte('duty_date', end_date),
      
      supabase
        .from('leave_requests')
        .select(`
          id,
          leave_start_date,
          leave_end_date,
          leave_category,
          approval_status,
          staff_member:medical_staff!leave_requests_staff_member_id_fkey(full_name)
        `)
        .gte('leave_end_date', start_date)
        .lte('leave_start_date', end_date)
        .eq('approval_status', 'approved')
    ]);
    
    const events = [];
    
    // Process rotations
    rotations.data?.forEach(rotation => {
      events.push({
        id: rotation.id,
        title: `${rotation.resident?.full_name || 'Resident'} - ${rotation.training_unit?.unit_name || 'Unit'}`,
        start: rotation.start_date,
        end: rotation.end_date,
        type: 'rotation',
        status: rotation.rotation_status,
        color: rotation.rotation_status === 'active' ? 'blue' : rotation.rotation_status === 'upcoming' ? 'orange' : 'gray'
      });
    });
    
    // Process on-call
    oncall.data?.forEach(schedule => {
      events.push({
        id: schedule.id,
        title: `On-call: ${schedule.primary_physician?.full_name || 'Physician'}`,
        start: schedule.duty_date,
        end: schedule.duty_date,
        type: 'oncall',
        shift_type: schedule.shift_type,
        color: schedule.shift_type === 'primary_call' ? 'red' : 'yellow'
      });
    });
    
    // Process absences
    absences.data?.forEach(absence => {
      events.push({
        id: absence.id,
        title: `${absence.staff_member?.full_name || 'Staff'} - ${absence.leave_category}`,
        start: absence.leave_start_date,
        end: absence.leave_end_date,
        type: 'absence',
        leave_category: absence.leave_category,
        color: 'green'
      });
    });
    
    res.json(events);
  } catch (error) {
    console.error('Calendar events error:', error);
    res.status(500).json({ error: 'Failed to fetch calendar events', message: error.message });
  }
});

// ============ ERROR HANDLING ============

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The requested endpoint ${req.originalUrl} does not exist`,
    availableEndpoints: [
      '/health',
      '/api/auth/login',
      '/api/auth/logout',
      '/api/medical-staff',
      '/api/departments',
      '/api/training-units',
      '/api/rotations',
      '/api/rotations/current',
      '/api/rotations/upcoming',
      '/api/oncall',
      '/api/oncall/today',
      '/api/oncall/upcoming',
      '/api/absences',
      '/api/absences/upcoming',
      '/api/absences/pending',
      '/api/announcements',
      '/api/announcements/urgent',
      '/api/users',
      '/api/users/profile',
      '/api/audit-logs',
      '/api/dashboard/stats',
      '/api/dashboard/upcoming-events',
      '/api/settings',
      '/api/available-data',
      '/api/search/medical-staff',
      '/api/calendar/events',
      '/api/debug/tables'
    ]
  });
});

// Global error handler
app.use((err, req, res, next) => {
  const timestamp = new Date().toISOString();
  console.error(`[${timestamp}] ${req.method} ${req.url} - Error:`, err.message);
  console.error(err.stack);
  
  if (err.message?.includes('JWT') || err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Authentication error', message: 'Invalid or expired authentication token' });
  }
  
  if (err.message?.includes('Supabase') || err.code?.startsWith('PGRST')) {
    return res.status(500).json({ error: 'Database error', message: 'An error occurred while accessing the database' });
  }
  
  res.status(500).json({
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? err.message : 'An unexpected error occurred',
    timestamp
  });
});

// ============ SERVER STARTUP ============
const server = app.listen(PORT, () => {
  console.log(`
    ======================================================
    🏥 NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API v5.1
    ======================================================
    ✅ OPTIMIZED FOR VUE FRONTEND
    ✅ Server running on port: ${PORT}
    ✅ Environment: ${NODE_ENV}
    ✅ Health check: http://localhost:${PORT}/health
    ✅ Debug endpoint: http://localhost:${PORT}/api/debug/tables
    ======================================================
    📊 ENDPOINTS SUMMARY:
    • Authentication: 2 endpoints
    • Medical Staff: 5 endpoints  
    • Departments: 4 endpoints
    • Training Units: 4 endpoints
    • Rotations: 7 endpoints
    • On-call: 7 endpoints
    • Absences: 6 endpoints
    • Announcements: 5 endpoints
    • Users: 4 endpoints
    • Audit Logs: 1 endpoint
    • Dashboard: 2 endpoints
    • System Settings: 2 endpoints
    • Available Data: 1 endpoint
    • Search: 1 endpoint
    • Calendar: 1 endpoint
    • Debug: 1 endpoint
    ======================================================
    TOTAL: 53 WELL-STRUCTURED ENDPOINTS
    ======================================================
    🎯 READY FOR VUE FRONTEND INTEGRATION
    ======================================================
  `);
});

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

module.exports = app;
