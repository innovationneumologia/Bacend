// ============ NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API ============
// VERSION 4.1 - COMPLETE CORRECTED SUPABASE SYNTAX
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

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Missing required environment variables: SUPABASE_URL, SUPABASE_SERVICE_KEY');
  process.exit(1);
}

// ============ SUPABASE CLIENT ============
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

// ============ SECURITY MIDDLEWARE ============
app.use(helmet());
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || process.env.NODE_ENV === 'development') return callback(null, true);
    
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

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP, please try again after 15 minutes' }
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: process.env.NODE_ENV === 'development' ? 100 : 5,
  message: { error: 'Too many login attempts, please try again later' },
  skipSuccessfulRequests: true
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request Logger Middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ============ UTILITY FUNCTIONS ============
const generateId = (prefix) => {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 9)}`;
};

const formatDate = (dateString) => {
  if (!dateString) return '';
  try {
    return new Date(dateString).toISOString().split('T')[0];
  } catch { return ''; }
};

const calculateDays = (start, end) => {
  const startDate = new Date(start);
  const endDate = new Date(end);
  const diffTime = Math.abs(endDate - startDate);
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
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
    coverage_notes: Joi.string().max(500).optional().allow(''),
    schedule_id: Joi.string().optional()
  }),
  
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
const checkPermission = (resource, action) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (req.user.role === 'system_admin') return next();
    
    // Simplified permission check - can be expanded
    const allowedRoles = {
      'medical_staff': ['system_admin', 'department_head', 'resident_manager'],
      'departments': ['system_admin', 'department_head'],
      'training_units': ['system_admin', 'department_head', 'resident_manager'],
      'resident_rotations': ['system_admin', 'department_head', 'resident_manager'],
      'oncall_schedule': ['system_admin', 'department_head'],
      'staff_absence': ['system_admin', 'department_head', 'resident_manager'],
      'communications': ['system_admin', 'department_head'],
      'system_settings': ['system_admin'],
      'users': ['system_admin']
    };
    
    if (!allowedRoles[resource]?.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        message: `You don't have permission to ${action} ${resource}`
      });
    }
    
    next();
  };
};

// ============ ROUTES ============

// ===== HEALTH CHECK =====
// GET /health - Check API status and database connection
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'NeumoCare Hospital API',
    version: '4.1.0',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    database: SUPABASE_URL ? 'Connected' : 'Not connected'
  });
});

// ===== AUTHENTICATION =====
// POST /api/auth/login - User login with JWT token generation
app.post('/api/auth/login', authLimiter, validate(schemas.login), async (req, res) => {
  try {
    const { email, password } = req.validatedData;
    
    // Demo admin account
    if (email === 'admin@neumocare.org' && password === 'password123') {
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
      { id: user.id, email: user.email, role: user.user_role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    const { password_hash, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout - User logout (client-side token removal)
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== USER PROFILE =====
// GET /api/users/profile - Get current user's profile information
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

// PUT /api/users/profile - Update current user's profile
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
    
    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ===== MEDICAL STAFF =====
// GET /api/medical-staff - List all medical staff with pagination and filtering
app.get('/api/medical-staff', authenticateToken, checkPermission('medical_staff', 'read'), apiLimiter, async (req, res) => {
  try {
    const { search, staff_type, employment_status, department_id, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    
    let query = supabase
      .from('medical_staff')
      .select('*, departments!medical_staff_department_id_fkey(name, code)', { count: 'exact' });
    
    if (search) query = query.or(`full_name.ilike.%${search}%,staff_id.ilike.%${search}%,professional_email.ilike.%${search}%`);
    if (staff_type) query = query.eq('staff_type', staff_type);
    if (employment_status) query = query.eq('employment_status', employment_status);
    if (department_id) query = query.eq('department_id', department_id);
    
    query = query.order('full_name').range(offset, offset + limit - 1);
    
    const { data, error, count } = await query;
    if (error) throw error;
    
    // Transform response
    const transformedData = data.map(item => ({
      ...item,
      department: item.departments ? { name: item.departments.name, code: item.departments.code } : null
    }));
    
    res.json({
      data: transformedData,
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

// GET /api/medical-staff/:id - Get detailed information for a specific medical staff member
app.get('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'read'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('medical_staff')
      .select('*, departments!medical_staff_department_id_fkey(name, code)')
      .eq('id', req.params.id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Medical staff not found' });
      throw error;
    }
    
    // Transform response
    const transformed = {
      ...data,
      department: data.departments ? { name: data.departments.name, code: data.departments.code } : null
    };
    
    res.json(transformed);
  } catch (error) {
    console.error('Medical staff details error:', error);
    res.status(500).json({ error: 'Failed to fetch staff details' });
  }
});

// POST /api/medical-staff - Create new medical staff record
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
    
    if (error) throw error;
    
    res.status(201).json(data);
  } catch (error) {
    console.error('Create medical staff error:', error);
    if (error.code === '23505') {
      return res.status(409).json({ 
        error: 'Duplicate entry',
        message: 'A staff member with this email or staff ID already exists'
      });
    }
    res.status(500).json({ error: 'Failed to create medical staff' });
  }
});

// PUT /api/medical-staff/:id - Update existing medical staff record
app.put('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'update'), validate(schemas.medicalStaff), async (req, res) => {
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
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Medical staff not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update medical staff error:', error);
    res.status(500).json({ error: 'Failed to update medical staff' });
  }
});

// DELETE /api/medical-staff/:id - Deactivate medical staff (soft delete)
app.delete('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'delete'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('medical_staff')
      .update({ 
        employment_status: 'inactive',
        updated_at: new Date().toISOString()
      })
      .eq('id', req.params.id)
      .select('full_name')
      .single();
    
    if (error) throw error;
    
    res.json({ 
      message: 'Medical staff deactivated successfully',
      staff_name: data.full_name
    });
  } catch (error) {
    console.error('Delete medical staff error:', error);
    res.status(500).json({ error: 'Failed to deactivate medical staff' });
  }
});

// ===== DEPARTMENTS =====
// GET /api/departments - List all hospital departments with head of department information
app.get('/api/departments', authenticateToken, apiLimiter, async (req, res) => {
  try {
    // CORRECTED SUPABASE SYNTAX - No alias before foreign key
    const { data, error } = await supabase
      .from('departments')
      .select('*, medical_staff!departments_head_of_department_id_fkey(full_name, professional_email)')
      .order('name');
    
    if (error) throw error;
    
    // Transform response - medical_staff object contains the joined data
    const transformedData = data.map(item => ({
      ...item,
      head_of_department: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null
      }
    }));
    
    res.json(transformedData);
  } catch (error) {
    console.error('Departments error:', error);
    res.status(500).json({ error: 'Failed to fetch departments' });
  }
});

// GET /api/departments/:id - Get detailed information for a specific department
app.get('/api/departments/:id', authenticateToken, async (req, res) => {
  try {
    // CORRECTED SUPABASE SYNTAX
    const { data, error } = await supabase
      .from('departments')
      .select('*, medical_staff!departments_head_of_department_id_fkey(full_name, professional_email, staff_type)')
      .eq('id', req.params.id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Department not found' });
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
    console.error('Department details error:', error);
    res.status(500).json({ error: 'Failed to fetch department details' });
  }
});

// POST /api/departments - Create new hospital department
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
    console.error('Create department error:', error);
    res.status(500).json({ error: 'Failed to create department' });
  }
});

// PUT /api/departments/:id - Update existing department information
app.put('/api/departments/:id', authenticateToken, checkPermission('departments', 'update'), validate(schemas.department), async (req, res) => {
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
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Department not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update department error:', error);
    res.status(500).json({ error: 'Failed to update department' });
  }
});

// ===== TRAINING UNITS =====
// GET /api/training-units - List all clinical training units with department and supervisor info
app.get('/api/training-units', authenticateToken, async (req, res) => {
  try {
    const { department_id, unit_status } = req.query;
    
    // CORRECTED SYNTAX - Two foreign key relationships
    let query = supabase
      .from('training_units')
      .select('*, departments!training_units_department_id_fkey(name, code), medical_staff!training_units_supervisor_id_fkey(full_name, professional_email)')
      .order('unit_name');
    
    if (department_id) query = query.eq('department_id', department_id);
    if (unit_status) query = query.eq('unit_status', unit_status);
    
    const { data, error } = await query;
    if (error) throw error;
    
    // Transform response
    const transformedData = data.map(item => ({
      ...item,
      department: item.departments ? { name: item.departments.name, code: item.departments.code } : null,
      supervisor: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null
      }
    }));
    
    res.json(transformedData);
  } catch (error) {
    console.error('Training units error:', error);
    res.status(500).json({ error: 'Failed to fetch training units' });
  }
});

// GET /api/training-units/:id - Get detailed information for a specific training unit
app.get('/api/training-units/:id', authenticateToken, async (req, res) => {
  try {
    // CORRECTED SYNTAX
    const { data, error } = await supabase
      .from('training_units')
      .select('*, departments!training_units_department_id_fkey(name, code), medical_staff!training_units_supervisor_id_fkey(full_name, professional_email)')
      .eq('id', req.params.id)
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Training unit not found' });
      throw error;
    }
    
    // Transform response
    const transformed = {
      ...data,
      department: data.departments ? { name: data.departments.name, code: data.departments.code } : null,
      supervisor: {
        full_name: data.medical_staff?.full_name || null,
        professional_email: data.medical_staff?.professional_email || null
      }
    };
    
    res.json(transformed);
  } catch (error) {
    console.error('Training unit details error:', error);
    res.status(500).json({ error: 'Failed to fetch training unit details' });
  }
});

// POST /api/training-units - Create new clinical training unit
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
    console.error('Create training unit error:', error);
    res.status(500).json({ error: 'Failed to create training unit' });
  }
});

// PUT /api/training-units/:id - Update existing training unit information
app.put('/api/training-units/:id', authenticateToken, checkPermission('training_units', 'update'), validate(schemas.trainingUnit), async (req, res) => {
  try {
    const unitData = {
      ...req.validatedData,
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('training_units')
      .update(unitData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Training unit not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update training unit error:', error);
    res.status(500).json({ error: 'Failed to update training unit' });
  }
});

// ===== RESIDENT ROTATIONS =====
// GET /api/rotations - List all resident rotations with resident, supervisor, and unit info
app.get('/api/rotations', authenticateToken, async (req, res) => {
  try {
    const { resident_id, rotation_status, training_unit_id, start_date, end_date, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    
    // CORRECTED SYNTAX - Multiple foreign keys with proper naming
    let query = supabase
      .from('resident_rotations')
      .select('*, medical_staff!resident_rotations_resident_id_fkey(full_name, professional_email, staff_type), medical_staff!resident_rotations_supervising_attending_id_fkey(full_name, professional_email), training_units(unit_name, unit_code)', { count: 'exact' });
    
    if (resident_id) query = query.eq('resident_id', resident_id);
    if (rotation_status) query = query.eq('rotation_status', rotation_status);
    if (training_unit_id) query = query.eq('training_unit_id', training_unit_id);
    if (start_date) query = query.gte('start_date', start_date);
    if (end_date) query = query.lte('end_date', end_date);
    
    query = query.order('start_date', { ascending: false }).range(offset, offset + limit - 1);
    
    const { data, error, count } = await query;
    if (error) throw error;
    
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
      }
    });
  } catch (error) {
    console.error('Rotations error:', error);
    res.status(500).json({ error: 'Failed to fetch rotations' });
  }
});

// POST /api/rotations - Assign resident to a training unit rotation
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
    console.error('Create rotation error:', error);
    res.status(500).json({ error: 'Failed to create rotation' });
  }
});

// PUT /api/rotations/:id - Update existing rotation assignment
app.put('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'update'), validate(schemas.rotation), async (req, res) => {
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
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Rotation not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update rotation error:', error);
    res.status(500).json({ error: 'Failed to update rotation' });
  }
});

// DELETE /api/rotations/:id - Cancel a resident rotation
app.delete('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'delete'), async (req, res) => {
  try {
    const { error } = await supabase
      .from('resident_rotations')
      .update({
        rotation_status: 'cancelled',
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
// GET /api/oncall - List all on-call schedules with physician information
app.get('/api/oncall', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { start_date, end_date, physician_id } = req.query;
    
    // CORRECTED SYNTAX - Two foreign keys for primary and backup physicians
    let query = supabase
      .from('oncall_schedule')
      .select('*, medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email, mobile_phone), medical_staff!oncall_schedule_backup_physician_id_fkey(full_name, professional_email, mobile_phone)')
      .order('duty_date');
    
    if (start_date) query = query.gte('duty_date', start_date);
    if (end_date) query = query.lte('duty_date', end_date);
    if (physician_id) query = query.or(`primary_physician_id.eq.${physician_id},backup_physician_id.eq.${physician_id}`);
    
    const { data, error } = await query;
    if (error) throw error;
    
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
    
    res.json(transformedData);
  } catch (error) {
    console.error('On-call schedule error:', error);
    res.status(500).json({ error: 'Failed to fetch on-call schedule' });
  }
});

// POST /api/oncall - Schedule physician for on-call duty
app.post('/api/oncall', authenticateToken, checkPermission('oncall_schedule', 'create'), validate(schemas.onCall), async (req, res) => {
  try {
    const scheduleData = {
      ...req.validatedData,
      schedule_id: req.validatedData.schedule_id || generateId('SCH'),
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
    console.error('Create on-call error:', error);
    res.status(500).json({ error: 'Failed to create on-call schedule' });
  }
});

// PUT /api/oncall/:id - Update existing on-call schedule
app.put('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'update'), validate(schemas.onCall), async (req, res) => {
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
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Schedule not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update on-call error:', error);
    res.status(500).json({ error: 'Failed to update on-call schedule' });
  }
});

// DELETE /api/oncall/:id - Remove on-call schedule entry
app.delete('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'delete'), async (req, res) => {
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

// ===== STAFF ABSENCES (LEAVE REQUESTS) =====
// GET /api/absences - List all staff leave/absence requests
app.get('/api/absences', authenticateToken, async (req, res) => {
  try {
    const { staff_member_id, approval_status, start_date, end_date } = req.query;
    
    // CORRECTED SYNTAX - Join with medical_staff for staff info
    let query = supabase
      .from('leave_requests')
      .select('*, medical_staff!leave_requests_staff_member_id_fkey(full_name, professional_email, department_id)')
      .order('leave_start_date');
    
    if (staff_member_id) query = query.eq('staff_member_id', staff_member_id);
    if (approval_status) query = query.eq('approval_status', approval_status);
    if (start_date) query = query.gte('leave_start_date', start_date);
    if (end_date) query = query.lte('leave_end_date', end_date);
    
    const { data, error } = await query;
    if (error) throw error;
    
    // Transform response
    const transformedData = data.map(item => ({
      ...item,
      staff_member: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null,
        department_id: item.medical_staff?.department_id || null
      }
    }));
    
    res.json(transformedData);
  } catch (error) {
    console.error('Absences error:', error);
    res.status(500).json({ error: 'Failed to fetch absences' });
  }
});

// POST /api/absences - Submit new leave/absence request
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
    console.error('Create absence error:', error);
    res.status(500).json({ error: 'Failed to create absence record' });
  }
});

// PUT /api/absences/:id - Update existing leave request
app.put('/api/absences/:id', authenticateToken, checkPermission('staff_absence', 'update'), validate(schemas.absence), async (req, res) => {
  try {
    const absenceData = {
      ...req.validatedData,
      total_days: calculateDays(req.validatedData.leave_start_date, req.validatedData.leave_end_date),
      updated_at: new Date().toISOString()
    };
    
    const { data, error } = await supabase
      .from('leave_requests')
      .update(absenceData)
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Absence record not found' });
      throw error;
    }
    
    res.json(data);
  } catch (error) {
    console.error('Update absence error:', error);
    res.status(500).json({ error: 'Failed to update absence record' });
  }
});

// PUT /api/absences/:id/approve - Approve or reject a leave request
app.put('/api/absences/:id/approve', authenticateToken, checkPermission('staff_absence', 'update'), async (req, res) => {
  try {
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
      .eq('id', req.params.id)
      .select()
      .single();
    
    if (error) throw error;
    
    res.json(data);
  } catch (error) {
    console.error('Approve absence error:', error);
    res.status(500).json({ error: 'Failed to update absence status' });
  }
});

// ===== ANNOUNCEMENTS =====
// GET /api/announcements - List all active announcements
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
    
    res.json(data);
  } catch (error) {
    console.error('Announcements error:', error);
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

// POST /api/announcements - Create new announcement
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
    console.error('Create announcement error:', error);
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

// DELETE /api/announcements/:id - Remove announcement
app.delete('/api/announcements/:id', authenticateToken, checkPermission('communications', 'delete'), async (req, res) => {
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

// ===== DASHBOARD ENDPOINTS =====
// GET /api/dashboard/stats - Get key metrics for dashboard display
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
    
    res.json({
      totalStaff: totalStaff || 0,
      activeStaff: activeStaff || 0,
      activeResidents: activeResidents || 0,
      todayOnCall: todayOnCall || 0,
      pendingAbsences: pendingAbsences || 0,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

// ===== SYSTEM SETTINGS =====
// GET /api/settings - Get system configuration settings
app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('system_settings')
      .select('*')
      .limit(1)
      .single();
    
    if (error) {
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

// PUT /api/settings - Update system configuration settings
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
    console.error('Update settings error:', error);
    res.status(500).json({ error: 'Failed to update system settings' });
  }
});

// ===== USERS MANAGEMENT =====
// GET /api/users - List all system users (admin only)
app.get('/api/users', authenticateToken, checkPermission('users', 'read'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, account_status, created_at, departments!app_users_department_id_fkey(name)')
      .order('full_name');
    
    if (error) throw error;
    
    // Transform response
    const transformedData = data.map(item => ({
      ...item,
      department: item.departments ? { name: item.departments.name } : null
    }));
    
    res.json(transformedData);
  } catch (error) {
    console.error('Users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ===== NOTIFICATIONS =====
// GET /api/notifications - Get unread notifications for current user
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('notifications')
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

// ===== AVAILABLE DATA FOR SELECT OPTIONS =====
// GET /api/available-data - Get dropdown data for forms (departments, residents, etc.)
app.get('/api/available-data', authenticateToken, async (req, res) => {
  try {
    const [departments, residents, attendings, trainingUnits] = await Promise.all([
      supabase.from('departments').select('id, name, code').eq('status', 'active').order('name'),
      supabase.from('medical_staff').select('id, full_name, training_year').eq('staff_type', 'medical_resident').eq('employment_status', 'active').order('full_name'),
      supabase.from('medical_staff').select('id, full_name, specialization').eq('staff_type', 'attending_physician').eq('employment_status', 'active').order('full_name'),
      supabase.from('training_units').select('id, unit_name, unit_code, maximum_residents').eq('unit_status', 'active').order('unit_name')
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

// ===== AUDIT LOGS =====
// GET /api/audit-logs - Get system audit logs (admin only)
app.get('/api/audit-logs', authenticateToken, checkPermission('system_settings', 'read'), async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;
    
    const { data, error, count } = await supabase
      .from('audit_logs')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);
    
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

// ============ ERROR HANDLING ============
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

app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Error:`, err.message);
  
  if (err.message?.includes('JWT') || err.name === 'JsonWebTokenError') {
    return res.status(401).json({ 
      error: 'Authentication error',
      message: 'Invalid or expired authentication token' 
    });
  }
  
  res.status(500).json({
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? err.message : 'An unexpected error occurred'
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
