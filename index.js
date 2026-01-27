// ============ NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API ============
// COMPLETE VERSION WITH ALL ENDPOINTS FOR YOUR DATABASE STRUCTURE
// VERSION 2.2 - FULLY COMPATIBLE WITH YOUR FRONTEND
// ==================================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
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
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

// ============ SECURITY MIDDLEWARE ============
app.use(helmet());
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (process.env.NODE_ENV === 'development') return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:8080',
      'http://127.0.0.1:5500',
      'https://innovationneumologia.github.io',
      'https://*.github.io',
      'https://*.vercel.app',
      'https://*.netlify.app',
      'https://*.railway.app'
    ];
    
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin.includes('*')) {
        const regex = new RegExp('^' + allowedOrigin.replace('*', '.*') + '$');
        return regex.test(origin);
      }
      return allowedOrigin === origin;
    });
    
    callback(null, isAllowed);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request Logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

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

// ============ PERMISSIONS ============
const PERMISSIONS = {
  system_admin: { name: 'System Administrator', permissions: { all: true } },
  department_head: { name: 'Head of Department', permissions: { read: true, write: true } },
  resident_manager: { name: 'Resident Manager', permissions: { read: true, write: true } },
  attending_physician: { name: 'Attending Physician', permissions: { read: true } },
  viewing_doctor: { name: 'Viewing Doctor', permissions: { read: true } }
};

// ============ ROUTES ============

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'NeumoCare Hospital API',
    version: '2.2.0',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    uptime: process.uptime()
  });
});

// ===== DATABASE CHECK =====
app.get('/api/db-check', async (req, res) => {
  try {
    const tables = [
      'medical_staff', 'departments', 'clinical_units', 'training_units',
      'resident_rotations', 'oncall_schedule', 'leave_requests',
      'department_announcements', 'app_users', 'system_settings',
      'system_roles', 'audit_logs', 'notifications'
    ];
    
    const results = {};
    
    for (const table of tables) {
      try {
        const { error } = await supabase
          .from(table)
          .select('id')
          .limit(1);
        
        results[table] = {
          exists: !error || !error.message?.includes('does not exist'),
          error: error?.message
        };
      } catch (err) {
        results[table] = {
          exists: false,
          error: err.message
        };
      }
    }
    
    res.json({
      database: 'Connected',
      tables: results,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Database check failed', message: error.message });
  }
});

// ===== AUTHENTICATION =====
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Demo admin account
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
      .select('*')
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

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
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
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// ===== DASHBOARD ENDPOINTS =====
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    // Get all counts
    const [
      { count: totalStaff = 0 },
      { count: activeStaff = 0 },
      { count: activeResidents = 0 },
      { count: todayOnCall = 0 },
      { count: pendingAbsences = 0 }
    ] = await Promise.all([
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('employment_status', 'active'),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('staff_type', 'medical_resident').eq('employment_status', 'active'),
      supabase.from('oncall_schedule').select('*', { count: 'exact', head: true }).eq('duty_date', today),
      supabase.from('leave_requests').select('*', { count: 'exact', head: true }).eq('approval_status', 'pending_review')
    ]);
    
    res.json({
      totalStaff,
      activeStaff,
      activeResidents,
      todayOnCall,
      pendingAbsences,
      activeAlerts: 0,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

app.get('/api/dashboard/oncall-today', authenticateToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    const { data, error } = await supabase
      .from('oncall_schedule')
      .select(`
        *,
        primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email),
        backup_physician:medical_staff!oncall_schedule_backup_physician_id_fkey(full_name, professional_email)
      `)
      .eq('duty_date', today)
      .order('start_time');
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
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
      supabase.from('leave_requests').select('*').eq('approval_status', 'approved').gte('leave_start_date', start).lte('leave_end_date', end),
      supabase.from('resident_rotations').select('*').in('rotation_status', ['active', 'upcoming']).gte('start_date', start).lte('end_date', end),
      supabase.from('oncall_schedule').select('*').gte('duty_date', start).lte('duty_date', end)
    ]);
    
    res.json({
      absences: absences.data || [],
      rotations: rotations.data || [],
      oncall: oncall.data || []
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch calendar events' });
  }
});

// ===== MEDICAL STAFF =====
app.get('/api/medical-staff', authenticateToken, apiLimiter, async (req, res) => {
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
    
    if (search) {
      query = query.or(`full_name.ilike.%${search}%,staff_id.ilike.%${search}%,professional_email.ilike.%${search}%`);
    }
    if (staff_type) query = query.eq('staff_type', staff_type);
    if (employment_status) query = query.eq('employment_status', employment_status);
    if (department_id) query = query.eq('department_id', department_id);
    
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
    res.status(500).json({ error: 'Failed to fetch medical staff' });
  }
});

app.get('/api/medical-staff/:id', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('medical_staff')
      .select(`
        *,
        department:departments(name, code)
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
    res.status(500).json({ error: 'Failed to fetch staff details' });
  }
});

// ===== DEPARTMENTS =====
app.get('/api/departments', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('departments')
      .select(`
        *,
        head_of_department:medical_staff!departments_head_of_department_id_fkey(full_name, professional_email)
      `)
      .order('name');
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch departments' });
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
        supervisor:medical_staff(full_name, professional_email)
      `)
      .order('unit_name');
    
    if (department_id) query = query.eq('department_id', department_id);
    if (status) query = query.eq('status', status);
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch training units' });
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
        resident:medical_staff!resident_rotations_resident_id_fkey(full_name, professional_email),
        supervisor:medical_staff!resident_rotations_supervising_attending_id_fkey(full_name, professional_email),
        training_unit:training_units(unit_name, unit_code)
      `, { count: 'exact' });
    
    if (resident_id) query = query.eq('resident_id', resident_id);
    if (status) query = query.eq('rotation_status', status);
    if (training_unit_id) query = query.eq('training_unit_id', training_unit_id);
    if (start_date) query = query.gte('start_date', start_date);
    if (end_date) query = query.lte('end_date', end_date);
    
    query = query.order('start_date', { ascending: false }).range(offset, offset + limit - 1);
    
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
    res.status(500).json({ error: 'Failed to fetch rotations' });
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
        primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email),
        backup_physician:medical_staff!oncall_schedule_backup_physician_id_fkey(full_name, professional_email)
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
    res.status(500).json({ error: 'Failed to fetch on-call schedule' });
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
        staff_member:medical_staff!leave_requests_staff_member_id_fkey(full_name, professional_email)
      `)
      .order('leave_start_date');
    
    if (staff_id) query = query.eq('staff_member_id', staff_id);
    if (status) query = query.eq('approval_status', status);
    if (start_date) query = query.gte('leave_start_date', start_date);
    if (end_date) query = query.lte('leave_end_date', end_date);
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch absences' });
  }
});

// ===== ANNOUNCEMENTS =====
app.get('/api/announcements', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    
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
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

// ===== AUDIT LOGS =====
app.get('/api/audit-logs', authenticateToken, async (req, res) => {
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
      .select('*', { count: 'exact' })
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
    
    if (error && error.code !== 'PGRST116') {
      throw error;
    }
    
    res.json(data || {
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
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch system settings' });
  }
});

// ===== PERMISSIONS =====
app.get('/api/permissions', authenticateToken, async (req, res) => {
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
    res.status(500).json({ error: 'Failed to fetch permissions' });
  }
});

// ===== USERS MANAGEMENT =====
app.get('/api/users', authenticateToken, async (req, res) => {
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
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ===== NOTIFICATIONS =====
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
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// ===== LIVE STATS =====
app.get('/api/live-stats', authenticateToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    const [
      { data: occupancyResult },
      { count: staffCount = 0 },
      { count: pendingCount = 0 },
      { count: onCallCount = 0 }
    ] = await Promise.all([
      supabase.from('patient_census').select('current_occupancy, max_capacity').single(),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('employment_status', 'active'),
      supabase.from('leave_requests').select('*', { count: 'exact', head: true }).eq('approval_status', 'pending_review'),
      supabase.from('oncall_schedule').select('*', { count: 'exact', head: true }).eq('duty_date', today)
    ]);
    
    const occupancy = occupancyResult 
      ? Math.round((occupancyResult.current_occupancy / occupancyResult.max_capacity) * 100)
      : 65;
    
    res.json({
      occupancy,
      occupancyTrend: 2,
      onDutyStaff: staffCount,
      staffTrend: 0,
      pendingRequests: pendingCount,
      erCapacity: { current: 12, max: 20, status: 'medium' },
      icuCapacity: { current: 6, max: 10, status: 'low' },
      todayOnCall: onCallCount,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
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
    res.status(500).json({ error: 'Failed to fetch available data' });
  }
});

// ===== 404 HANDLER =====
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The requested endpoint ${req.originalUrl} does not exist`,
    availableEndpoints: [
      '/api/auth/login',
      '/api/dashboard/stats',
      '/api/medical-staff',
      '/api/departments',
      '/api/clinical-units',
      '/api/training-units',
      '/api/rotations',
      '/api/oncall',
      '/api/absences',
      '/api/announcements',
      '/api/settings',
      '/api/available-data',
      '/api/live-stats',
      '/api/permissions',
      '/api/users',
      '/api/notifications',
      '/api/audit-logs',
      '/health'
    ]
  });
});

// ===== ERROR HANDLER =====
app.use((err, req, res, next) => {
  console.error(`Error:`, {
    message: err.message,
    stack: NODE_ENV === 'development' ? err.stack : undefined,
    url: req.url,
    method: req.method
  });
  
  res.status(500).json({
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? err.message : 'An unexpected error occurred'
  });
});

// ===== START SERVER =====
const server = app.listen(PORT, () => {
  console.log(`
    ============================================
    🏥 NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API
    ============================================
    ✅ Server running on port: ${PORT}
    ✅ Environment: ${NODE_ENV}
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
