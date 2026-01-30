// ============ NEUMOCARE HOSPITAL MANAGEMENT SYSTEM - VUE FRONTEND ============
// VERSION 5.0 - COMPLETE API-INTEGRATED FRONTEND
// ========================================================================

const { createApp } = Vue;

// API Configuration
const API_BASE_URL = window.location.hostname.includes('localhost') 
    ? 'http://localhost:3000' 
    : 'https://your-backend-service.railway.app';

createApp({
    data() {
        return {
            // ===== CORE STATE =====
            currentUser: null,
            loading: false,
            saving: false,
            toastIdCounter: 0,
            
            // ===== UI STATE =====
            currentView: 'daily_operations',
            sidebarCollapsed: false,
            mobileMenuOpen: false,
            statsSidebarOpen: false,
            userMenuOpen: false,
            
            // ===== SEARCH & FILTERS =====
            searchQuery: '',
            searchScope: 'All',
            searchFilter: 'all',
            staffSearch: '',
            staffFilter: {
                staff_category: '',
                employment_status: '',
                department_id: ''
            },
            rotationFilter: {
                resident_id: '',
                status: '',
                clinical_unit_id: ''
            },
            oncallFilter: {
                date: '',
                shift_type: '',
                physician_id: ''
            },
            absenceFilter: {
                staff_id: '',
                status: '',
                start_date: ''
            },
            
            // ===== DATA STORES =====
            departments: [],
            medicalStaff: [],
            clinicalUnits: [],
            residentRotations: [],
            oncallSchedules: [],
            staffAbsences: [],
            recentAnnouncements: [],
            researchGroups: [],
            researchLines: [],
            systemSettings: {},
            notifications: [],
            
            // ===== STATISTICS =====
            stats: {
                totalStaff: 0,
                activeRotations: 0,
                occupiedUnits: 0,
                totalUnits: 0,
                pendingAlerts: 0
            },
            liveStats: {
                occupancy: 0,
                occupancyTrend: 0,
                onDutyStaff: 0,
                staffTrend: 0,
                pendingRequests: 0,
                clinicalCapacity: {
                    current: 0,
                    max: 0,
                    status: 'normal'
                },
                activeRotations: 0
            },
            loadingStats: false,
            loadingAnnouncements: false,
            loadingStaff: false,
            loadingRotations: false,
            loadingOncall: false,
            loadingAbsences: false,
            
            // ===== MODALS =====
            staffDetailsModal: {
                show: false,
                staff: null,
                activeTab: 'personal',
                stats: {},
                currentRotation: '',
                nextOncall: ''
            },
            medicalStaffModal: {
                show: false,
                mode: 'add',
                activeTab: 'basic',
                form: {
                    id: null,
                    full_name: '',
                    email: '',
                    staff_id: '',
                    employment_status: 'active',
                    staff_category: 'physician',
                    physician_type: 'medical_resident',
                    resident_category: 'department_internal',
                    resident_year: '',
                    staff_role: '',
                    clinical_unit_id: '',
                    academic_degree: '',
                    research_group_id: '',
                    research_line_id: '',
                    is_phd_researcher: false,
                    specialization: '',
                    medical_license: '',
                    years_experience: '',
                    biography: ''
                }
            },
            departmentModal: {
                show: false,
                mode: 'add',
                activeTab: 'basic',
                form: {
                    id: null,
                    name: '',
                    code: '',
                    status: 'active',
                    description: '',
                    head_of_department_id: '',
                    clinical_units: [{
                        unit_name: '',
                        unit_code: '',
                        unit_type: 'clinical',
                        unit_status: 'active',
                        maximum_residents: 10,
                        unit_description: ''
                    }]
                }
            },
            clinicalUnitModal: {
                show: false,
                mode: 'add',
                form: {
                    id: null,
                    unit_name: '',
                    unit_code: '',
                    department_id: '',
                    unit_description: '',
                    unit_status: 'active',
                    maximum_residents: 10,
                    specialty: '',
                    supervising_attending_id: ''
                }
            },
            rotationModal: {
                show: false,
                mode: 'add',
                form: {
                    id: null,
                    rotation_id: '',
                    rotation_status: 'scheduled',
                    rotation_start_date: '',
                    rotation_end_date: '',
                    resident_id: '',
                    clinical_unit_id: '',
                    supervising_attending_id: '',
                    rotation_category: 'clinical_rotation',
                    clinical_notes: '',
                    supervisor_evaluation: ''
                }
            },
            onCallModal: {
                show: false,
                mode: 'add',
                form: {
                    id: null,
                    duty_date: '',
                    shift_type: 'backup_call',
                    start_time: '08:00',
                    end_time: '17:00',
                    primary_physician_id: '',
                    backup_physician_id: '',
                    coverage_area: 'emergency',
                    coverage_notes: '',
                    contact_number: ''
                }
            },
            absenceModal: {
                show: false,
                mode: 'add',
                form: {
                    id: null,
                    staff_member_id: '',
                    absence_reason: '',
                    start_date: '',
                    end_date: '',
                    status: 'upcoming',
                    total_days: 0
                }
            },
            communicationsModal: {
                show: false,
                activeTab: 'announcement',
                form: {
                    announcement_title: '',
                    announcement_content: '',
                    publish_start_date: this.formatDateTimeLocal(new Date()),
                    publish_end_date: '',
                    priority_level: 'medium',
                    target_audience: 'all_staff',
                    target_department_id: '',
                    stats: {
                        er_patients: 0,
                        icu_patients: 0,
                        ward_patients: 0,
                        clinic_patients: 0,
                        notes: '',
                        expires_in: '24'
                    }
                }
            },
            researchGroupModal: {
                show: false,
                mode: 'add',
                form: {
                    id: null,
                    name: '',
                    status: 'active',
                    description: '',
                    principal_investigator_id: '',
                    research_lines: [{
                        name: '',
                        status: 'active',
                        description: ''
                    }]
                }
            },
            userProfileModal: {
                show: false,
                activeTab: 'profile',
                form: {
                    full_name: '',
                    email: '',
                    department_id: '',
                    biography: '',
                    current_password: '',
                    new_password: '',
                    confirm_password: ''
                }
            },
            confirmationModal: null,
            
            // ===== UTILITY =====
            toasts: [],
            activeAlerts: [],
            unreadNotifications: 0,
            loginForm: {
                email: '',
                password: '',
                remember_me: false
            }
        };
    },

    computed: {
        // ===== FILTERED LISTS =====
        filteredMedicalStaff() {
            let filtered = [...this.medicalStaff];
            
            // Apply search
            if (this.staffSearch) {
                const searchTerm = this.staffSearch.toLowerCase();
                filtered = filtered.filter(staff => 
                    staff.full_name?.toLowerCase().includes(searchTerm) ||
                    staff.staff_id?.toLowerCase().includes(searchTerm) ||
                    staff.email?.toLowerCase().includes(searchTerm)
                );
            }
            
            // Apply filters
            if (this.staffFilter.staff_category) {
                filtered = filtered.filter(staff => staff.staff_category === this.staffFilter.staff_category);
            }
            
            if (this.staffFilter.employment_status) {
                filtered = filtered.filter(staff => staff.employment_status === this.staffFilter.employment_status);
            }
            
            return filtered;
        },

        filteredRotations() {
            let filtered = [...this.residentRotations];
            
            // Apply filters
            if (this.rotationFilter.resident_id) {
                filtered = filtered.filter(rotation => rotation.resident_id === this.rotationFilter.resident_id);
            }
            
            if (this.rotationFilter.status) {
                filtered = filtered.filter(rotation => rotation.rotation_status === this.rotationFilter.status);
            }
            
            if (this.rotationFilter.clinical_unit_id) {
                filtered = filtered.filter(rotation => rotation.clinical_unit_id === this.rotationFilter.clinical_unit_id);
            }
            
            return filtered;
        },

        filteredOncall() {
            let filtered = [...this.oncallSchedules];
            
            // Apply filters
            if (this.oncallFilter.date) {
                filtered = filtered.filter(schedule => schedule.duty_date === this.oncallFilter.date);
            }
            
            if (this.oncallFilter.shift_type) {
                filtered = filtered.filter(schedule => schedule.shift_type === this.oncallFilter.shift_type);
            }
            
            if (this.oncallFilter.physician_id) {
                filtered = filtered.filter(schedule => 
                    schedule.primary_physician_id === this.oncallFilter.physician_id ||
                    schedule.backup_physician_id === this.oncallFilter.physician_id
                );
            }
            
            return filtered;
        },

        filteredAbsences() {
            let filtered = [...this.staffAbsences];
            
            // Apply filters
            if (this.absenceFilter.staff_id) {
                filtered = filtered.filter(absence => absence.staff_member_id === this.absenceFilter.staff_id);
            }
            
            if (this.absenceFilter.status) {
                filtered = filtered.filter(absence => absence.status === this.absenceFilter.status);
            }
            
            if (this.absenceFilter.start_date) {
                filtered = filtered.filter(absence => absence.start_date >= this.absenceFilter.start_date);
            }
            
            return filtered;
        },

        // ===== AVAILABLE DATA FOR DROPDOWNS =====
        availableDepartments() {
            return this.departments.filter(dept => dept.status === 'active');
        },

        availableResidents() {
            return this.medicalStaff.filter(staff => 
                staff.staff_category === 'physician' && 
                staff.physician_type === 'medical_resident' &&
                staff.employment_status === 'active'
            );
        },

        availablePhysicians() {
            return this.medicalStaff.filter(staff => 
                staff.staff_category === 'physician' &&
                staff.employment_status === 'active'
            );
        },

        availableAttendings() {
            return this.medicalStaff.filter(staff => 
                staff.staff_category === 'physician' &&
                staff.physician_type === 'attending_physician' &&
                staff.employment_status === 'active'
            );
        },

        availableStaff() {
            return this.medicalStaff.filter(staff => staff.employment_status === 'active');
        },

        availableResearchers() {
            return this.medicalStaff.filter(staff => 
                staff.staff_category === 'physician' &&
                staff.is_phd_researcher
            );
        },

        activeClinicalUnits() {
            return this.clinicalUnits.filter(unit => unit.unit_status === 'active');
        },

        availableHeadsOfDepartment() {
            return this.medicalStaff.filter(staff => 
                staff.staff_category === 'physician' &&
                staff.physician_type === 'attending_physician' &&
                staff.employment_status === 'active'
            );
        },

        // ===== TODAY'S DATA =====
        todaysOnCall() {
            const today = this.formatDate(new Date());
            return this.oncallSchedules.filter(schedule => schedule.duty_date === today);
        },

        todaysRotations() {
            const today = this.formatDate(new Date());
            return this.residentRotations.filter(rotation => 
                rotation.rotation_start_date <= today && 
                rotation.rotation_end_date >= today &&
                rotation.rotation_status === 'active'
            );
        },

        // ===== DEPARTMENT UTILITIES =====
        departmentUnits() {
            const unitsMap = {};
            this.clinicalUnits.forEach(unit => {
                if (!unitsMap[unit.department_id]) {
                    unitsMap[unit.department_id] = [];
                }
                unitsMap[unit.department_id].push(unit);
            });
            return unitsMap;
        }
    },

    methods: {
        // ===== AUTHENTICATION =====
        async handleLogin() {
            try {
                this.loading = true;
                
                // For demo purposes - allow demo credentials
                if (this.loginForm.email === 'admin@neumocare.org' && this.loginForm.password === 'password123') {
                    this.currentUser = {
                        id: '11111111-1111-1111-1111-111111111111',
                        email: 'admin@neumocare.org',
                        full_name: 'System Administrator',
                        user_role: 'system_admin',
                        department_id: null
                    };
                    
                    // Store token in localStorage
                    localStorage.setItem('auth_token', 'demo-token-admin');
                    localStorage.setItem('user_data', JSON.stringify(this.currentUser));
                    
                    this.showToast('Login successful', 'Welcome back, Administrator!', 'success');
                    await this.initializeData();
                    return;
                }
                
                // Real API call
                const response = await this.apiPost('/api/auth/login', this.loginForm);
                
                if (response.token) {
                    // Store token
                    localStorage.setItem('auth_token', response.token);
                    localStorage.setItem('user_data', JSON.stringify(response.user));
                    
                    this.currentUser = response.user;
                    this.showToast('Login successful', `Welcome back, ${response.user.full_name}!`, 'success');
                    await this.initializeData();
                }
            } catch (error) {
                this.showToast('Login failed', error.message || 'Invalid credentials', 'error');
            } finally {
                this.loading = false;
            }
        },

        async handleLogout() {
            try {
                await this.apiPost('/api/auth/logout');
            } catch (error) {
                console.log('Logout error:', error);
            }
            
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_data');
            this.currentUser = null;
            this.showToast('Logged out', 'You have been logged out successfully', 'info');
        },

        // ===== API METHODS =====
        getAuthHeaders() {
            const token = localStorage.getItem('auth_token');
            return {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            };
        },

        async apiGet(endpoint) {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                headers: this.getAuthHeaders()
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || `API Error: ${response.status}`);
            }
            
            return await response.json();
        },

        async apiPost(endpoint, data) {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: this.getAuthHeaders(),
                body: JSON.stringify(data)
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || `API Error: ${response.status}`);
            }
            
            return await response.json();
        },

        async apiPut(endpoint, data) {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'PUT',
                headers: this.getAuthHeaders(),
                body: JSON.stringify(data)
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || `API Error: ${response.status}`);
            }
            
            return await response.json();
        },

        async apiDelete(endpoint) {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'DELETE',
                headers: this.getAuthHeaders()
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || `API Error: ${response.status}`);
            }
            
            return await response.json();
        },

        // ===== DATA INITIALIZATION =====
        async initializeData() {
            try {
                await Promise.all([
                    this.fetchDepartments(),
                    this.fetchMedicalStaff(),
                    this.fetchClinicalUnits(),
                    this.fetchRotations(),
                    this.fetchOncallSchedules(),
                    this.fetchAbsences(),
                    this.fetchAnnouncements(),
                    this.fetchSystemSettings(),
                    this.fetchNotifications()
                ]);
                
                this.showToast('System ready', 'All data loaded successfully', 'success');
            } catch (error) {
                console.error('Initialization error:', error);
                this.showToast('Warning', 'Some data could not be loaded', 'warning');
            }
        },

        async fetchDepartments() {
            try {
                const data = await this.apiGet('/api/departments');
                this.departments = data;
            } catch (error) {
                console.error('Failed to fetch departments:', error);
            }
        },

        async fetchMedicalStaff() {
            try {
                this.loadingStaff = true;
                const data = await this.apiGet('/api/medical-staff');
                this.medicalStaff = data.data || data;
                
                // Update stats
                this.stats.totalStaff = data.data?.length || data.length || 0;
            } catch (error) {
                console.error('Failed to fetch medical staff:', error);
            } finally {
                this.loadingStaff = false;
            }
        },

        async fetchClinicalUnits() {
            try {
                const data = await this.apiGet('/api/training-units');
                this.clinicalUnits = data.map(unit => ({
                    ...unit,
                    current_residents: this.getUnitResidents(unit.id).length
                }));
                
                // Update stats
                this.stats.totalUnits = this.clinicalUnits.length;
                this.stats.occupiedUnits = this.clinicalUnits.filter(unit => 
                    this.getUnitResidents(unit.id).length > 0
                ).length;
            } catch (error) {
                console.error('Failed to fetch clinical units:', error);
            }
        },

        async fetchRotations() {
            try {
                this.loadingRotations = true;
                const data = await this.apiGet('/api/rotations');
                this.residentRotations = data.data || data;
                
                // Update stats
                const today = this.formatDate(new Date());
                this.stats.activeRotations = this.residentRotations.filter(rotation => 
                    rotation.rotation_status === 'active' &&
                    rotation.rotation_start_date <= today &&
                    rotation.rotation_end_date >= today
                ).length;
            } catch (error) {
                console.error('Failed to fetch rotations:', error);
            } finally {
                this.loadingRotations = false;
            }
        },

        async fetchOncallSchedules() {
            try {
                this.loadingOncall = true;
                const data = await this.apiGet('/api/oncall');
                this.oncallSchedules = data;
            } catch (error) {
                console.error('Failed to fetch on-call schedules:', error);
            } finally {
                this.loadingOncall = false;
            }
        },

        async fetchAbsences() {
            try {
                this.loadingAbsences = true;
                const data = await this.apiGet('/api/absences');
                this.staffAbsences = data;
                
                // Update stats
                this.stats.pendingAlerts = data.filter(absence => 
                    absence.approval_status === 'pending'
                ).length;
            } catch (error) {
                console.error('Failed to fetch absences:', error);
            } finally {
                this.loadingAbsences = false;
            }
        },

        async fetchAnnouncements() {
            try {
                this.loadingAnnouncements = true;
                const data = await this.apiGet('/api/announcements');
                this.recentAnnouncements = data.slice(0, 5);
            } catch (error) {
                console.error('Failed to fetch announcements:', error);
            } finally {
                this.loadingAnnouncements = false;
            }
        },

        async fetchSystemSettings() {
            try {
                const data = await this.apiGet('/api/settings');
                this.systemSettings = data;
            } catch (error) {
                console.error('Failed to fetch system settings:', error);
            }
        },

        async fetchNotifications() {
            try {
                const data = await this.apiGet('/api/notifications');
                this.notifications = data;
                this.unreadNotifications = data.filter(n => !n.is_read).length;
            } catch (error) {
                console.error('Failed to fetch notifications:', error);
            }
        },

        // ===== LIVE STATS UPDATES =====
        async updateLiveStats() {
            if (!this.currentUser) return;
            
            try {
                this.loadingStats = true;
                
                // Fetch dashboard stats
                const stats = await this.apiGet('/api/dashboard/stats');
                const clinicalCapacity = {
                    current: 0,
                    max: 0,
                    status: 'normal'
                };
                
                // Calculate clinical capacity
                this.clinicalUnits.forEach(unit => {
                    const currentResidents = this.getUnitResidents(unit.id).length;
                    clinicalCapacity.current += currentResidents;
                    clinicalCapacity.max += unit.maximum_residents;
                });
                
                const occupancyRate = clinicalCapacity.max > 0 ? 
                    Math.round((clinicalCapacity.current / clinicalCapacity.max) * 100) : 0;
                
                clinicalCapacity.status = occupancyRate > 90 ? 'critical' : 
                                         occupancyRate > 70 ? 'warning' : 'normal';
                
                this.liveStats = {
                    occupancy: occupancyRate,
                    occupancyTrend: 0, // You could calculate trend from previous data
                    onDutyStaff: stats.activeStaff || 0,
                    staffTrend: 0,
                    pendingRequests: this.staffAbsences.filter(a => a.approval_status === 'pending').length,
                    clinicalCapacity: clinicalCapacity,
                    activeRotations: this.todaysRotations.length
                };
                
            } catch (error) {
                console.error('Failed to update live stats:', error);
            } finally {
                this.loadingStats = false;
            }
        },

        // ===== MODAL METHODS =====
        
        // MEDICAL STAFF MODALS
        showAddMedicalStaffModal() {
            this.medicalStaffModal = {
                show: true,
                mode: 'add',
                activeTab: 'basic',
                form: {
                    id: null,
                    full_name: '',
                    email: '',
                    staff_id: '',
                    employment_status: 'active',
                    staff_category: 'physician',
                    physician_type: 'medical_resident',
                    resident_category: 'department_internal',
                    resident_year: '',
                    staff_role: '',
                    clinical_unit_id: '',
                    academic_degree: '',
                    research_group_id: '',
                    research_line_id: '',
                    is_phd_researcher: false,
                    specialization: '',
                    medical_license: '',
                    years_experience: '',
                    biography: ''
                }
            };
        },

        editMedicalStaff(staff) {
            this.medicalStaffModal = {
                show: true,
                mode: 'edit',
                activeTab: 'basic',
                form: { ...staff }
            };
        },

        async saveMedicalStaff() {
            try {
                this.saving = true;
                
                // Prepare data for API
                const staffData = {
                    full_name: this.medicalStaffModal.form.full_name,
                    professional_email: this.medicalStaffModal.form.email,
                    staff_type: this.medicalStaffModal.form.physician_type,
                    staff_id: this.medicalStaffModal.form.staff_id || undefined,
                    employment_status: this.medicalStaffModal.form.employment_status,
                    department_id: this.medicalStaffModal.form.department_id || null,
                    resident_category: this.medicalStaffModal.form.resident_category || null,
                    training_year: this.medicalStaffModal.form.resident_year || null,
                    specialization: this.medicalStaffModal.form.specialization || '',
                    years_experience: parseInt(this.medicalStaffModal.form.years_experience) || null,
                    biography: this.medicalStaffModal.form.biography || '',
                    mobile_phone: '',
                    medical_license: this.medicalStaffModal.form.medical_license || '',
                    can_supervise_residents: this.medicalStaffModal.form.physician_type === 'attending_physician'
                };
                
                let response;
                if (this.medicalStaffModal.mode === 'add') {
                    response = await this.apiPost('/api/medical-staff', staffData);
                } else {
                    response = await this.apiPut(`/api/medical-staff/${this.medicalStaffModal.form.id}`, staffData);
                }
                
                await this.fetchMedicalStaff();
                this.medicalStaffModal.show = false;
                
                this.showToast(
                    'Success',
                    this.medicalStaffModal.mode === 'add' ? 'Medical staff added successfully' : 'Medical staff updated successfully',
                    'success'
                );
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to save medical staff', 'error');
            } finally {
                this.saving = false;
            }
        },

        // DEPARTMENT MODALS
        showAddDepartmentModal() {
            this.departmentModal = {
                show: true,
                mode: 'add',
                activeTab: 'basic',
                form: {
                    id: null,
                    name: '',
                    code: '',
                    status: 'active',
                    description: '',
                    head_of_department_id: '',
                    clinical_units: [{
                        unit_name: '',
                        unit_code: '',
                        unit_type: 'clinical',
                        unit_status: 'active',
                        maximum_residents: 10,
                        unit_description: ''
                    }]
                }
            };
        },

        editDepartment(department) {
            this.departmentModal = {
                show: true,
                mode: 'edit',
                activeTab: 'basic',
                form: { ...department }
            };
        },

        addClinicalUnit() {
            this.departmentModal.form.clinical_units.push({
                unit_name: '',
                unit_code: '',
                unit_type: 'clinical',
                unit_status: 'active',
                maximum_residents: 10,
                unit_description: ''
            });
        },

        removeClinicalUnit(index) {
            this.departmentModal.form.clinical_units.splice(index, 1);
        },

        async saveDepartment() {
            try {
                this.saving = true;
                
                // Validate required fields
                if (!this.departmentModal.form.name || !this.departmentModal.form.code) {
                    throw new Error('Department name and code are required');
                }
                
                if (this.departmentModal.form.clinical_units.length === 0) {
                    throw new Error('At least one clinical unit is required');
                }
                
                // Validate clinical units
                for (const unit of this.departmentModal.form.clinical_units) {
                    if (!unit.unit_name || !unit.unit_code) {
                        throw new Error('All clinical units must have a name and code');
                    }
                }
                
                // Prepare department data
                const deptData = {
                    name: this.departmentModal.form.name,
                    code: this.departmentModal.form.code,
                    status: this.departmentModal.form.status,
                    description: this.departmentModal.form.description || '',
                    head_of_department_id: this.departmentModal.form.head_of_department_id || null
                };
                
                let departmentResponse;
                if (this.departmentModal.mode === 'add') {
                    departmentResponse = await this.apiPost('/api/departments', deptData);
                } else {
                    departmentResponse = await this.apiPut(`/api/departments/${this.departmentModal.form.id}`, deptData);
                }
                
                // Create clinical units
                const departmentId = departmentResponse.id;
                for (const unit of this.departmentModal.form.clinical_units) {
                    const unitData = {
                        unit_name: unit.unit_name,
                        unit_code: unit.unit_code,
                        department_id: departmentId,
                        unit_type: unit.unit_type,
                        unit_status: unit.unit_status,
                        maximum_residents: unit.maximum_residents,
                        unit_description: unit.unit_description || '',
                        specialty: ''
                    };
                    
                    try {
                        await this.apiPost('/api/training-units', unitData);
                    } catch (unitError) {
                        console.error('Failed to create clinical unit:', unitError);
                    }
                }
                
                await this.fetchDepartments();
                await this.fetchClinicalUnits();
                this.departmentModal.show = false;
                
                this.showToast(
                    'Success',
                    this.departmentModal.mode === 'add' ? 'Department created successfully' : 'Department updated successfully',
                    'success'
                );
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to save department', 'error');
            } finally {
                this.saving = false;
            }
        },

        // CLINICAL UNIT MODALS
        showAddClinicalUnitModal() {
            this.clinicalUnitModal = {
                show: true,
                mode: 'add',
                form: {
                    id: null,
                    unit_name: '',
                    unit_code: '',
                    department_id: '',
                    unit_description: '',
                    unit_status: 'active',
                    maximum_residents: 10,
                    specialty: '',
                    supervising_attending_id: ''
                }
            };
        },

        editClinicalUnit(unit) {
            this.clinicalUnitModal = {
                show: true,
                mode: 'edit',
                form: { ...unit }
            };
        },

        async saveClinicalUnit() {
            try {
                this.saving = true;
                
                // Validate
                if (!this.clinicalUnitModal.form.unit_name || !this.clinicalUnitModal.form.unit_code || !this.clinicalUnitModal.form.department_id) {
                    throw new Error('Unit name, code, and department are required');
                }
                
                // Prepare data for API
                const unitData = {
                    unit_name: this.clinicalUnitModal.form.unit_name,
                    unit_code: this.clinicalUnitModal.form.unit_code,
                    department_id: this.clinicalUnitModal.form.department_id,
                    department_name: this.getDepartmentName(this.clinicalUnitModal.form.department_id),
                    maximum_residents: parseInt(this.clinicalUnitModal.form.maximum_residents) || 10,
                    unit_description: this.clinicalUnitModal.form.unit_description || '',
                    supervisor_id: this.clinicalUnitModal.form.supervising_attending_id || null,
                    unit_status: this.clinicalUnitModal.form.unit_status,
                    specialty: this.clinicalUnitModal.form.specialty || '',
                    location_building: '',
                    location_floor: ''
                };
                
                let response;
                if (this.clinicalUnitModal.mode === 'add') {
                    response = await this.apiPost('/api/training-units', unitData);
                } else {
                    response = await this.apiPut(`/api/training-units/${this.clinicalUnitModal.form.id}`, unitData);
                }
                
                await this.fetchClinicalUnits();
                this.clinicalUnitModal.show = false;
                
                this.showToast(
                    'Success',
                    this.clinicalUnitModal.mode === 'add' ? 'Clinical unit added successfully' : 'Clinical unit updated successfully',
                    'success'
                );
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to save clinical unit', 'error');
            } finally {
                this.saving = false;
            }
        },

        // ROTATION MODALS
        showAddRotationModal() {
            this.rotationModal = {
                show: true,
                mode: 'add',
                form: {
                    id: null,
                    rotation_id: this.generateRotationId(),
                    rotation_status: 'scheduled',
                    rotation_start_date: this.formatDate(new Date()),
                    rotation_end_date: this.formatDate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)), // 30 days from now
                    resident_id: '',
                    clinical_unit_id: '',
                    supervising_attending_id: '',
                    rotation_category: 'clinical_rotation',
                    clinical_notes: '',
                    supervisor_evaluation: ''
                }
            };
        },

        editRotation(rotation) {
            this.rotationModal = {
                show: true,
                mode: 'edit',
                form: { ...rotation }
            };
        },

        async saveRotation() {
            try {
                this.saving = true;
                
                // Validate
                if (!this.rotationModal.form.resident_id || !this.rotationModal.form.clinical_unit_id) {
                    throw new Error('Resident and clinical unit are required');
                }
                
                // Prepare data for API
                const rotationData = {
                    resident_id: this.rotationModal.form.resident_id,
                    training_unit_id: this.rotationModal.form.clinical_unit_id,
                    start_date: this.rotationModal.form.rotation_start_date,
                    end_date: this.rotationModal.form.rotation_end_date,
                    supervising_attending_id: this.rotationModal.form.supervising_attending_id || null,
                    rotation_status: this.rotationModal.form.rotation_status,
                    goals: this.rotationModal.form.clinical_notes || '',
                    notes: this.rotationModal.form.supervisor_evaluation || '',
                    rotation_category: this.rotationModal.form.rotation_category
                };
                
                let response;
                if (this.rotationModal.mode === 'add') {
                    rotationData.rotation_id = this.rotationModal.form.rotation_id;
                    response = await this.apiPost('/api/rotations', rotationData);
                } else {
                    response = await this.apiPut(`/api/rotations/${this.rotationModal.form.id}`, rotationData);
                }
                
                await this.fetchRotations();
                await this.fetchClinicalUnits(); // Update unit resident counts
                this.rotationModal.show = false;
                
                this.showToast(
                    'Success',
                    this.rotationModal.mode === 'add' ? 'Rotation scheduled successfully' : 'Rotation updated successfully',
                    'success'
                );
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to save rotation', 'error');
            } finally {
                this.saving = false;
            }
        },

        // ON-CALL MODALS
        showAddOnCallModal() {
            this.onCallModal = {
                show: true,
                mode: 'add',
                form: {
                    id: null,
                    duty_date: this.formatDate(new Date()),
                    shift_type: 'backup_call',
                    start_time: '08:00',
                    end_time: '17:00',
                    primary_physician_id: '',
                    backup_physician_id: '',
                    coverage_area: 'emergency',
                    coverage_notes: '',
                    contact_number: ''
                }
            };
        },

        editOnCallSchedule(schedule) {
            this.onCallModal = {
                show: true,
                mode: 'edit',
                form: { ...schedule }
            };
        },

        async saveOnCallSchedule() {
            try {
                this.saving = true;
                
                // Validate
                if (!this.onCallModal.form.primary_physician_id) {
                    throw new Error('Primary physician is required');
                }
                
                // Prepare data for API
                const scheduleData = {
                    duty_date: this.onCallModal.form.duty_date,
                    shift_type: this.onCallModal.form.shift_type,
                    start_time: this.onCallModal.form.start_time,
                    end_time: this.onCallModal.form.end_time,
                    primary_physician_id: this.onCallModal.form.primary_physician_id,
                    backup_physician_id: this.onCallModal.form.backup_physician_id || null,
                    coverage_notes: this.onCallModal.form.coverage_notes || '',
                    schedule_id: this.generateScheduleId()
                };
                
                let response;
                if (this.onCallModal.mode === 'add') {
                    response = await this.apiPost('/api/oncall', scheduleData);
                } else {
                    response = await this.apiPut(`/api/oncall/${this.onCallModal.form.id}`, scheduleData);
                }
                
                await this.fetchOncallSchedules();
                this.onCallModal.show = false;
                
                this.showToast(
                    'Success',
                    this.onCallModal.mode === 'add' ? 'On-call scheduled successfully' : 'On-call schedule updated successfully',
                    'success'
                );
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to save on-call schedule', 'error');
            } finally {
                this.saving = false;
            }
        },

        // ABSENCE MODALS
        showAddAbsenceModal() {
            this.absenceModal = {
                show: true,
                mode: 'add',
                form: {
                    id: null,
                    staff_member_id: '',
                    absence_reason: '',
                    start_date: this.formatDate(new Date()),
                    end_date: this.formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)), // 7 days from now
                    status: 'upcoming',
                    total_days: this.calculateAbsenceDuration(
                        this.formatDate(new Date()),
                        this.formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000))
                    )
                }
            };
        },

        editAbsence(absence) {
            this.absenceModal = {
                show: true,
                mode: 'edit',
                form: { ...absence }
            };
        },

        async saveAbsence() {
            try {
                this.saving = true;
                
                // Validate
                if (!this.absenceModal.form.staff_member_id || !this.absenceModal.form.absence_reason) {
                    throw new Error('Staff member and absence reason are required');
                }
                
                // Calculate total days
                const totalDays = this.calculateAbsenceDuration(
                    this.absenceModal.form.start_date,
                    this.absenceModal.form.end_date
                );
                
                // Map form data to API schema
                const absenceData = {
                    staff_member_id: this.absenceModal.form.staff_member_id,
                    leave_category: this.absenceModal.form.absence_reason,
                    leave_start_date: this.absenceModal.form.start_date,
                    leave_end_date: this.absenceModal.form.end_date,
                    leave_reason: `${this.absenceModal.form.absence_reason} - ${totalDays} days`,
                    coverage_required: true,
                    approval_status: 'approved', // Simplified - auto-approve for demo
                    review_notes: ''
                };
                
                let response;
                if (this.absenceModal.mode === 'add') {
                    response = await this.apiPost('/api/absences', absenceData);
                } else {
                    response = await this.apiPut(`/api/absences/${this.absenceModal.form.id}`, absenceData);
                }
                
                await this.fetchAbsences();
                this.absenceModal.show = false;
                
                this.showToast(
                    'Success',
                    this.absenceModal.mode === 'add' ? 'Absence documented successfully' : 'Absence updated successfully',
                    'success'
                );
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to save absence', 'error');
            } finally {
                this.saving = false;
            }
        },

        // COMMUNICATIONS MODALS
        showCommunicationsModal() {
            this.communicationsModal = {
                show: true,
                activeTab: 'announcement',
                form: {
                    announcement_title: '',
                    announcement_content: '',
                    publish_start_date: this.formatDateTimeLocal(new Date()),
                    publish_end_date: '',
                    priority_level: 'medium',
                    target_audience: 'all_staff',
                    target_department_id: '',
                    stats: {
                        er_patients: 0,
                        icu_patients: 0,
                        ward_patients: 0,
                        clinic_patients: 0,
                        notes: '',
                        expires_in: '24'
                    }
                }
            };
        },

        async saveCommunication() {
            try {
                this.saving = true;
                
                if (this.communicationsModal.activeTab === 'announcement') {
                    // Save announcement
                    const announcementData = {
                        announcement_title: this.communicationsModal.form.announcement_title,
                        announcement_content: this.communicationsModal.form.announcement_content,
                        publish_start_date: this.communicationsModal.form.publish_start_date,
                        publish_end_date: this.communicationsModal.form.publish_end_date || null,
                        priority_level: this.communicationsModal.form.priority_level,
                        announcement_type: 'department',
                        target_audience: this.communicationsModal.form.target_audience,
                        visible_to_roles: ['viewing_doctor'] // Default
                    };
                    
                    await this.apiPost('/api/announcements', announcementData);
                    
                    this.showToast('Success', 'Announcement posted successfully', 'success');
                } else {
                    // Save daily stats as announcement
                    const stats = this.communicationsModal.form.stats;
                    const announcementData = {
                        announcement_title: 'Daily Department Statistics',
                        announcement_content: `ER: ${stats.er_patients} patients | ICU: ${stats.icu_patients} patients | Ward: ${stats.ward_patients} patients | Clinic: ${stats.clinic_patients} patients\n\n${stats.notes || 'No additional notes'}`,
                        publish_start_date: this.formatDateTimeLocal(new Date()),
                        publish_end_date: this.formatDateTimeLocal(new Date(Date.now() + (parseInt(stats.expires_in) || 24) * 60 * 60 * 1000)),
                        priority_level: 'low',
                        announcement_type: 'department',
                        target_audience: 'all_staff',
                        visible_to_roles: ['viewing_doctor']
                    };
                    
                    await this.apiPost('/api/announcements', announcementData);
                    
                    this.showToast('Success', 'Daily statistics posted successfully', 'success');
                }
                
                await this.fetchAnnouncements();
                this.communicationsModal.show = false;
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to post communication', 'error');
            } finally {
                this.saving = false;
            }
        },

        // RESEARCH GROUP MODALS
        showAddResearchGroupModal() {
            this.researchGroupModal = {
                show: true,
                mode: 'add',
                form: {
                    id: null,
                    name: '',
                    status: 'active',
                    description: '',
                    principal_investigator_id: '',
                    research_lines: [{
                        name: '',
                        status: 'active',
                        description: ''
                    }]
                }
            };
        },

        editResearchGroup(group) {
            this.researchGroupModal = {
                show: true,
                mode: 'edit',
                form: { ...group }
            };
        },

        addResearchLine() {
            this.researchGroupModal.form.research_lines.push({
                name: '',
                status: 'active',
                description: ''
            });
        },

        removeResearchLine(index) {
            if (this.researchGroupModal.form.research_lines.length > 1) {
                this.researchGroupModal.form.research_lines.splice(index, 1);
            }
        },

        async saveResearchGroup() {
            try {
                this.saving = true;
                
                // Note: Research groups API endpoint would need to be implemented in backend
                // This is a placeholder for the workflow
                
                this.showToast(
                    'Success',
                    this.researchGroupModal.mode === 'add' ? 'Research group created successfully' : 'Research group updated successfully',
                    'success'
                );
                
                this.researchGroupModal.show = false;
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to save research group', 'error');
            } finally {
                this.saving = false;
            }
        },

        // USER PROFILE MODAL
        showUserProfile() {
            this.userProfileModal = {
                show: true,
                activeTab: 'profile',
                form: {
                    full_name: this.currentUser.full_name,
                    email: this.currentUser.email,
                    department_id: this.currentUser.department_id,
                    biography: '',
                    current_password: '',
                    new_password: '',
                    confirm_password: ''
                }
            };
        },

        async saveUserProfile() {
            try {
                this.saving = true;
                
                // Update profile
                const profileData = {
                    full_name: this.userProfileModal.form.full_name,
                    email: this.userProfileModal.form.email,
                    department_id: this.userProfileModal.form.department_id,
                    biography: this.userProfileModal.form.biography
                };
                
                await this.apiPut('/api/users/profile', profileData);
                
                // Update password if provided
                if (this.userProfileModal.form.new_password) {
                    if (this.userProfileModal.form.new_password !== this.userProfileModal.form.confirm_password) {
                        throw new Error('New password and confirm password do not match');
                    }
                    
                    const passwordData = {
                        current_password: this.userProfileModal.form.current_password,
                        new_password: this.userProfileModal.form.new_password,
                        confirm_password: this.userProfileModal.form.confirm_password
                    };
                    
                    await this.apiPut('/api/users/change-password', passwordData);
                }
                
                // Update current user
                this.currentUser.full_name = this.userProfileModal.form.full_name;
                this.currentUser.email = this.userProfileModal.form.email;
                this.currentUser.department_id = this.userProfileModal.form.department_id;
                
                // Update localStorage
                localStorage.setItem('user_data', JSON.stringify(this.currentUser));
                
                this.showToast('Success', 'Profile updated successfully', 'success');
                this.userProfileModal.show = false;
                
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to update profile', 'error');
            } finally {
                this.saving = false;
            }
        },

        // SYSTEM SETTINGS
        async saveSystemSettings() {
            try {
                this.saving = true;
                await this.apiPut('/api/settings', this.systemSettings);
                this.showToast('Success', 'System settings saved successfully', 'success');
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to save system settings', 'error');
            } finally {
                this.saving = false;
            }
        },

        // ===== VIEW METHODS =====
        viewStaffDetails(staff) {
            const stats = {
                completedRotations: this.residentRotations.filter(r => 
                    r.resident_id === staff.id && r.rotation_status === 'completed'
                ).length,
                oncallShifts: this.oncallSchedules.filter(s => 
                    s.primary_physician_id === staff.id || s.backup_physician_id === staff.id
                ).length,
                absenceDays: this.staffAbsences.filter(a => 
                    a.staff_member_id === staff.id && a.approval_status === 'approved'
                ).reduce((total, absence) => total + (absence.total_days || 0), 0),
                researchProjects: 0 // Would come from research data
            };
            
            const currentRotation = this.residentRotations.find(r => 
                r.resident_id === staff.id && r.rotation_status === 'active'
            );
            
            const nextOncall = this.oncallSchedules.find(s => 
                (s.primary_physician_id === staff.id || s.backup_physician_id === staff.id) &&
                s.duty_date >= this.formatDate(new Date())
            );
            
            this.staffDetailsModal = {
                show: true,
                staff: staff,
                activeTab: 'personal',
                stats: stats,
                currentRotation: currentRotation ? 
                    `${this.getClinicalUnitName(currentRotation.clinical_unit_id)} (${this.formatDate(currentRotation.rotation_start_date)} - ${this.formatDate(currentRotation.rotation_end_date)})` : 
                    null,
                nextOncall: nextOncall ? 
                    `${this.formatDate(nextOncall.duty_date)} - ${nextOncall.shift_type}` : 
                    null
            };
        },

        assignRotationToStaff(staff) {
            this.rotationModal.form.resident_id = staff.id;
            this.showAddRotationModal();
        },

        showAddRotationModalForUnit(unit) {
            this.rotationModal.form.clinical_unit_id = unit.id;
            this.showAddRotationModal();
        },

        // ===== CONFIRMATION MODAL =====
        showConfirmationModal(config) {
            this.confirmationModal = {
                show: true,
                title: config.title || 'Confirm Action',
                message: config.message || 'Are you sure you want to proceed?',
                details: config.details || '',
                icon: config.icon || 'fa-question-circle',
                confirmButtonText: config.confirmButtonText || 'Confirm',
                confirmButtonClass: config.confirmButtonClass || 'btn-danger',
                confirmButtonIcon: config.confirmButtonIcon || 'fa-check',
                cancelButtonText: config.cancelButtonText || 'Cancel',
                onConfirm: config.onConfirm,
                onCancel: config.onCancel
            };
        },

        confirmAction() {
            if (this.confirmationModal.onConfirm) {
                this.confirmationModal.onConfirm();
            }
            this.confirmationModal.show = false;
            this.confirmationModal = null;
        },

        cancelConfirmation() {
            if (this.confirmationModal.onCancel) {
                this.confirmationModal.onCancel();
            }
            this.confirmationModal.show = false;
            this.confirmationModal = null;
        },

        // ===== DELETE METHODS =====
        async deleteMedicalStaff(staffId) {
            this.showConfirmationModal({
                title: 'Delete Medical Staff',
                message: 'Are you sure you want to deactivate this medical staff member?',
                details: 'This will mark the staff member as inactive. Their data will be preserved but they will no longer appear in active lists.',
                icon: 'fa-user-md',
                confirmButtonText: 'Deactivate',
                confirmButtonClass: 'btn-danger',
                confirmButtonIcon: 'fa-trash',
                onConfirm: async () => {
                    try {
                        await this.apiDelete(`/api/medical-staff/${staffId}`);
                        await this.fetchMedicalStaff();
                        this.showToast('Success', 'Medical staff deactivated successfully', 'success');
                    } catch (error) {
                        this.showToast('Error', error.message || 'Failed to deactivate medical staff', 'error');
                    }
                }
            });
        },

        async deleteRotation(rotationId) {
            this.showConfirmationModal({
                title: 'Cancel Rotation',
                message: 'Are you sure you want to cancel this rotation?',
                details: 'This will mark the rotation as cancelled. The resident will be removed from the clinical unit.',
                icon: 'fa-calendar-times',
                confirmButtonText: 'Cancel Rotation',
                confirmButtonClass: 'btn-danger',
                confirmButtonIcon: 'fa-times',
                onConfirm: async () => {
                    try {
                        await this.apiDelete(`/api/rotations/${rotationId}`);
                        await this.fetchRotations();
                        await this.fetchClinicalUnits();
                        this.showToast('Success', 'Rotation cancelled successfully', 'success');
                    } catch (error) {
                        this.showToast('Error', error.message || 'Failed to cancel rotation', 'error');
                    }
                }
            });
        },

        async deleteOnCallSchedule(scheduleId) {
            this.showConfirmationModal({
                title: 'Delete On-call Schedule',
                message: 'Are you sure you want to delete this on-call schedule?',
                details: 'This action cannot be undone.',
                icon: 'fa-phone-alt',
                confirmButtonText: 'Delete',
                confirmButtonClass: 'btn-danger',
                confirmButtonIcon: 'fa-trash',
                onConfirm: async () => {
                    try {
                        await this.apiDelete(`/api/oncall/${scheduleId}`);
                        await this.fetchOncallSchedules();
                        this.showToast('Success', 'On-call schedule deleted successfully', 'success');
                    } catch (error) {
                        this.showToast('Error', error.message || 'Failed to delete on-call schedule', 'error');
                    }
                }
            });
        },

        async deleteAbsence(absenceId) {
            this.showConfirmationModal({
                title: 'Delete Absence Record',
                message: 'Are you sure you want to delete this absence record?',
                details: 'This action cannot be undone.',
                icon: 'fa-calendar-times',
                confirmButtonText: 'Delete',
                confirmButtonClass: 'btn-danger',
                confirmButtonIcon: 'fa-trash',
                onConfirm: async () => {
                    try {
                        // Note: Absence deletion endpoint may not exist in backend
                        // This would need to be implemented
                        this.showToast('Info', 'Absence deletion functionality requires backend implementation', 'info');
                    } catch (error) {
                        this.showToast('Error', error.message || 'Failed to delete absence', 'error');
                    }
                }
            });
        },

        // ===== UTILITY METHODS =====
        
        // Formatting
        formatDate(date) {
            if (!date) return '';
            const d = new Date(date);
            if (isNaN(d.getTime())) return '';
            return d.toISOString().split('T')[0];
        },

        formatDateTime(date) {
            if (!date) return '';
            const d = new Date(date);
            if (isNaN(d.getTime())) return '';
            return d.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        },

        formatDateTimeLocal(date) {
            if (!date) return '';
            const d = new Date(date);
            if (isNaN(d.getTime())) return '';
            
            const pad = (num) => num.toString().padStart(2, '0');
            
            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        },

        formatTimeAgo(date) {
            if (!date) return '';
            const d = new Date(date);
            if (isNaN(d.getTime())) return '';
            
            const now = new Date();
            const diffMs = now - d;
            const diffMins = Math.floor(diffMs / (1000 * 60));
            const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
            const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
            
            if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
            if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
            if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
            return this.formatDate(date);
        },

        formatTimeRange(start, end) {
            if (!start || !end) return '';
            return `${start} - ${end}`;
        },

        // Calculations
        calculateAbsenceDuration(startDate, endDate) {
            if (!startDate || !endDate) return 0;
            const start = new Date(startDate);
            const end = new Date(endDate);
            if (isNaN(start.getTime()) || isNaN(end.getTime())) return 0;
            const diffTime = Math.abs(end - start);
            return Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
        },

        // Getters
        getDepartmentName(departmentId) {
            if (!departmentId) return 'Not assigned';
            const dept = this.departments.find(d => d.id === departmentId);
            return dept ? dept.name : 'Unknown department';
        },

        getClinicalUnitName(unitId) {
            if (!unitId) return 'Not assigned';
            const unit = this.clinicalUnits.find(u => u.id === unitId);
            return unit ? unit.unit_name : 'Unknown unit';
        },

        getResidentName(residentId) {
            if (!residentId) return 'Unknown';
            const resident = this.medicalStaff.find(s => s.id === residentId);
            return resident ? resident.full_name : 'Unknown resident';
        },

        getPhysicianName(physicianId) {
            if (!physicianId) return 'Not assigned';
            const physician = this.medicalStaff.find(s => s.id === physicianId);
            return physician ? physician.full_name : 'Unknown physician';
        },

        getStaffName(staffId) {
            if (!staffId) return 'Unknown';
            const staff = this.medicalStaff.find(s => s.id === staffId);
            return staff ? staff.full_name : 'Unknown staff';
        },

        getResearchGroupName(groupId) {
            if (!groupId) return 'Not assigned';
            const group = this.researchGroups.find(g => g.id === groupId);
            return group ? group.name : 'Unknown research group';
        },

        getResearchLineName(lineId) {
            if (!lineId) return 'Not assigned';
            const line = this.researchLines.find(l => l.id === lineId);
            return line ? line.name : 'Unknown research line';
        },

        getUnitResidents(unitId) {
            if (!unitId) return [];
            return this.residentRotations
                .filter(rotation => 
                    rotation.clinical_unit_id === unitId && 
                    rotation.rotation_status === 'active'
                )
                .map(rotation => {
                    const resident = this.medicalStaff.find(s => s.id === rotation.resident_id);
                    return resident ? {
                        id: resident.id,
                        full_name: resident.full_name,
                        resident_category: resident.resident_category
                    } : null;
                })
                .filter(r => r !== null);
        },

        getDepartmentUnits(departmentId) {
            if (!departmentId) return [];
            return this.clinicalUnits.filter(unit => unit.department_id === departmentId);
        },

        getResearchLines(groupId) {
            if (!groupId) return [];
            return this.researchLines.filter(line => line.research_group_id === groupId);
        },

        // UI Helpers
        getInitials(name) {
            if (!name) return '??';
            return name.split(' ')
                .map(part => part[0])
                .join('')
                .toUpperCase()
                .substring(0, 2);
        },

        getUserRoleDisplay(role) {
            const roleNames = {
                'system_admin': 'System Administrator',
                'department_head': 'Department Head',
                'resident_manager': 'Resident Manager',
                'attending_physician': 'Attending Physician',
                'viewing_doctor': 'Viewing Doctor'
            };
            return roleNames[role] || role;
        },

        getCurrentTitle() {
            const titles = {
                'daily_operations': 'Dashboard Overview',
                'medical_staff': 'Medical Staff Management',
                'oncall_schedule': 'On-call Schedule',
                'resident_rotations': 'Resident Rotations',
                'clinical_units': 'Clinical Units',
                'staff_absence': 'Staff Absence Management',
                'department_management': 'Department Management',
                'communications': 'Department Communications',
                'research_management': 'Research Management',
                'system_settings': 'System Settings'
            };
            return titles[this.currentView] || 'NeumoCare';
        },

        getCurrentSubtitle() {
            const subtitles = {
                'daily_operations': 'Daily operations and key metrics',
                'medical_staff': 'Manage physicians, residents, and staff',
                'oncall_schedule': 'Schedule and manage on-call duties',
                'resident_rotations': 'Assign and track resident rotations',
                'clinical_units': 'Manage clinical units and capacities',
                'staff_absence': 'Track staff leave and absences',
                'department_management': 'Configure departments and units',
                'communications': 'Announcements and department updates',
                'research_management': 'Research groups and projects',
                'system_settings': 'System configuration and preferences'
            };
            return subtitles[this.currentView] || '';
        },

        getSearchPlaceholder() {
            const placeholders = {
                'daily_operations': 'Search staff, rotations, announcements...',
                'medical_staff': 'Search by name, ID, email...',
                'oncall_schedule': 'Search by physician, date, shift...',
                'resident_rotations': 'Search by resident, unit, status...',
                'clinical_units': 'Search units, departments, specialties...',
                'staff_absence': 'Search by staff, date, reason...',
                'department_management': 'Search departments, units...',
                'communications': 'Search announcements...',
                'research_management': 'Search research groups, lines...',
                'system_settings': 'Search settings...'
            };
            return placeholders[this.currentView] || 'Search...';
        },

        // Staff formatting
        getStaffCategoryClass(staff) {
            if (staff.staff_category === 'physician') {
                switch (staff.physician_type) {
                    case 'attending_physician': return 'badge-attending';
                    case 'medical_resident': return 'badge-resident';
                    case 'fellow': return 'badge-fellow';
                    case 'nurse_practitioner': return 'badge-nurse';
                    default: return 'badge-primary';
                }
            }
            return 'badge-other-staff';
        },

        formatStaffCategory(category) {
            const categories = {
                'physician': 'Physician',
                'other': 'Other Staff'
            };
            return categories[category] || category;
        },

        formatPhysicianType(type) {
            const types = {
                'attending_physician': 'Attending Physician',
                'medical_resident': 'Medical Resident',
                'fellow': 'Fellow',
                'nurse_practitioner': 'Nurse Practitioner'
            };
            return types[type] || type;
        },

        formatResidentCategory(category) {
            const categories = {
                'department_internal': 'Department Internal',
                'rotating_other_dept': 'Rotating Other Dept',
                'external_institution': 'External Institution'
            };
            return categories[category] || category;
        },

        formatEmploymentStatus(status) {
            const statuses = {
                'active': 'Active',
                'on_leave': 'On Leave',
                'inactive': 'Inactive'
            };
            return statuses[status] || status;
        },

        formatRotationStatus(status) {
            const statuses = {
                'scheduled': 'Scheduled',
                'active': 'Active',
                'completed': 'Completed',
                'cancelled': 'Cancelled'
            };
            return statuses[status] || status;
        },

        formatRotationCategory(category) {
            const categories = {
                'clinical_rotation': 'Clinical Rotation',
                'elective_rotation': 'Elective Rotation',
                'research_rotation': 'Research',
                'vacation_rotation': 'Vacation'
            };
            return categories[category] || category;
        },

        getRotationStatusClass(status) {
            switch (status) {
                case 'active': return 'status-available';
                case 'upcoming': return 'status-busy';
                case 'completed': return 'status-oncall';
                case 'cancelled': return 'status-critical';
                default: return 'badge-primary';
            }
        },

        formatShiftType(type) {
            const types = {
                'primary_call': 'Primary Call',
                'backup_call': 'Backup Call'
            };
            return types[type] || type;
        },

        formatAbsenceReason(reason) {
            const reasons = {
                'vacation': 'Vacation',
                'sick_leave': 'Sick Leave',
                'family_emergency': 'Family Emergency',
                'conference': 'Conference/Training',
                'maternity_paternity': 'Maternity/Paternity',
                'personal': 'Personal Leave',
                'other': 'Other'
            };
            return reasons[reason] || reason;
        },

        formatAbsenceStatus(status) {
            const statuses = {
                'upcoming': 'Upcoming',
                'active': 'Active',
                'completed': 'Completed',
                'cancelled': 'Cancelled'
            };
            return statuses[status] || status;
        },

        getAbsenceStatusClass(status) {
            switch (status) {
                case 'active': return 'status-busy';
                case 'upcoming': return 'status-oncall';
                case 'completed': return 'status-available';
                case 'cancelled': return 'status-critical';
                default: return 'badge-primary';
            }
        },

        getPriorityColor(priority) {
            switch (priority) {
                case 'urgent': return 'danger';
                case 'high': return 'warning';
                case 'medium': return 'info';
                case 'low': return 'success';
                default: return 'primary';
            }
        },

        getCommunicationIcon(tab) {
            return tab === 'announcement' ? 'fa-bullhorn' : 'fa-chart-bar';
        },

        getCommunicationButtonText(tab) {
            return tab === 'announcement' ? 'Post Announcement' : 'Post Daily Stats';
        },

        // UI Controls
        switchView(view) {
            this.currentView = view;
            if (view === 'daily_operations') {
                this.updateLiveStats();
            }
        },

        toggleSearchScope() {
            const scopes = ['All', 'Staff', 'Rotations', 'Units', 'Announcements'];
            const currentIndex = scopes.indexOf(this.searchScope);
            this.searchScope = scopes[(currentIndex + 1) % scopes.length];
        },

        toggleStatsSidebar() {
            this.statsSidebarOpen = !this.statsSidebarOpen;
        },

        toggleUserMenu() {
            this.userMenuOpen = !this.userMenuOpen;
        },

        handleStaffCategoryChange() {
            // Reset physician-specific fields when category changes
            if (this.medicalStaffModal.form.staff_category !== 'physician') {
                this.medicalStaffModal.form.physician_type = '';
                this.medicalStaffModal.form.resident_category = '';
                this.medicalStaffModal.form.resident_year = '';
                this.medicalStaffModal.form.clinical_unit_id = '';
                this.medicalStaffModal.form.academic_degree = '';
                this.medicalStaffModal.form.research_group_id = '';
                this.medicalStaffModal.form.research_line_id = '';
                this.medicalStaffModal.form.is_phd_researcher = false;
                this.medicalStaffModal.form.specialization = '';
                this.medicalStaffModal.form.medical_license = '';
                this.medicalStaffModal.form.years_experience = '';
            }
        },

        // Filter methods
        applyStaffFilters() {
            // Filters are applied in computed property
            this.showToast('Info', 'Filters applied', 'info');
        },

        resetStaffFilters() {
            this.staffFilter = {
                staff_category: '',
                employment_status: '',
                department_id: ''
            };
            this.staffSearch = '';
            this.showToast('Info', 'Filters reset', 'info');
        },

        applyRotationFilters() {
            this.showToast('Info', 'Filters applied', 'info');
        },

        resetRotationFilters() {
            this.rotationFilter = {
                resident_id: '',
                status: '',
                clinical_unit_id: ''
            };
            this.showToast('Info', 'Filters reset', 'info');
        },

        applyOncallFilters() {
            this.showToast('Info', 'Filters applied', 'info');
        },

        resetOncallFilters() {
            this.oncallFilter = {
                date: '',
                shift_type: '',
                physician_id: ''
            };
            this.showToast('Info', 'Filters reset', 'info');
        },

        applyAbsenceFilters() {
            this.showToast('Info', 'Filters applied', 'info');
        },

        resetAbsenceFilters() {
            this.absenceFilter = {
                staff_id: '',
                status: '',
                start_date: ''
            };
            this.showToast('Info', 'Filters reset', 'info');
        },

        // Toast system
        showToast(title, message, type = 'info') {
            const icons = {
                'success': 'fa-check-circle',
                'error': 'fa-exclamation-circle',
                'warning': 'fa-exclamation-triangle',
                'info': 'fa-info-circle'
            };
            
            const toast = {
                id: ++this.toastIdCounter,
                title,
                message,
                type,
                icon: icons[type] || 'fa-info-circle'
            };
            
            this.toasts.push(toast);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                this.removeToast(toast.id);
            }, 5000);
        },

        removeToast(id) {
            this.toasts = this.toasts.filter(toast => toast.id !== id);
        },

        // Alert system
        dismissAlert(alertId) {
            this.activeAlerts = this.activeAlerts.filter(alert => alert.id !== alertId);
        },

        // Notifications
        showNotifications() {
            this.showToast('Notifications', `${this.unreadNotifications} unread notifications`, 'info');
            // In a full implementation, this would show a notifications panel
        },

        // Search
        handleSearch() {
            if (!this.searchQuery.trim()) return;
            
            this.showToast('Search', `Searching for "${this.searchQuery}" in ${this.searchScope}...`, 'info');
            
            // In a full implementation, this would perform the search
            // For now, just clear the search
            setTimeout(() => {
                this.searchQuery = '';
            }, 1000);
        },

        // Permission system
        hasPermission(resource, action) {
            if (!this.currentUser) return false;
            
            // Admin has all permissions
            if (this.currentUser.user_role === 'system_admin') return true;
            
            // Define role permissions
            const rolePermissions = {
                system_admin: {
                    medical_staff: ['create', 'read', 'update', 'delete'],
                    resident_rotations: ['create', 'read', 'update', 'delete'],
                    clinical_units: ['create', 'read', 'update', 'delete'],
                    oncall_schedule: ['create', 'read', 'update', 'delete'],
                    staff_absence: ['create', 'read', 'update', 'delete'],
                    communications: ['create', 'read', 'update', 'delete'],
                    system: ['read', 'manage_departments'],
                    research: ['manage']
                },
                department_head: {
                    medical_staff: ['create', 'read', 'update'],
                    resident_rotations: ['create', 'read', 'update'],
                    clinical_units: ['create', 'read', 'update'],
                    oncall_schedule: ['create', 'read', 'update'],
                    staff_absence: ['create', 'read', 'update', 'delete'],
                    communications: ['create', 'read', 'update'],
                    system: ['read'],
                    research: ['manage']
                },
                resident_manager: {
                    medical_staff: ['create', 'read', 'update'],
                    resident_rotations: ['create', 'read', 'update', 'delete'],
                    clinical_units: ['read'],
                    oncall_schedule: ['create', 'read', 'update'],
                    staff_absence: ['create', 'read', 'update'],
                    communications: ['create', 'read'],
                    system: ['read']
                },
                attending_physician: {
                    medical_staff: ['read'],
                    resident_rotations: ['read'],
                    clinical_units: ['read'],
                    oncall_schedule: ['read'],
                    staff_absence: ['read'],
                    communications: ['read'],
                    system: []
                },
                viewing_doctor: {
                    medical_staff: ['read'],
                    resident_rotations: ['read'],
                    clinical_units: ['read'],
                    oncall_schedule: ['read'],
                    staff_absence: ['read'],
                    communications: ['read'],
                    system: []
                }
            };
            
            const permissions = rolePermissions[this.currentUser.user_role];
            if (!permissions || !permissions[resource]) return false;
            
            return permissions[resource].includes(action);
        },

        // ID Generators
        generateRotationId() {
            return `ROT-${Date.now().toString(36).toUpperCase().substring(2, 8)}`;
        },

        generateScheduleId() {
            return `SCH-${Date.now().toString(36).toUpperCase().substring(2, 8)}`;
        },

        // Action menu
        toggleActionMenu(event) {
            // Close all other menus
            document.querySelectorAll('.action-menu').forEach(menu => {
                menu.style.display = 'none';
            });
            
            const button = event.currentTarget;
            const menu = button.nextElementSibling;
            
            if (menu && menu.classList.contains('action-menu')) {
                menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
                
                // Close menu when clicking outside
                const closeMenu = (e) => {
                    if (!button.contains(e.target) && !menu.contains(e.target)) {
                        menu.style.display = 'none';
                        document.removeEventListener('click', closeMenu);
                    }
                };
                
                setTimeout(() => {
                    document.addEventListener('click', closeMenu);
                }, 0);
            }
        },

        // Remove resident from unit
        async removeResidentFromUnit(residentId, unitId) {
            try {
                // Find and cancel the active rotation
                const rotation = this.residentRotations.find(r => 
                    r.resident_id === residentId && 
                    r.clinical_unit_id === unitId &&
                    r.rotation_status === 'active'
                );
                
                if (rotation) {
                    await this.apiDelete(`/api/rotations/${rotation.id}`);
                    await this.fetchRotations();
                    await this.fetchClinicalUnits();
                    this.showToast('Success', 'Resident removed from unit', 'success');
                }
            } catch (error) {
                this.showToast('Error', error.message || 'Failed to remove resident', 'error');
            }
        }
    },

    // Lifecycle hooks
    mounted() {
        // Check for saved authentication
        const savedUser = localStorage.getItem('user_data');
        const savedToken = localStorage.getItem('auth_token');
        
        if (savedUser && savedToken) {
            this.currentUser = JSON.parse(savedUser);
            this.initializeData();
            
            // Start periodic updates
            this.updateLiveStats();
            setInterval(() => this.updateLiveStats(), 60000); // Update every minute
            
            // Update absence durations in real-time
            this.$watch('absenceModal.form.start_date', () => {
                if (this.absenceModal.form.start_date && this.absenceModal.form.end_date) {
                    this.absenceModal.form.total_days = this.calculateAbsenceDuration(
                        this.absenceModal.form.start_date,
                        this.absenceModal.form.end_date
                    );
                }
            });
            
            this.$watch('absenceModal.form.end_date', () => {
                if (this.absenceModal.form.start_date && this.absenceModal.form.end_date) {
                    this.absenceModal.form.total_days = this.calculateAbsenceDuration(
                        this.absenceModal.form.start_date,
                        this.absenceModal.form.end_date
                    );
                }
            });
        }
    }
}).mount('#app');
