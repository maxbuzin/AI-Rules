# Security Standards & Protocols

## 🔒 Overview

This document establishes comprehensive security standards for Next.js 15 applications with Supabase backend. These guidelines ensure robust protection through Row Level Security (RLS), secure authentication, and proper separation of client/server code.

## 🛡️ Supabase Security Framework

### Row Level Security (RLS) - Enabled by Default
```sql
-- ✅ GOOD: Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;

-- ✅ GOOD: Least-privilege policies
-- Users can only read their own data
CREATE POLICY "Users can view own profile" ON users
  FOR SELECT USING (auth.uid() = id);

-- Users can only update their own data
CREATE POLICY "Users can update own profile" ON users
  FOR UPDATE USING (auth.uid() = id);

-- Public posts are readable by authenticated users
CREATE POLICY "Authenticated users can view public posts" ON posts
  FOR SELECT USING (auth.role() = 'authenticated' AND is_public = true);

-- Users can only modify their own posts
CREATE POLICY "Users can manage own posts" ON posts
  FOR ALL USING (auth.uid() = user_id);
```

### Client/Server Code Separation
```typescript
// ✅ GOOD: Server-side operations (never expose service keys)
// app/actions/user-actions.ts
import { createServerActionClient } from '@supabase/auth-helpers-nextjs'
import { cookies } from 'next/headers'

export async function deleteUser(userId: string) {
  'use server'
  
  // Use service role client for admin operations
  const supabase = createServerActionClient({ 
    cookies,
    supabaseKey: process.env.SUPABASE_SERVICE_ROLE_KEY // Server-only
  })
  
  const { error } = await supabase.auth.admin.deleteUser(userId)
  if (error) throw new Error('Failed to delete user')
}

// ✅ GOOD: Client-side operations (anon/authenticated keys only)
// components/user-profile.tsx
'use client'
import { createClientComponentClient } from '@supabase/auth-helpers-nextjs'

export function UserProfile() {
  const supabase = createClientComponentClient() // Uses anon key
  
  // Client can only access data allowed by RLS policies
  const { data: profile } = await supabase
    .from('users')
    .select('*')
    .eq('id', user.id)
    .single()
    
  return <div>{profile?.name}</div>
}
```

This document establishes comprehensive security standards, protocols, and best practices applicable to any development project. These guidelines ensure applications are built with security-first principles and maintain robust protection against common threats.

## 🛡️ Security Principles

### Core Security Principles
```yaml
Defense in Depth:
  Description: Multiple layers of security controls
  Implementation:
    - Network security (firewalls, VPNs)
    - Application security (input validation, authentication)
    - Data security (encryption, access controls)
    - Infrastructure security (hardened systems, monitoring)

Least Privilege:
  Description: Minimum necessary access rights
  Implementation:
    - Role-based access control (RBAC)
    - Just-in-time access provisioning
    - Regular access reviews and audits
    - Principle of need-to-know

Zero Trust:
  Description: Never trust, always verify
  Implementation:
    - Verify every user and device
    - Continuous authentication and authorization
    - Micro-segmentation of network access
    - Comprehensive logging and monitoring

Secure by Default:
  Description: Security built into the foundation
  Implementation:
    - Secure configuration templates
    - Default deny policies
    - Automatic security updates
    - Security-first development practices

Fail Securely:
  Description: Fail to a secure state
  Implementation:
    - Graceful error handling
    - No sensitive data in error messages
    - Secure fallback mechanisms
    - Comprehensive logging of failures

Privacy by Design:
  Description: Privacy considerations from the start
  Implementation:
    - Data minimization principles
    - Purpose limitation for data collection
    - Consent management systems
    - Data retention and deletion policies
```

## 🔐 Authentication & Authorization

### Authentication Standards
```typescript
// ✅ GOOD: Secure authentication implementation
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';

// Password validation schema
const passwordSchema = z.string()
  .min(12, 'Password must be at least 12 characters')
  .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
    'Password must contain uppercase, lowercase, number, and special character');

// User registration with secure password hashing
class AuthService {
  private readonly saltRounds = 12;
  private readonly jwtSecret = process.env.JWT_SECRET!;
  private readonly jwtExpiry = '15m'; // Short-lived tokens
  private readonly refreshTokenExpiry = '7d';

  async registerUser(email: string, password: string): Promise<User> {
    // Validate input
    const validatedPassword = passwordSchema.parse(password);
    
    // Hash password with salt
    const hashedPassword = await bcrypt.hash(validatedPassword, this.saltRounds);
    
    // Create user with hashed password
    const user = await this.userRepository.create({
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      emailVerified: false,
      createdAt: new Date(),
      lastLogin: null,
      failedLoginAttempts: 0,
      accountLocked: false,
    });

    // Send email verification
    await this.sendEmailVerification(user);
    
    return user;
  }

  async authenticateUser(email: string, password: string): Promise<AuthResult> {
    const user = await this.userRepository.findByEmail(email.toLowerCase().trim());
    
    if (!user) {
      // Prevent user enumeration - same response time
      await bcrypt.hash(password, this.saltRounds);
      throw new AuthError('Invalid credentials');
    }

    // Check account lock status
    if (user.accountLocked) {
      throw new AuthError('Account is locked. Please contact support.');
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      await this.handleFailedLogin(user);
      throw new AuthError('Invalid credentials');
    }

    // Reset failed attempts on successful login
    await this.resetFailedAttempts(user);
    
    // Generate tokens
    const accessToken = this.generateAccessToken(user);
    const refreshToken = this.generateRefreshToken(user);
    
    // Update last login
    await this.userRepository.updateLastLogin(user.id);
    
    return {
      user: this.sanitizeUser(user),
      accessToken,
      refreshToken,
      expiresIn: this.jwtExpiry,
    };
  }

  private generateAccessToken(user: User): string {
    return jwt.sign(
      {
        sub: user.id,
        email: user.email,
        roles: user.roles,
        iat: Math.floor(Date.now() / 1000),
      },
      this.jwtSecret,
      {
        expiresIn: this.jwtExpiry,
        issuer: 'your-app',
        audience: 'your-app-users',
      }
    );
  }

  private async handleFailedLogin(user: User): Promise<void> {
    const updatedAttempts = user.failedLoginAttempts + 1;
    const shouldLock = updatedAttempts >= 5;
    
    await this.userRepository.update(user.id, {
      failedLoginAttempts: updatedAttempts,
      accountLocked: shouldLock,
      lockedAt: shouldLock ? new Date() : null,
    });

    if (shouldLock) {
      await this.notifyAccountLocked(user);
    }
  }
}

// Rate limiting for authentication endpoints
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Rate limit exceeded',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000),
    });
  },
});
```

### Authorization Framework
```typescript
// ✅ GOOD: Role-based access control (RBAC)
interface Permission {
  resource: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'admin';
  conditions?: Record<string, any>;
}

interface Role {
  id: string;
  name: string;
  permissions: Permission[];
  inherits?: string[]; // Role inheritance
}

class AuthorizationService {
  private roles: Map<string, Role> = new Map();
  private userRoles: Map<string, string[]> = new Map();

  // Check if user has permission for specific action
  async hasPermission(
    userId: string, 
    resource: string, 
    action: string, 
    context?: Record<string, any>
  ): Promise<boolean> {
    const userRoles = await this.getUserRoles(userId);
    
    for (const roleName of userRoles) {
      const role = this.roles.get(roleName);
      if (!role) continue;
      
      // Check direct permissions
      if (await this.checkRolePermission(role, resource, action, context)) {
        return true;
      }
      
      // Check inherited permissions
      if (role.inherits) {
        for (const inheritedRole of role.inherits) {
          const parentRole = this.roles.get(inheritedRole);
          if (parentRole && await this.checkRolePermission(parentRole, resource, action, context)) {
            return true;
          }
        }
      }
    }
    
    return false;
  }

  private async checkRolePermission(
    role: Role, 
    resource: string, 
    action: string, 
    context?: Record<string, any>
  ): Promise<boolean> {
    for (const permission of role.permissions) {
      if (permission.resource === resource && permission.action === action) {
        // Check conditions if present
        if (permission.conditions && context) {
          return this.evaluateConditions(permission.conditions, context);
        }
        return true;
      }
    }
    return false;
  }

  private evaluateConditions(conditions: Record<string, any>, context: Record<string, any>): boolean {
    // Simple condition evaluation - can be extended
    for (const [key, value] of Object.entries(conditions)) {
      if (context[key] !== value) {
        return false;
      }
    }
    return true;
  }
}

// Authorization middleware
function requirePermission(resource: string, action: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = req.user; // From authentication middleware
      if (!user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const authService = new AuthorizationService();
      const hasPermission = await authService.hasPermission(
        user.id, 
        resource, 
        action, 
        { userId: user.id, ...req.params }
      );

      if (!hasPermission) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }

      next();
    } catch (error) {
      res.status(500).json({ error: 'Authorization check failed' });
    }
  };
}

// Usage example
app.get('/api/users/:id', 
  authenticateToken,
  requirePermission('user', 'read'),
  getUserHandler
);
```

## 🛡️ Input Validation & Sanitization

### Input Validation Standards
```typescript
// ✅ GOOD: Comprehensive input validation
import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';
import validator from 'validator';

// Schema definitions for common data types
const emailSchema = z.string()
  .email('Invalid email format')
  .max(254, 'Email too long')
  .transform(email => email.toLowerCase().trim());

const phoneSchema = z.string()
  .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format');

const urlSchema = z.string()
  .url('Invalid URL format')
  .max(2048, 'URL too long');

const htmlContentSchema = z.string()
  .max(10000, 'Content too long')
  .transform(content => DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li'],
    ALLOWED_ATTR: [],
  }));

// SQL injection prevention
class DatabaseService {
  // ✅ GOOD: Using parameterized queries
  async getUserById(id: string): Promise<User | null> {
    const userIdSchema = z.string().uuid('Invalid user ID format');
    const validatedId = userIdSchema.parse(id);
    
    const query = 'SELECT * FROM users WHERE id = $1';
    const result = await this.db.query(query, [validatedId]);
    
    return result.rows[0] || null;
  }

  // ✅ GOOD: Input sanitization for search
  async searchUsers(searchTerm: string): Promise<User[]> {
    const searchSchema = z.string()
      .min(1, 'Search term required')
      .max(100, 'Search term too long')
      .regex(/^[a-zA-Z0-9\s\-_.@]+$/, 'Invalid characters in search term');
    
    const sanitizedTerm = searchSchema.parse(searchTerm);
    
    const query = `
      SELECT * FROM users 
      WHERE LOWER(name) LIKE LOWER($1) 
      OR LOWER(email) LIKE LOWER($1)
      LIMIT 50
    `;
    
    const result = await this.db.query(query, [`%${sanitizedTerm}%`]);
    return result.rows;
  }
}

// XSS prevention
class ContentService {
  // ✅ GOOD: HTML sanitization
  sanitizeHtmlContent(content: string): string {
    return DOMPurify.sanitize(content, {
      ALLOWED_TAGS: [
        'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote'
      ],
      ALLOWED_ATTR: ['href', 'title'],
      ALLOWED_URI_REGEXP: /^https?:\/\//,
    });
  }

  // ✅ GOOD: Safe HTML rendering component
  SafeHtml({ content }: { content: string }) {
    const sanitizedContent = this.sanitizeHtmlContent(content);
    return (
      <div 
        dangerouslySetInnerHTML={{ __html: sanitizedContent }}
        className="safe-content"
      />
    );
  }

  // ✅ GOOD: Text escaping for dynamic content
  escapeHtml(text: string): string {
    const htmlEscapes: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
    };
    
    return text.replace(/[&<>"'\/]/g, (match) => htmlEscapes[match]);
  }
}

// File upload security
class FileUploadService {
  private readonly allowedMimeTypes = [
    'image/jpeg',
    'image/png', 
    'image/gif',
    'image/webp',
    'application/pdf',
    'text/plain',
  ];
  
  private readonly maxFileSize = 10 * 1024 * 1024; // 10MB
  
  async validateFile(file: Express.Multer.File): Promise<void> {
    // Check file size
    if (file.size > this.maxFileSize) {
      throw new ValidationError('File size exceeds limit');
    }
    
    // Check MIME type
    if (!this.allowedMimeTypes.includes(file.mimetype)) {
      throw new ValidationError('File type not allowed');
    }
    
    // Check file extension
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.txt'];
    const fileExtension = path.extname(file.originalname).toLowerCase();
    
    if (!allowedExtensions.includes(fileExtension)) {
      throw new ValidationError('File extension not allowed');
    }
    
    // Scan for malware (if antivirus service available)
    await this.scanForMalware(file);
  }
  
  private async scanForMalware(file: Express.Multer.File): Promise<void> {
    // Implementation depends on antivirus service
    // Example: ClamAV, VirusTotal API, etc.
  }
}
```

## 🔒 Data Protection

### Encryption Standards
```typescript
// ✅ GOOD: Data encryption implementation
import crypto from 'crypto';
import bcrypt from 'bcrypt';

class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32; // 256 bits
  private readonly ivLength = 16;  // 128 bits
  private readonly tagLength = 16; // 128 bits
  
  // Generate secure random key
  generateKey(): Buffer {
    return crypto.randomBytes(this.keyLength);
  }
  
  // Encrypt sensitive data
  encrypt(plaintext: string, key: Buffer): EncryptedData {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipher(this.algorithm, key);
    cipher.setAAD(Buffer.from('additional-auth-data'));
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
    };
  }
  
  // Decrypt sensitive data
  decrypt(encryptedData: EncryptedData, key: Buffer): string {
    const decipher = crypto.createDecipher(this.algorithm, key);
    decipher.setAAD(Buffer.from('additional-auth-data'));
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
  
  // Hash passwords securely
  async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }
  
  // Verify password hash
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
  
  // Generate secure tokens
  generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }
  
  // Hash sensitive data (one-way)
  hashData(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }
}

interface EncryptedData {
  encrypted: string;
  iv: string;
  tag: string;
}

// Database encryption for sensitive fields
class SecureUserService {
  private encryptionService = new EncryptionService();
  private encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  
  async createUser(userData: CreateUserData): Promise<User> {
    // Encrypt sensitive fields
    const encryptedSSN = userData.ssn ? 
      this.encryptionService.encrypt(userData.ssn, this.encryptionKey) : null;
    
    const encryptedPhone = userData.phone ?
      this.encryptionService.encrypt(userData.phone, this.encryptionKey) : null;
    
    // Hash password
    const hashedPassword = await this.encryptionService.hashPassword(userData.password);
    
    return this.userRepository.create({
      ...userData,
      password: hashedPassword,
      ssn: encryptedSSN,
      phone: encryptedPhone,
    });
  }
  
  async getUserWithDecryptedData(userId: string): Promise<User> {
    const user = await this.userRepository.findById(userId);
    
    if (user.ssn) {
      user.ssn = this.encryptionService.decrypt(user.ssn, this.encryptionKey);
    }
    
    if (user.phone) {
      user.phone = this.encryptionService.decrypt(user.phone, this.encryptionKey);
    }
    
    return user;
  }
}
```

### Data Privacy & GDPR Compliance
```typescript
// ✅ GOOD: GDPR compliance implementation
class PrivacyService {
  // Data subject rights implementation
  async handleDataSubjectRequest(request: DataSubjectRequest): Promise<void> {
    switch (request.type) {
      case 'access':
        await this.handleAccessRequest(request);
        break;
      case 'rectification':
        await this.handleRectificationRequest(request);
        break;
      case 'erasure':
        await this.handleErasureRequest(request);
        break;
      case 'portability':
        await this.handlePortabilityRequest(request);
        break;
      case 'restriction':
        await this.handleRestrictionRequest(request);
        break;
      default:
        throw new Error('Unknown request type');
    }
  }
  
  // Right to access (Article 15)
  private async handleAccessRequest(request: DataSubjectRequest): Promise<void> {
    const userData = await this.collectUserData(request.userId);
    const report = this.generateDataReport(userData);
    
    await this.sendDataReport(request.email, report);
    await this.logDataAccess(request);
  }
  
  // Right to erasure (Article 17)
  private async handleErasureRequest(request: DataSubjectRequest): Promise<void> {
    // Check if erasure is legally required
    const canErase = await this.validateErasureRequest(request);
    
    if (!canErase) {
      throw new Error('Erasure not permitted due to legal obligations');
    }
    
    // Anonymize or delete data
    await this.anonymizeUserData(request.userId);
    await this.logDataErasure(request);
  }
  
  // Data retention policy
  async enforceRetentionPolicy(): Promise<void> {
    const retentionPolicies = [
      { dataType: 'user_activity', retentionDays: 365 },
      { dataType: 'audit_logs', retentionDays: 2555 }, // 7 years
      { dataType: 'marketing_data', retentionDays: 730 }, // 2 years
    ];
    
    for (const policy of retentionPolicies) {
      await this.deleteExpiredData(policy.dataType, policy.retentionDays);
    }
  }
  
  // Consent management
  async updateConsent(userId: string, consentData: ConsentData): Promise<void> {
    const consent = {
      userId,
      ...consentData,
      timestamp: new Date(),
      ipAddress: consentData.ipAddress,
      userAgent: consentData.userAgent,
    };
    
    await this.consentRepository.create(consent);
    await this.updateUserPreferences(userId, consentData.preferences);
  }
}

interface DataSubjectRequest {
  id: string;
  userId: string;
  email: string;
  type: 'access' | 'rectification' | 'erasure' | 'portability' | 'restriction';
  reason?: string;
  createdAt: Date;
}

interface ConsentData {
  marketing: boolean;
  analytics: boolean;
  functional: boolean;
  preferences: Record<string, boolean>;
  ipAddress: string;
  userAgent: string;
}
```

## 🌐 API Security

### API Security Standards
```typescript
// ✅ GOOD: Comprehensive API security
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';

// Rate limiting configuration
const createRateLimit = (windowMs: number, max: number, message: string) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter: Math.ceil(req.rateLimit.resetTime / 1000),
      });
    },
  });
};

// Different rate limits for different endpoints
const authRateLimit = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  5, // 5 attempts
  'Too many authentication attempts'
);

const apiRateLimit = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  100, // 100 requests
  'Too many API requests'
);

const strictRateLimit = createRateLimit(
  60 * 1000, // 1 minute
  10, // 10 requests
  'Rate limit exceeded for sensitive operations'
);

// Security middleware setup
function setupSecurity(app: Express) {
  // Helmet for security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'", 'https://api.yourdomain.com'],
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
  }));
  
  // CORS configuration
  app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 86400, // 24 hours
  }));
  
  // Global rate limiting
  app.use('/api/', apiRateLimit);
  app.use('/api/auth/', authRateLimit);
  app.use('/api/admin/', strictRateLimit);
}

// API key authentication
class ApiKeyService {
  private apiKeys: Map<string, ApiKeyData> = new Map();
  
  async validateApiKey(key: string): Promise<ApiKeyData | null> {
    const hashedKey = crypto.createHash('sha256').update(key).digest('hex');
    const apiKeyData = await this.apiKeyRepository.findByHash(hashedKey);
    
    if (!apiKeyData || !apiKeyData.isActive) {
      return null;
    }
    
    // Check expiration
    if (apiKeyData.expiresAt && apiKeyData.expiresAt < new Date()) {
      return null;
    }
    
    // Update last used
    await this.apiKeyRepository.updateLastUsed(apiKeyData.id);
    
    return apiKeyData;
  }
  
  async createApiKey(userId: string, permissions: string[]): Promise<string> {
    const apiKey = crypto.randomBytes(32).toString('hex');
    const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');
    
    await this.apiKeyRepository.create({
      userId,
      keyHash: hashedKey,
      permissions,
      isActive: true,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
    });
    
    return apiKey;
  }
}

// API key middleware
function requireApiKey(permissions: string[] = []) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const apiKey = req.headers['x-api-key'] as string;
    
    if (!apiKey) {
      return res.status(401).json({ error: 'API key required' });
    }
    
    const apiKeyService = new ApiKeyService();
    const apiKeyData = await apiKeyService.validateApiKey(apiKey);
    
    if (!apiKeyData) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    // Check permissions
    if (permissions.length > 0) {
      const hasPermission = permissions.every(permission => 
        apiKeyData.permissions.includes(permission)
      );
      
      if (!hasPermission) {
        return res.status(403).json({ error: 'Insufficient API key permissions' });
      }
    }
    
    req.apiKey = apiKeyData;
    next();
  };
}

interface ApiKeyData {
  id: string;
  userId: string;
  keyHash: string;
  permissions: string[];
  isActive: boolean;
  createdAt: Date;
  expiresAt?: Date;
  lastUsedAt?: Date;
}
```

## 🔍 Security Monitoring & Logging

### Security Logging Standards
```typescript
// ✅ GOOD: Comprehensive security logging
import winston from 'winston';

// Security event types
enum SecurityEventType {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
  ACCOUNT_LOCKED = 'account_locked',
  PASSWORD_CHANGED = 'password_changed',
  PERMISSION_DENIED = 'permission_denied',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  DATA_ACCESS = 'data_access',
  DATA_MODIFICATION = 'data_modification',
  API_KEY_USED = 'api_key_used',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
}

interface SecurityEvent {
  type: SecurityEventType;
  userId?: string;
  sessionId?: string;
  ipAddress: string;
  userAgent: string;
  resource?: string;
  action?: string;
  success: boolean;
  details?: Record<string, any>;
  timestamp: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

class SecurityLogger {
  private logger: winston.Logger;
  
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({ 
          filename: 'logs/security.log',
          maxsize: 10485760, // 10MB
          maxFiles: 10,
        }),
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ],
    });
  }
  
  logSecurityEvent(event: SecurityEvent): void {
    const logEntry = {
      ...event,
      timestamp: event.timestamp.toISOString(),
      // Remove sensitive data
      details: this.sanitizeDetails(event.details),
    };
    
    switch (event.severity) {
      case 'critical':
        this.logger.error('SECURITY_CRITICAL', logEntry);
        this.alertSecurityTeam(event);
        break;
      case 'high':
        this.logger.warn('SECURITY_HIGH', logEntry);
        break;
      case 'medium':
        this.logger.info('SECURITY_MEDIUM', logEntry);
        break;
      case 'low':
        this.logger.info('SECURITY_LOW', logEntry);
        break;
    }
  }
  
  private sanitizeDetails(details?: Record<string, any>): Record<string, any> {
    if (!details) return {};
    
    const sanitized = { ...details };
    
    // Remove sensitive fields
    const sensitiveFields = ['password', 'token', 'apiKey', 'ssn', 'creditCard'];
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }
  
  private async alertSecurityTeam(event: SecurityEvent): Promise<void> {
    // Implementation depends on alerting system
    // Could be email, Slack, PagerDuty, etc.
    console.log(`SECURITY ALERT: ${event.type}`, event);
  }
}

// Security monitoring middleware
function securityMonitoring() {
  const securityLogger = new SecurityLogger();
  
  return (req: Request, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    
    // Log request details
    const requestEvent: Partial<SecurityEvent> = {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent') || 'unknown',
      resource: req.path,
      action: req.method,
      timestamp: new Date(),
    };
    
    // Override res.json to log responses
    const originalJson = res.json;
    res.json = function(body: any) {
      const responseTime = Date.now() - startTime;
      
      // Log security-relevant responses
      if (res.statusCode >= 400) {
        securityLogger.logSecurityEvent({
          ...requestEvent,
          type: SecurityEventType.PERMISSION_DENIED,
          success: false,
          severity: res.statusCode >= 500 ? 'high' : 'medium',
          details: {
            statusCode: res.statusCode,
            responseTime,
            error: body.error,
          },
        } as SecurityEvent);
      }
      
      return originalJson.call(this, body);
    };
    
    next();
  };
}

// Anomaly detection
class AnomalyDetector {
  private userBehavior: Map<string, UserBehaviorProfile> = new Map();
  
  async analyzeRequest(req: Request): Promise<void> {
    const userId = req.user?.id;
    if (!userId) return;
    
    const profile = this.getUserProfile(userId);
    const currentBehavior = this.extractBehaviorMetrics(req);
    
    // Check for anomalies
    const anomalies = this.detectAnomalies(profile, currentBehavior);
    
    if (anomalies.length > 0) {
      const securityLogger = new SecurityLogger();
      securityLogger.logSecurityEvent({
        type: SecurityEventType.SUSPICIOUS_ACTIVITY,
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent') || 'unknown',
        success: false,
        severity: 'high',
        details: { anomalies },
        timestamp: new Date(),
      });
    }
    
    // Update profile
    this.updateProfile(userId, currentBehavior);
  }
  
  private getUserProfile(userId: string): UserBehaviorProfile {
    if (!this.userBehavior.has(userId)) {
      this.userBehavior.set(userId, {
        userId,
        typicalIpAddresses: new Set(),
        typicalUserAgents: new Set(),
        averageRequestsPerHour: 0,
        typicalRequestTimes: [],
        lastUpdated: new Date(),
      });
    }
    
    return this.userBehavior.get(userId)!;
  }
  
  private detectAnomalies(profile: UserBehaviorProfile, current: BehaviorMetrics): string[] {
    const anomalies: string[] = [];
    
    // Check for new IP address
    if (!profile.typicalIpAddresses.has(current.ipAddress)) {
      anomalies.push('new_ip_address');
    }
    
    // Check for unusual request frequency
    if (current.requestsInLastHour > profile.averageRequestsPerHour * 3) {
      anomalies.push('high_request_frequency');
    }
    
    // Check for unusual time of access
    const currentHour = new Date().getHours();
    const typicalHours = profile.typicalRequestTimes;
    if (typicalHours.length > 0 && !typicalHours.includes(currentHour)) {
      anomalies.push('unusual_access_time');
    }
    
    return anomalies;
  }
}

interface UserBehaviorProfile {
  userId: string;
  typicalIpAddresses: Set<string>;
  typicalUserAgents: Set<string>;
  averageRequestsPerHour: number;
  typicalRequestTimes: number[];
  lastUpdated: Date;
}

interface BehaviorMetrics {
  ipAddress: string;
  userAgent: string;
  requestsInLastHour: number;
  requestTime: Date;
}
```

## 🔧 Security Configuration

### Environment Security
```bash
# ✅ GOOD: Secure environment configuration

# Database
DATABASE_URL="postgresql://user:password@localhost:5432/dbname?sslmode=require"
DATABASE_SSL_CERT="/path/to/cert.pem"
DATABASE_SSL_KEY="/path/to/key.pem"
DATABASE_SSL_CA="/path/to/ca.pem"

# Encryption
ENCRYPTION_KEY="64-character-hex-string-for-aes-256-encryption"
JWT_SECRET="secure-random-string-for-jwt-signing"
JWT_REFRESH_SECRET="different-secure-random-string-for-refresh-tokens"

# API Keys
API_RATE_LIMIT_REDIS_URL="redis://localhost:6379"
EXTERNAL_API_KEY="your-external-service-api-key"

# Security Headers
CSP_REPORT_URI="https://your-domain.com/api/csp-report"
HSTS_MAX_AGE="31536000"

# Monitoring
SENTRY_DSN="https://your-sentry-dsn"
LOG_LEVEL="info"
SECURITY_LOG_WEBHOOK="https://your-security-monitoring-webhook"

# Feature Flags
ENABLE_2FA="true"
ENABLE_RATE_LIMITING="true"
ENABLE_SECURITY_HEADERS="true"
```

### Security Headers Configuration
```typescript
// ✅ GOOD: Comprehensive security headers
const securityHeaders = {
  // Content Security Policy
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://api.yourdomain.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "upgrade-insecure-requests",
  ].join('; '),
  
  // HTTP Strict Transport Security
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  
  // X-Frame-Options
  'X-Frame-Options': 'DENY',
  
  // X-Content-Type-Options
  'X-Content-Type-Options': 'nosniff',
  
  // Referrer Policy
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  
  // Permissions Policy
  'Permissions-Policy': [
    'camera=()',
    'microphone=()',
    'geolocation=()',
    'payment=()',
    'usb=()',
  ].join(', '),
  
  // X-XSS-Protection (legacy browsers)
  'X-XSS-Protection': '1; mode=block',
};

// Apply security headers middleware
function applySecurityHeaders(req: Request, res: Response, next: NextFunction) {
  Object.entries(securityHeaders).forEach(([header, value]) => {
    res.setHeader(header, value);
  });
  next();
}
```

## ✅ Security Checklist

### Pre-Deployment Security Checklist
- [ ] All dependencies updated to latest secure versions
- [ ] Security headers properly configured
- [ ] Input validation implemented for all endpoints
- [ ] Authentication and authorization working correctly
- [ ] Rate limiting configured for all public endpoints
- [ ] Sensitive data encrypted at rest and in transit
- [ ] Error messages don't expose sensitive information
- [ ] Logging configured for security events
- [ ] HTTPS enforced in production
- [ ] Environment variables secured
- [ ] Database connections use SSL/TLS
- [ ] File upload restrictions implemented
- [ ] CORS configured properly
- [ ] Security testing completed
- [ ] Vulnerability scanning performed

### Ongoing Security Maintenance
- [ ] Regular security audits scheduled
- [ ] Dependency vulnerability scanning automated
- [ ] Security logs monitored and analyzed
- [ ] Incident response plan tested
- [ ] Security training completed by team
- [ ] Backup and recovery procedures tested
- [ ] Access reviews conducted quarterly
- [ ] Security policies updated annually

---

*These security standards should be adapted based on specific application requirements, compliance needs, and threat model.*