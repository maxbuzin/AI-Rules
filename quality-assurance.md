# Quality Assurance Standards

## 🎯 Overview

This document establishes comprehensive quality assurance standards for Next.js 15 applications with shadcn/ui, Tailwind CSS v4.1, and Supabase backend. These standards cover testing Server Components, Server Actions, RLS policies, and mobile-first responsive design validation.

## 🧪 Testing Standards

### Testing Pyramid
```yaml
Testing Strategy:
  Unit Tests (70%):
    - Fast execution (< 100ms per test)
    - Isolated components
    - Mock external dependencies
    - Coverage target: 80%+
  
  Integration Tests (20%):
    - Component interactions
    - API endpoint testing
    - Database operations
    - External service integration
  
  End-to-End Tests (10%):
    - Critical user journeys
    - Cross-browser compatibility
    - Performance validation
    - Accessibility compliance
```

### Unit Testing Standards
```typescript
// ✅ GOOD: Comprehensive unit test structure
describe('UserService', () => {
  let userService: UserService;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockEmailService: jest.Mocked<EmailService>;

  beforeEach(() => {
    mockUserRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    };

    mockEmailService = {
      sendWelcomeEmail: jest.fn(),
      sendPasswordReset: jest.fn(),
    };

    userService = new UserService(mockUserRepository, mockEmailService);
  });

  describe('createUser', () => {
    const validUserData = {
      email: 'test@example.com',
      name: 'Test User',
      password: 'SecurePass123!',
    };

    it('should create user with valid data', async () => {
      // Arrange
      const expectedUser = { id: '1', ...validUserData };
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.create.mockResolvedValue(expectedUser);
      mockEmailService.sendWelcomeEmail.mockResolvedValue(undefined);

      // Act
      const result = await userService.createUser(validUserData);

      // Assert
      expect(result).toEqual(expectedUser);
      expect(mockUserRepository.findByEmail).toHaveBeenCalledWith(validUserData.email);
      expect(mockUserRepository.create).toHaveBeenCalledWith(validUserData);
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(validUserData.email);
    });

### Next.js 15 & Supabase Testing

```typescript
// ✅ GOOD: Testing Server Components
import { render, screen } from '@testing-library/react'
import { createServerComponentClient } from '@supabase/auth-helpers-nextjs'
import UserProfile from '@/app/profile/[id]/page'

// Mock Supabase client
jest.mock('@supabase/auth-helpers-nextjs', () => ({
  createServerComponentClient: jest.fn(),
}))

const mockSupabase = {
  from: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  eq: jest.fn().mockReturnThis(),
  single: jest.fn(),
}

describe('UserProfile Server Component', () => {
  beforeEach(() => {
    (createServerComponentClient as jest.Mock).mockReturnValue(mockSupabase)
  })

  it('should render user profile data', async () => {
    // Arrange
    const mockUser = {
      id: '1',
      name: 'John Doe',
      email: 'john@example.com',
      avatar: '/avatar.jpg'
    }
    mockSupabase.single.mockResolvedValue({ data: mockUser, error: null })

    // Act
    const ProfileComponent = await UserProfile({ params: { id: '1' } })
    render(ProfileComponent)

    // Assert
    expect(screen.getByText('John Doe')).toBeInTheDocument()
    expect(screen.getByText('john@example.com')).toBeInTheDocument()
    expect(mockSupabase.from).toHaveBeenCalledWith('users')
    expect(mockSupabase.eq).toHaveBeenCalledWith('id', '1')
  })

  it('should handle database errors gracefully', async () => {
    // Arrange
    mockSupabase.single.mockResolvedValue({ 
      data: null, 
      error: { message: 'User not found' } 
    })

    // Act
    const ProfileComponent = await UserProfile({ params: { id: '999' } })
    render(ProfileComponent)

    // Assert
    expect(screen.getByText('Error loading user')).toBeInTheDocument()
  })
})

// ✅ GOOD: Testing Server Actions
import { updateUserProfile } from '@/app/actions/user-actions'

describe('updateUserProfile Server Action', () => {
  it('should update user profile successfully', async () => {
    // Arrange
    const formData = new FormData()
    formData.append('name', 'Updated Name')
    formData.append('userId', '1')
    
    mockSupabase.update.mockReturnThis()
    mockSupabase.eq.mockReturnThis()
    mockSupabase.eq.mockResolvedValue({ error: null })

    // Act & Assert
    await expect(updateUserProfile(formData)).resolves.not.toThrow()
    expect(mockSupabase.update).toHaveBeenCalledWith({ name: 'Updated Name' })
    expect(mockSupabase.eq).toHaveBeenCalledWith('id', '1')
  })
})

// ✅ GOOD: Testing RLS Policies
describe('Row Level Security Policies', () => {
  it('should allow users to read their own data', async () => {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', currentUser.id)
    
    expect(error).toBeNull()
    expect(data).toHaveLength(1)
    expect(data[0].id).toBe(currentUser.id)
  })

  it('should prevent users from reading other users data', async () => {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', 'other-user-id')
    
    expect(data).toHaveLength(0) // RLS blocks access
  })
})
```

### Mobile-First Responsive Testing

```typescript
// ✅ GOOD: Testing responsive design from 320px up
import { render, screen } from '@testing-library/react'
import { act } from 'react-dom/test-utils'

describe('Responsive Component Tests', () => {
  const viewports = [
    { width: 320, height: 568, name: 'iPhone SE' },
    { width: 375, height: 667, name: 'iPhone 8' },
    { width: 768, height: 1024, name: 'iPad' },
    { width: 1024, height: 768, name: 'Desktop' },
  ]

  viewports.forEach(({ width, height, name }) => {
    it(`should render correctly on ${name} (${width}x${height})`, () => {
      // Arrange
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: width,
      })
      Object.defineProperty(window, 'innerHeight', {
        writable: true,
        configurable: true,
        value: height,
      })

      // Act
      act(() => {
        window.dispatchEvent(new Event('resize'))
      })
      render(<ResponsiveComponent />)

      // Assert
      const component = screen.getByTestId('responsive-component')
      expect(component).toBeVisible()
      
      if (width >= 768) {
        expect(screen.getByTestId('desktop-nav')).toBeVisible()
      } else {
        expect(screen.getByTestId('mobile-nav')).toBeVisible()
      }
    })
  })
})
```

    it('should throw ConflictError when user already exists', async () => {
      // Arrange
      const existingUser = { id: '1', email: validUserData.email };
      mockUserRepository.findByEmail.mockResolvedValue(existingUser);

      // Act & Assert
      await expect(userService.createUser(validUserData))
        .rejects
        .toThrow(ConflictError);
      
      expect(mockUserRepository.create).not.toHaveBeenCalled();
      expect(mockEmailService.sendWelcomeEmail).not.toHaveBeenCalled();
    });

    it('should handle email service failure gracefully', async () => {
      // Arrange
      const expectedUser = { id: '1', ...validUserData };
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.create.mockResolvedValue(expectedUser);
      mockEmailService.sendWelcomeEmail.mockRejectedValue(new Error('Email service down'));

      // Act & Assert
      await expect(userService.createUser(validUserData))
        .rejects
        .toThrow('Email service down');
    });
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      // Arrange
      const userId = '1';
      const expectedUser = { id: userId, email: 'test@example.com' };
      mockUserRepository.findById.mockResolvedValue(expectedUser);

      // Act
      const result = await userService.getUserById(userId);

      // Assert
      expect(result).toEqual(expectedUser);
      expect(mockUserRepository.findById).toHaveBeenCalledWith(userId);
    });

    it('should return null when user not found', async () => {
      // Arrange
      const userId = 'nonexistent';
      mockUserRepository.findById.mockResolvedValue(null);

      // Act
      const result = await userService.getUserById(userId);

      // Assert
      expect(result).toBeNull();
    });
  });
});
```

### Integration Testing
```typescript
// ✅ GOOD: API integration tests
describe('User API Integration', () => {
  let app: Application;
  let database: TestDatabase;

  beforeAll(async () => {
    database = await setupTestDatabase();
    app = createTestApp(database);
  });

  afterAll(async () => {
    await database.cleanup();
  });

  beforeEach(async () => {
    await database.reset();
  });

  describe('POST /api/users', () => {
    it('should create user and return 201', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'SecurePass123!',
      };

      // Act
      const response = await request(app)
        .post('/api/users')
        .send(userData)
        .expect(201);

      // Assert
      expect(response.body).toMatchObject({
        id: expect.any(String),
        email: userData.email,
        name: userData.name,
      });
      expect(response.body.password).toBeUndefined();

      // Verify in database
      const userInDb = await database.users.findUnique({
        where: { email: userData.email },
      });
      expect(userInDb).toBeTruthy();
    });

    it('should return 400 for invalid email', async () => {
      // Arrange
      const invalidUserData = {
        email: 'invalid-email',
        name: 'Test User',
        password: 'SecurePass123!',
      };

      // Act & Assert
      const response = await request(app)
        .post('/api/users')
        .send(invalidUserData)
        .expect(400);

      expect(response.body.error).toContain('Invalid email');
    });

    it('should return 409 for duplicate email', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'SecurePass123!',
      };

      await database.users.create({ data: userData });

      // Act & Assert
      await request(app)
        .post('/api/users')
        .send(userData)
        .expect(409);
    });
  });

  describe('GET /api/users/:id', () => {
    it('should return user when found', async () => {
      // Arrange
      const user = await database.users.create({
        data: {
          email: 'test@example.com',
          name: 'Test User',
          password: 'hashedpassword',
        },
      });

      // Act
      const response = await request(app)
        .get(`/api/users/${user.id}`)
        .expect(200);

      // Assert
      expect(response.body).toMatchObject({
        id: user.id,
        email: user.email,
        name: user.name,
      });
    });

    it('should return 404 when user not found', async () => {
      // Act & Assert
      await request(app)
        .get('/api/users/nonexistent-id')
        .expect(404);
    });
  });
});
```

### End-to-End Testing
```typescript
// ✅ GOOD: E2E test with Playwright
import { test, expect, Page } from '@playwright/test';

test.describe('User Registration Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/register');
  });

  test('should complete user registration successfully', async ({ page }) => {
    // Fill registration form
    await page.fill('[data-testid="email-input"]', 'test@example.com');
    await page.fill('[data-testid="name-input"]', 'Test User');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.fill('[data-testid="confirm-password-input"]', 'SecurePass123!');

    // Submit form
    await page.click('[data-testid="register-button"]');

    // Verify success
    await expect(page).toHaveURL('/dashboard');
    await expect(page.locator('[data-testid="welcome-message"]'))
      .toContainText('Welcome, Test User!');
  });

  test('should show validation errors for invalid input', async ({ page }) => {
    // Submit empty form
    await page.click('[data-testid="register-button"]');

    // Verify validation errors
    await expect(page.locator('[data-testid="email-error"]'))
      .toContainText('Email is required');
    await expect(page.locator('[data-testid="name-error"]'))
      .toContainText('Name is required');
    await expect(page.locator('[data-testid="password-error"]'))
      .toContainText('Password is required');
  });

  test('should be accessible', async ({ page }) => {
    // Check for proper ARIA labels
    await expect(page.locator('input[aria-label="Email address"]')).toBeVisible();
    await expect(page.locator('input[aria-label="Full name"]')).toBeVisible();
    await expect(page.locator('input[aria-label="Password"]')).toBeVisible();

    // Test keyboard navigation
    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="email-input"]')).toBeFocused();
    
    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="name-input"]')).toBeFocused();
  });

  test('should work on mobile devices', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    // Verify mobile layout
    const form = page.locator('[data-testid="registration-form"]');
    await expect(form).toBeVisible();
    
    // Test touch interactions
    await page.tap('[data-testid="email-input"]');
    await expect(page.locator('[data-testid="email-input"]')).toBeFocused();
  });
});
```

## 🚀 Performance Standards

### Performance Targets

> **Note**: For detailed performance standards and optimization techniques, refer to [performance-optimization.md](./performance-optimization.md)

```yaml
Core Web Vitals (Must Meet):
  Largest Contentful Paint (LCP): ≤ 2.5 seconds
  First Input Delay (FID): ≤ 100 milliseconds
  Cumulative Layout Shift (CLS): ≤ 0.1
  First Contentful Paint (FCP): ≤ 1.8 seconds
  Time to Interactive (TTI): ≤ 3.8 seconds

Lighthouse Scores (Minimum):
  Performance: ≥ 90
  Accessibility: ≥ 95
  Best Practices: ≥ 95
  SEO: ≥ 95

Bundle Size Limits:
  Initial JavaScript: ≤ 200KB (gzipped)
  Initial CSS: ≤ 50KB (gzipped)
  Total Page Weight: ≤ 1MB

Network Performance:
  Time to First Byte (TTFB): ≤ 200ms
  Fast 3G: Page Load ≤ 5 seconds
```

### Performance Testing
```typescript
// ✅ GOOD: Performance monitoring
class PerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();

  startTiming(label: string): () => void {
    const startTime = performance.now();
    
    return () => {
      const endTime = performance.now();
      const duration = endTime - startTime;
      
      if (!this.metrics.has(label)) {
        this.metrics.set(label, []);
      }
      
      this.metrics.get(label)!.push(duration);
      
      // Log slow operations
      if (duration > 1000) {
        console.warn(`Slow operation detected: ${label} took ${duration.toFixed(2)}ms`);
      }
    };
  }

  getMetrics(label: string): { avg: number; min: number; max: number; count: number } {
    const times = this.metrics.get(label) || [];
    if (times.length === 0) {
      return { avg: 0, min: 0, max: 0, count: 0 };
    }

    const sum = times.reduce((a, b) => a + b, 0);
    return {
      avg: sum / times.length,
      min: Math.min(...times),
      max: Math.max(...times),
      count: times.length,
    };
  }

  reset(): void {
    this.metrics.clear();
  }
}

// Usage in tests
test('API response time should be under 500ms', async () => {
  const monitor = new PerformanceMonitor();
  const endTiming = monitor.startTiming('api-call');
  
  await fetch('/api/users');
  endTiming();
  
  const metrics = monitor.getMetrics('api-call');
  expect(metrics.avg).toBeLessThan(500);
});

// ✅ GOOD: Load testing
import { check } from 'k6';
import http from 'k6/http';

export let options = {
  stages: [
    { duration: '2m', target: 100 }, // Ramp up
    { duration: '5m', target: 100 }, // Stay at 100 users
    { duration: '2m', target: 200 }, // Ramp up to 200 users
    { duration: '5m', target: 200 }, // Stay at 200 users
    { duration: '2m', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests under 500ms
    http_req_failed: ['rate<0.1'],    // Error rate under 10%
  },
};

export default function () {
  const response = http.get('https://api.example.com/users');
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
}
```

## 🔒 Security Standards

### Security Requirements
```yaml
Authentication:
  - Multi-factor authentication support
  - Secure password requirements
  - Session management
  - JWT token security

Authorization:
  - Role-based access control
  - Resource-level permissions
  - API endpoint protection
  - Data access restrictions

Data Protection:
  - Input validation and sanitization
  - SQL injection prevention
  - XSS protection
  - CSRF protection
  - Data encryption at rest and in transit

Infrastructure:
  - HTTPS enforcement
  - Security headers
  - Rate limiting
  - Monitoring and logging
```

### Security Testing
```typescript
// ✅ GOOD: Security test examples
describe('Security Tests', () => {
  describe('Input Validation', () => {
    it('should prevent SQL injection', async () => {
      const maliciousInput = "'; DROP TABLE users; --";
      
      const response = await request(app)
        .post('/api/users/search')
        .send({ query: maliciousInput })
        .expect(400);
      
      expect(response.body.error).toContain('Invalid input');
    });

    it('should sanitize HTML input', async () => {
      const xssPayload = '<script>alert("XSS")</script>';
      
      const response = await request(app)
        .post('/api/users')
        .send({
          name: xssPayload,
          email: 'test@example.com',
          password: 'SecurePass123!',
        })
        .expect(201);
      
      expect(response.body.name).not.toContain('<script>');
      expect(response.body.name).toBe('alert("XSS")');
    });
  });

  describe('Authentication', () => {
    it('should require authentication for protected routes', async () => {
      await request(app)
        .get('/api/users/profile')
        .expect(401);
    });

    it('should validate JWT tokens', async () => {
      const invalidToken = 'invalid.jwt.token';
      
      await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(401);
    });
  });

  describe('Rate Limiting', () => {
    it('should limit login attempts', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      // Make multiple failed attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/auth/login')
          .send(loginData)
          .expect(401);
      }

      // 6th attempt should be rate limited
      await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(429);
    });
  });

  describe('CORS', () => {
    it('should have proper CORS headers', async () => {
      const response = await request(app)
        .options('/api/users')
        .expect(200);
      
      expect(response.headers['access-control-allow-origin']).toBeDefined();
      expect(response.headers['access-control-allow-methods']).toBeDefined();
    });
  });
});
```

## 📊 Code Quality Standards

### Static Analysis
```yaml
Linting Rules:
  - ESLint with strict configuration
  - TypeScript strict mode
  - Prettier for code formatting
  - Import/export organization
  - Unused code detection

Code Metrics:
  - Cyclomatic complexity < 10
  - Function length < 50 lines
  - File length < 500 lines
  - Nesting depth < 4 levels
  - Parameter count < 5

Type Coverage:
  - TypeScript strict mode enabled
  - No 'any' types allowed
  - All functions have return types
  - All parameters have types
  - Interfaces for all data structures
```

### Quality Gates
```typescript
// ✅ GOOD: Automated quality checks
// .github/workflows/quality.yml
name: Quality Gates

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - run: npm ci
      - run: npm run lint
      - run: npm run type-check
      - run: npm run test:unit
      - run: npm run test:integration
      - run: npm run test:e2e
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage/lcov.info
  
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm audit --audit-level high
      - run: npm run security:scan
  
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm run build
      - run: npm run lighthouse:ci
      - run: npm run bundle:analyze
```

### Coverage Requirements
```javascript
// jest.config.js
module.exports = {
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/__tests__/**',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
    './src/components/': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/utils/': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95,
    },
  },
  coverageReporters: ['text', 'lcov', 'html'],
};
```

## ✅ Quality Assurance Checklist

### Pre-Commit Checklist
- [ ] All tests pass (unit, integration, E2E)
- [ ] Code coverage meets requirements (80%+)
- [ ] Linting rules satisfied
- [ ] TypeScript compilation successful
- [ ] Security scan passes
- [ ] Performance benchmarks met
- [ ] Accessibility standards validated
- [ ] Documentation updated

### Pre-Release Checklist
- [ ] Full test suite passes
- [ ] Performance tests meet targets
- [ ] Security audit completed
- [ ] Load testing successful
- [ ] Browser compatibility verified
- [ ] Mobile responsiveness tested
- [ ] Accessibility compliance confirmed
- [ ] Monitoring and alerting configured

### Code Review Checklist
- [ ] Code follows established patterns
- [ ] Business logic is correct
- [ ] Error handling is comprehensive
- [ ] Security implications considered
- [ ] Performance impact assessed
- [ ] Tests cover new functionality
- [ ] Documentation is accurate
- [ ] Breaking changes are documented

---

*These standards should be customized based on project-specific requirements and risk tolerance.*