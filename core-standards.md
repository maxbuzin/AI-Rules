# Core Development Standards

## 🚀 Overview

This document establishes core coding standards and development practices for Next.js 15 applications with shadcn/ui, Tailwind CSS v4.1, and Supabase backend. These standards follow the **Simplicity First** principle and ensure code quality, maintainability, and team collaboration.

## 🎯 Simplicity First Principle

**Implementation Hierarchy** (use in order of preference):
1. **Vanilla JavaScript** - For simple interactions and basic functionality
2. **shadcn/ui Components** - For prebuilt UI patterns and common components
3. **React.js** - For complex interactivity beyond simple JS
4. **Next.js** - For full-stack routing, server components, and scalability
5. **Custom Components** - Only when simpler options cannot meet requirements

> **Rule**: Always start with the simplest solution and only add complexity when absolutely necessary.

## 📝 Code Quality Principles

### Universal Standards
```yaml
Code Quality:
  - Readability: Code should be self-documenting
  - Consistency: Follow established patterns throughout
  - Simplicity: Prefer simple solutions over complex ones
  - Maintainability: Write code that's easy to modify
  - Performance: Consider efficiency in all implementations
  - Security: Follow secure coding practices by default
```

### Naming Conventions
```typescript
// ✅ GOOD: Descriptive and consistent naming

// Variables and functions: camelCase
const userAccountBalance = 1000;
const calculateTotalExpenses = () => {};

// Constants: SCREAMING_SNAKE_CASE
const MAX_RETRY_ATTEMPTS = 3;
const API_BASE_URL = 'https://api.example.com';

// Classes and Types: PascalCase
class UserAccount {}
interface PaymentMethod {}
type DatabaseConnection = {};

// Files and directories: kebab-case
// user-profile.component.ts
// payment-methods/

// Boolean variables: is/has/can/should prefix
const isAuthenticated = true;
const hasPermission = false;
const canEdit = true;
const shouldValidate = true;
```

### File Organization
```
project-root/
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── ui/             # Base UI components
│   │   └── feature/        # Feature-specific components
│   ├── pages/              # Page components/routes
│   ├── hooks/              # Custom hooks
│   ├── utils/              # Utility functions
│   ├── types/              # Type definitions
│   ├── constants/          # Application constants
│   ├── services/           # API and external services
│   └── styles/             # Global styles
├── tests/                  # Test files
├── docs/                   # Documentation
└── config/                 # Configuration files
```

## 🔧 Development Practices

### Error Handling
```typescript
// ✅ GOOD: Comprehensive error handling
class ApiError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code?: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// Async function error handling
async function fetchUserData(userId: string): Promise<User | null> {
  try {
    const response = await api.get(`/users/${userId}`);
    return response.data;
  } catch (error) {
    if (error instanceof ApiError && error.statusCode === 404) {
      return null; // User not found is acceptable
    }
    
    // Log unexpected errors
    console.error('Failed to fetch user data:', {
      userId,
      error: error.message,
      stack: error.stack,
    });
    
    throw new ApiError(
      'Unable to fetch user data',
      500,
      'USER_FETCH_ERROR'
    );
  }
}

// Result pattern for better error handling
type Result<T, E = Error> = 
  | { success: true; data: T }
  | { success: false; error: E };

async function safeApiCall<T>(apiCall: () => Promise<T>): Promise<Result<T>> {
  try {
    const data = await apiCall();
    return { success: true, data };
  } catch (error) {
    return { success: false, error: error as Error };
  }
}
```

### Input Validation
```typescript
// ✅ GOOD: Comprehensive input validation
import { z } from 'zod';

// Define validation schemas
const userSchema = z.object({
  email: z.string().email('Invalid email format'),
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  age: z.number().int().min(0).max(150),
  role: z.enum(['user', 'admin', 'moderator']),
});

// Validation function
function validateInput<T>(schema: z.ZodSchema<T>, data: unknown): T {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new ValidationError('Invalid input', error.errors);
    }
    throw error;
  }
}

// Usage
function createUser(userData: unknown) {
  const validatedData = validateInput(userSchema, userData);
  // Proceed with validated data
}
```

### Performance Optimization
```typescript
// ✅ GOOD: Performance best practices

// Memoization for expensive calculations
const memoize = <T extends (...args: any[]) => any>(fn: T): T => {
  const cache = new Map();
  return ((...args: any[]) => {
    const key = JSON.stringify(args);
    if (cache.has(key)) {
      return cache.get(key);
    }
    const result = fn(...args);
    cache.set(key, result);
    return result;
  }) as T;
};

// Debouncing for user input
function debounce<T extends (...args: any[]) => any>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout;
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
}

// Lazy loading pattern
class LazyLoader<T> {
  private _value: T | undefined;
  private _loaded = false;

  constructor(private loader: () => T | Promise<T>) {}

  async get(): Promise<T> {
    if (!this._loaded) {
      this._value = await this.loader();
      this._loaded = true;
    }
    return this._value!;
  }
}
```

## 🧪 Testing Standards

### Test Structure
```typescript
// ✅ GOOD: Well-structured tests
describe('UserService', () => {
  describe('createUser', () => {
    it('should create a user with valid data', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        age: 25,
      };
      const mockRepository = {
        save: jest.fn().mockResolvedValue({ id: '1', ...userData }),
      };
      const userService = new UserService(mockRepository);

      // Act
      const result = await userService.createUser(userData);

      // Assert
      expect(result).toEqual({
        id: '1',
        email: 'test@example.com',
        name: 'Test User',
        age: 25,
      });
      expect(mockRepository.save).toHaveBeenCalledWith(userData);
    });

    it('should throw error for invalid email', async () => {
      // Arrange
      const invalidUserData = {
        email: 'invalid-email',
        name: 'Test User',
        age: 25,
      };
      const userService = new UserService({} as any);

      // Act & Assert
      await expect(userService.createUser(invalidUserData))
        .rejects
        .toThrow('Invalid email format');
    });
  });
});
```

### Test Categories
```yaml
Test Types:
  Unit Tests:
    - Test individual functions/methods
    - Mock external dependencies
    - Fast execution (< 100ms per test)
    - Coverage requirements: See [quality-assurance.md](./quality-assurance.md)
  
  Integration Tests:
    - Test component interactions
    - Use real dependencies where possible
    - Test API endpoints
    - Database operations
  
  End-to-End Tests:
    - Test complete user workflows
    - Use real browser environment
    - Critical path coverage
    - Performance validation
```

## 🔒 Security Practices

### Input Sanitization
```typescript
// ✅ GOOD: Secure input handling
import DOMPurify from 'isomorphic-dompurify';

// Sanitize HTML content
function sanitizeHtml(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li'],
    ALLOWED_ATTR: ['class'],
  });
}

// Escape SQL-like strings (when not using ORM)
function escapeString(str: string): string {
  return str.replace(/[\0\x08\x09\x1a\n\r"'\\%]/g, (char) => {
    switch (char) {
      case '\0': return '\\0';
      case '\x08': return '\\b';
      case '\x09': return '\\t';
      case '\x1a': return '\\z';
      case '\n': return '\\n';
      case '\r': return '\\r';
      case '"':
      case "'":
      case '\\':
      case '%': return '\\' + char;
      default: return char;
    }
  });
}

// Rate limiting
class RateLimiter {
  private requests = new Map<string, number[]>();

  isAllowed(identifier: string, maxRequests: number, windowMs: number): boolean {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    const userRequests = this.requests.get(identifier) || [];
    const validRequests = userRequests.filter(time => time > windowStart);
    
    if (validRequests.length >= maxRequests) {
      return false;
    }
    
    validRequests.push(now);
    this.requests.set(identifier, validRequests);
    return true;
  }
}
```

## 📚 Documentation Standards

### Code Documentation
```typescript
// ✅ GOOD: Comprehensive JSDoc comments

/**
 * Calculates the total cost of a trip including all expenses
 * @param expenses - Array of expense objects
 * @param taxRate - Tax rate as decimal (e.g., 0.08 for 8%)
 * @param currency - Currency code for formatting
 * @returns Formatted total cost string
 * @throws {ValidationError} When expenses array is empty
 * @example
 * ```typescript
 * const total = calculateTripTotal(
 *   [{ amount: 100 }, { amount: 50 }],
 *   0.08,
 *   'USD'
 * );
 * console.log(total); // "$162.00"
 * ```
 */
function calculateTripTotal(
  expenses: Expense[],
  taxRate: number,
  currency: string
): string {
  if (expenses.length === 0) {
    throw new ValidationError('Expenses array cannot be empty');
  }

  const subtotal = expenses.reduce((sum, expense) => sum + expense.amount, 0);
  const tax = subtotal * taxRate;
  const total = subtotal + tax;

  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
  }).format(total);
}
```

### README Template
```markdown
# Project Name

## 📋 Description
Brief description of what the project does and its main purpose.

## 🚀 Quick Start
1. Clone the repository
2. Install dependencies
3. Set up environment variables
4. Run the development server

## 🛠️ Tech Stack
- Framework/Language
- Database
- Key libraries

## 📁 Project Structure
```
src/
├── components/
├── pages/
└── utils/
```

## 🧪 Testing
- How to run tests
- Coverage requirements
- Testing strategy

## 🚀 Deployment
- Deployment process
- Environment setup
- CI/CD pipeline

## 🤝 Contributing
- Code standards
- Pull request process
- Issue reporting
```

## ✅ Quality Checklist

### Before Committing
- [ ] Code follows naming conventions
- [ ] All functions have proper error handling
- [ ] Input validation implemented
- [ ] Tests written and passing
- [ ] Documentation updated
- [ ] No hardcoded secrets or credentials
- [ ] Performance considerations addressed
- [ ] Security best practices followed

### Code Review Checklist
- [ ] Code is readable and well-structured
- [ ] Business logic is correct
- [ ] Edge cases are handled
- [ ] Tests cover new functionality
- [ ] No code duplication
- [ ] Performance impact assessed
- [ ] Security implications reviewed
- [ ] Documentation is accurate

---

*These standards should be adapted to specific project needs while maintaining core principles.*