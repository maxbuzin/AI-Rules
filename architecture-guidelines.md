# Architecture Guidelines

## 🏗️ Overview

This document outlines architectural patterns and design principles for Next.js 15 applications with shadcn/ui, Tailwind CSS v4.1, Lucide Icons, React Icons, and Supabase backend. These guidelines focus on scalable, maintainable, and future-proof architecture following the Simplicity First principle.

## 🎯 Technology Stack

### Frontend Stack
- **Next.js 15**: App Router, Server Components, Server Actions
- **shadcn/ui**: Prebuilt component library with Radix UI primitives
- **Tailwind CSS v4.1**: Utility-first CSS framework
- **Lucide Icons**: Primary icon library
- **React Icons**: Secondary icon library for additional icons
- **TypeScript**: Strict type safety throughout

### Backend Stack
- **Supabase**: PostgreSQL database with real-time capabilities
- **Supabase Auth**: Authentication and authorization
- **Supabase Edge Functions**: Serverless functions for server-side logic
- **Row Level Security (RLS)**: Database-level security policies

### Mobile-First Design
- **Minimum Width**: 320px (iPhone SE)
- **Responsive Breakpoints**: Tailwind CSS default breakpoints
- **Progressive Enhancement**: Desktop features built on mobile foundation

## 🎯 Architectural Principles

### Core Principles
```yaml
Architecture Principles:
  - Separation of Concerns: Each component has a single responsibility
  - Loose Coupling: Components are independent and interchangeable
  - High Cohesion: Related functionality is grouped together
  - Single Source of Truth: Data has one authoritative source
  - Fail Fast: Errors are detected and handled early
  - Scalability: Architecture supports growth and change
  - Testability: Components can be tested in isolation
  - Maintainability: Code is easy to understand and modify
```

### Next.js 15 Architecture Patterns

```typescript
// ✅ GOOD: Server Component with Supabase
import { createServerComponentClient } from '@supabase/auth-helpers-nextjs'
import { cookies } from 'next/headers'

export default async function UserProfile({ userId }: { userId: string }) {
  const supabase = createServerComponentClient({ cookies })
  
  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single()

  if (error) {
    return <div>Error loading user</div>
  }

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold">{user.name}</h1>
      <p className="text-gray-600">{user.email}</p>
    </div>
  )
}

// ✅ GOOD: Server Action for mutations
import { createServerActionClient } from '@supabase/auth-helpers-nextjs'
import { revalidatePath } from 'next/cache'

export async function updateUserProfile(formData: FormData) {
  'use server'
  
  const supabase = createServerActionClient({ cookies })
  const name = formData.get('name') as string
  const userId = formData.get('userId') as string
  
  const { error } = await supabase
    .from('users')
    .update({ name })
    .eq('id', userId)
  
  if (error) {
    throw new Error('Failed to update profile')
  }
  
  revalidatePath('/profile')
}
```

### Supabase Integration Patterns

```typescript
// ✅ GOOD: Supabase Repository Pattern
interface UserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(userData: CreateUserData): Promise<User>;
  update(id: string, updates: Partial<User>): Promise<User>;
  delete(id: string): Promise<void>;
}

class SupabaseUserRepository implements UserRepository {
  constructor(private supabase: SupabaseClient) {}

  async findById(id: string): Promise<User | null> {
    const { data, error } = await this.supabase
      .from('users')
      .select('*')
      .eq('id', id)
      .single()
    
    if (error) throw new Error(error.message)
    return data
  }

  async create(userData: CreateUserData): Promise<User> {
    const { data, error } = await this.supabase
      .from('users')
      .insert(userData)
      .select()
      .single()
    
    if (error) throw new Error(error.message)
    return data
  }

  // ... other methods
}

// ✅ GOOD: Service Layer Pattern
class UserService {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService,
    private logger: Logger
  ) {}

  async createUser(userData: CreateUserData): Promise<User> {
    // Validation
    this.validateUserData(userData);

    // Business logic
    const existingUser = await this.userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new ConflictError('User already exists');
    }

    // Create user
    const user = await this.userRepository.create(userData);

    // Side effects
    await this.emailService.sendWelcomeEmail(user.email);
    this.logger.info('User created', { userId: user.id });

    return user;
  }

  private validateUserData(userData: CreateUserData): void {
    // Validation logic
  }
}
```

## 🏛️ Layered Architecture

### Layer Structure
```
Presentation Layer (UI)
├── Components
├── Pages/Views
├── State Management
└── User Interactions

Application Layer (Business Logic)
├── Services
├── Use Cases
├── Command Handlers
└── Query Handlers

Domain Layer (Core Business)
├── Entities
├── Value Objects
├── Domain Services
└── Business Rules

Infrastructure Layer (External)
├── Database Access
├── External APIs
├── File System
└── Third-party Services
```

### Implementation Example
```typescript
// Domain Layer
class User {
  constructor(
    public readonly id: string,
    public readonly email: string,
    public readonly name: string,
    private _isActive: boolean = true
  ) {
    this.validateEmail(email);
  }

  get isActive(): boolean {
    return this._isActive;
  }

  deactivate(): void {
    if (!this._isActive) {
      throw new DomainError('User is already inactive');
    }
    this._isActive = false;
  }

  private validateEmail(email: string): void {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new DomainError('Invalid email format');
    }
  }
}

// Application Layer
class CreateUserUseCase {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService
  ) {}

  async execute(command: CreateUserCommand): Promise<UserDto> {
    // Create domain entity
    const user = new User(
      generateId(),
      command.email,
      command.name
    );

    // Persist
    await this.userRepository.save(user);

    // Side effects
    await this.emailService.sendWelcomeEmail(user.email);

    // Return DTO
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      isActive: user.isActive,
    };
  }
}

// Infrastructure Layer
class PostgresUserRepository implements UserRepository {
  constructor(private db: Database) {}

  async save(user: User): Promise<void> {
    await this.db.users.upsert({
      where: { id: user.id },
      create: {
        id: user.id,
        email: user.email,
        name: user.name,
        isActive: user.isActive,
      },
      update: {
        name: user.name,
        isActive: user.isActive,
      },
    });
  }
}

// Presentation Layer
class UserController {
  constructor(private createUserUseCase: CreateUserUseCase) {}

  async createUser(request: Request): Promise<Response> {
    try {
      const command = new CreateUserCommand(
        request.body.email,
        request.body.name
      );

      const user = await this.createUserUseCase.execute(command);

      return {
        status: 201,
        data: user,
      };
    } catch (error) {
      return this.handleError(error);
    }
  }
}
```

## 🔄 Event-Driven Architecture

### Event System
```typescript
// ✅ GOOD: Event-driven pattern
interface DomainEvent {
  eventId: string;
  eventType: string;
  aggregateId: string;
  occurredAt: Date;
  version: number;
}

class UserCreatedEvent implements DomainEvent {
  constructor(
    public readonly eventId: string,
    public readonly aggregateId: string,
    public readonly email: string,
    public readonly name: string,
    public readonly occurredAt: Date = new Date(),
    public readonly version: number = 1
  ) {}

  get eventType(): string {
    return 'UserCreated';
  }
}

// Event Bus
interface EventBus {
  publish(event: DomainEvent): Promise<void>;
  subscribe<T extends DomainEvent>(
    eventType: string,
    handler: EventHandler<T>
  ): void;
}

interface EventHandler<T extends DomainEvent> {
  handle(event: T): Promise<void>;
}

// Event Handlers
class SendWelcomeEmailHandler implements EventHandler<UserCreatedEvent> {
  constructor(private emailService: EmailService) {}

  async handle(event: UserCreatedEvent): Promise<void> {
    await this.emailService.sendWelcomeEmail(event.email);
  }
}

class UpdateAnalyticsHandler implements EventHandler<UserCreatedEvent> {
  constructor(private analyticsService: AnalyticsService) {}

  async handle(event: UserCreatedEvent): Promise<void> {
    await this.analyticsService.trackUserRegistration({
      userId: event.aggregateId,
      email: event.email,
      timestamp: event.occurredAt,
    });
  }
}

// Usage in Service
class UserService {
  constructor(
    private userRepository: UserRepository,
    private eventBus: EventBus
  ) {}

  async createUser(userData: CreateUserData): Promise<User> {
    const user = await this.userRepository.create(userData);

    // Publish event
    const event = new UserCreatedEvent(
      generateId(),
      user.id,
      user.email,
      user.name
    );

    await this.eventBus.publish(event);

    return user;
  }
}
```

## 🏗️ Microservices Patterns

### Service Communication
```typescript
// ✅ GOOD: API Gateway Pattern
class ApiGateway {
  constructor(
    private userService: UserServiceClient,
    private orderService: OrderServiceClient,
    private paymentService: PaymentServiceClient
  ) {}

  async getUserProfile(userId: string): Promise<UserProfile> {
    const [user, orders, paymentMethods] = await Promise.all([
      this.userService.getUser(userId),
      this.orderService.getUserOrders(userId),
      this.paymentService.getUserPaymentMethods(userId),
    ]);

    return {
      ...user,
      recentOrders: orders.slice(0, 5),
      defaultPaymentMethod: paymentMethods.find(pm => pm.isDefault),
    };
  }
}

// ✅ GOOD: Circuit Breaker Pattern
class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';

  constructor(
    private threshold: number = 5,
    private timeout: number = 60000
  ) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = 'CLOSED';
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();
    if (this.failures >= this.threshold) {
      this.state = 'OPEN';
    }
  }
}
```

## 📊 Data Architecture

### Data Flow Patterns
```typescript
// ✅ GOOD: CQRS Pattern
interface Command {
  commandId: string;
  timestamp: Date;
}

interface Query {
  queryId: string;
  timestamp: Date;
}

// Command Side
class CreateOrderCommand implements Command {
  constructor(
    public readonly commandId: string,
    public readonly userId: string,
    public readonly items: OrderItem[],
    public readonly timestamp: Date = new Date()
  ) {}
}

class CreateOrderHandler {
  constructor(
    private orderRepository: OrderRepository,
    private eventBus: EventBus
  ) {}

  async handle(command: CreateOrderCommand): Promise<void> {
    const order = new Order(
      generateId(),
      command.userId,
      command.items
    );

    await this.orderRepository.save(order);

    await this.eventBus.publish(
      new OrderCreatedEvent(order.id, order.userId, order.total)
    );
  }
}

// Query Side
class GetUserOrdersQuery implements Query {
  constructor(
    public readonly queryId: string,
    public readonly userId: string,
    public readonly limit: number = 10,
    public readonly offset: number = 0,
    public readonly timestamp: Date = new Date()
  ) {}
}

class GetUserOrdersHandler {
  constructor(private orderReadModel: OrderReadModel) {}

  async handle(query: GetUserOrdersQuery): Promise<OrderSummary[]> {
    return this.orderReadModel.getUserOrders(
      query.userId,
      query.limit,
      query.offset
    );
  }
}
```

### Caching Strategy
```typescript
// ✅ GOOD: Multi-level caching
class CacheService {
  constructor(
    private memoryCache: Map<string, any>,
    private redisCache: RedisClient,
    private database: Database
  ) {}

  async get<T>(key: string): Promise<T | null> {
    // L1: Memory cache
    if (this.memoryCache.has(key)) {
      return this.memoryCache.get(key);
    }

    // L2: Redis cache
    const redisValue = await this.redisCache.get(key);
    if (redisValue) {
      const parsed = JSON.parse(redisValue);
      this.memoryCache.set(key, parsed);
      return parsed;
    }

    return null;
  }

  async set<T>(key: string, value: T, ttl: number = 3600): Promise<void> {
    // Set in both caches
    this.memoryCache.set(key, value);
    await this.redisCache.setex(key, ttl, JSON.stringify(value));
  }

  async invalidate(key: string): Promise<void> {
    this.memoryCache.delete(key);
    await this.redisCache.del(key);
  }
}

// Cache-aside pattern
class UserService {
  constructor(
    private userRepository: UserRepository,
    private cacheService: CacheService
  ) {}

  async getUser(id: string): Promise<User | null> {
    const cacheKey = `user:${id}`;
    
    // Try cache first
    let user = await this.cacheService.get<User>(cacheKey);
    if (user) {
      return user;
    }

    // Fallback to database
    user = await this.userRepository.findById(id);
    if (user) {
      await this.cacheService.set(cacheKey, user, 1800); // 30 minutes
    }

    return user;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    const user = await this.userRepository.update(id, updates);
    
    // Invalidate cache
    await this.cacheService.invalidate(`user:${id}`);
    
    return user;
  }
}
```

## 🔧 Dependency Injection

### IoC Container
```typescript
// ✅ GOOD: Dependency injection container
class Container {
  private services = new Map<string, any>();
  private factories = new Map<string, () => any>();

  register<T>(name: string, factory: () => T): void {
    this.factories.set(name, factory);
  }

  registerSingleton<T>(name: string, factory: () => T): void {
    this.register(name, () => {
      if (!this.services.has(name)) {
        this.services.set(name, factory());
      }
      return this.services.get(name);
    });
  }

  resolve<T>(name: string): T {
    const factory = this.factories.get(name);
    if (!factory) {
      throw new Error(`Service ${name} not registered`);
    }
    return factory();
  }
}

// Service registration
const container = new Container();

// Register dependencies
container.registerSingleton('database', () => new Database());
container.registerSingleton('userRepository', () => 
  new PostgresUserRepository(container.resolve('database'))
);
container.registerSingleton('emailService', () => new EmailService());
container.register('userService', () => 
  new UserService(
    container.resolve('userRepository'),
    container.resolve('emailService')
  )
);

// Usage
const userService = container.resolve<UserService>('userService');
```

## 📈 Scalability Patterns

### Horizontal Scaling
```typescript
// ✅ GOOD: Load balancing
class LoadBalancer {
  private currentIndex = 0;

  constructor(private servers: string[]) {}

  // Round-robin algorithm
  getNextServer(): string {
    const server = this.servers[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.servers.length;
    return server;
  }

  // Health check
  async getHealthyServer(): Promise<string> {
    for (const server of this.servers) {
      try {
        await this.healthCheck(server);
        return server;
      } catch {
        continue;
      }
    }
    throw new Error('No healthy servers available');
  }

  private async healthCheck(server: string): Promise<void> {
    const response = await fetch(`${server}/health`);
    if (!response.ok) {
      throw new Error('Server unhealthy');
    }
  }
}

// ✅ GOOD: Database sharding
class ShardedRepository {
  constructor(private shards: Database[]) {}

  private getShardIndex(key: string): number {
    // Simple hash-based sharding
    const hash = this.hash(key);
    return hash % this.shards.length;
  }

  private hash(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  async findById(id: string): Promise<any> {
    const shardIndex = this.getShardIndex(id);
    const shard = this.shards[shardIndex];
    return shard.findById(id);
  }

  async create(data: any): Promise<any> {
    const shardIndex = this.getShardIndex(data.id);
    const shard = this.shards[shardIndex];
    return shard.create(data);
  }
}
```

## ✅ Architecture Checklist

### Design Review
- [ ] Single Responsibility Principle followed
- [ ] Dependencies are injected, not hardcoded
- [ ] Interfaces define contracts between layers
- [ ] Business logic is separated from infrastructure
- [ ] Error handling is consistent across layers
- [ ] Caching strategy is appropriate
- [ ] Database access is optimized
- [ ] Security is built into the architecture

### Scalability Review
- [ ] Architecture supports horizontal scaling
- [ ] Database can handle expected load
- [ ] Caching reduces database pressure
- [ ] Services can be deployed independently
- [ ] Monitoring and observability are built-in
- [ ] Performance bottlenecks are identified
- [ ] Failure modes are considered
- [ ] Recovery strategies are defined

---

*These guidelines should be adapted based on specific project requirements and constraints.*