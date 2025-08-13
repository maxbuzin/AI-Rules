# Performance Optimization Standards

## 🚀 Overview

This document establishes comprehensive performance standards and optimization techniques for Next.js 15 applications with shadcn/ui, Tailwind CSS v4.1, and Supabase backend. These guidelines ensure applications deliver exceptional user experiences with mobile-first design starting at 320px viewport width.

## 📱 Mobile-First Performance Requirements

### Viewport Standards
```yaml
Mobile-First Design:
  Minimum Width: 320px (iPhone SE)
  Primary Target: 375px (iPhone 12/13/14)
  Secondary Target: 390px (iPhone 12 Pro)
  Tablet Breakpoint: 768px
  Desktop Breakpoint: 1024px
  
Responsive Strategy:
  - Design for 320px first
  - Progressive enhancement for larger screens
  - Touch-friendly interactions (44px minimum)
  - Readable text without zoom (16px minimum)
```

## 📊 Performance Targets

### Core Web Vitals
```yaml
Core Web Vitals Targets:
  Largest Contentful Paint (LCP):
    Good: ≤ 2.5 seconds
    Needs Improvement: 2.5 - 4.0 seconds
    Poor: > 4.0 seconds
    
  First Input Delay (FID):
    Good: ≤ 100 milliseconds
    Needs Improvement: 100 - 300 milliseconds
    Poor: > 300 milliseconds
    
  Cumulative Layout Shift (CLS):
    Good: ≤ 0.1
    Needs Improvement: 0.1 - 0.25
    Poor: > 0.25
    
  First Contentful Paint (FCP):
    Good: ≤ 1.8 seconds
    Needs Improvement: 1.8 - 3.0 seconds
    Poor: > 3.0 seconds
    
  Time to Interactive (TTI):
    Good: ≤ 3.8 seconds
    Needs Improvement: 3.8 - 7.3 seconds
    Poor: > 7.3 seconds

Lighthouse Scores:
  Performance: ≥ 90
  Accessibility: ≥ 95
  Best Practices: ≥ 95
  SEO: ≥ 95

Bundle Size Limits:
  Initial JavaScript Bundle: ≤ 200KB (gzipped)
  Initial CSS Bundle: ≤ 50KB (gzipped)
  Total Page Weight: ≤ 1MB
  Images per Page: ≤ 2MB total

Network Performance:
  Time to First Byte (TTFB): ≤ 200ms
  DNS Lookup: ≤ 20ms
  SSL Handshake: ≤ 100ms
  Server Response: ≤ 100ms
```

### Performance Budgets by Connection
```yaml
Connection Speed Targets:
  Fast 3G (1.6 Mbps):
    Page Load: ≤ 5 seconds
    Time to Interactive: ≤ 5 seconds
    
  Slow 3G (400 Kbps):
    Page Load: ≤ 10 seconds
    Time to Interactive: ≤ 10 seconds
    
  2G (250 Kbps):
    Page Load: ≤ 15 seconds
    Basic Functionality: ≤ 8 seconds
```

## ⚡ Frontend Performance Optimization

### Next.js 15 & shadcn/ui Optimization
```typescript
// ✅ GOOD: Next.js 15 Server Components (preferred)
import { Suspense } from 'react'
import { createServerComponentClient } from '@supabase/auth-helpers-nextjs'
import { cookies } from 'next/headers'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'

// Server Component - runs on server, no JavaScript sent to client
export default async function UserProfile({ userId }: { userId: string }) {
  const supabase = createServerComponentClient({ cookies })
  
  // Data fetching happens on server
  const { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single()

  return (
    <Card className="w-full max-w-sm mx-auto">
      <CardHeader>
        <div className="flex items-center space-x-4">
          <Avatar>
            <AvatarImage src={user.avatar} alt={user.name} />
            <AvatarFallback>{user.name.charAt(0)}</AvatarFallback>
          </Avatar>
          <CardTitle>{user.name}</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">{user.email}</p>
      </CardContent>
    </Card>
  )
}

// ✅ GOOD: Client Component optimization (when interactivity needed)
'use client'
import React, { memo, useMemo, useCallback } from 'react'
import dynamic from 'next/dynamic'
import Image from 'next/image'

// Memoized component to prevent unnecessary re-renders
const UserCard = memo(({ user, onEdit }: UserCardProps) => {
  // Memoize expensive calculations
  const userStats = useMemo(() => {
    return calculateUserStats(user.activities);
  }, [user.activities]);
  
  // Memoize event handlers
  const handleEdit = useCallback(() => {
    onEdit(user.id);
  }, [user.id, onEdit]);
  
  return (
    <div className="user-card">
      <Image
        src={user.avatar}
        alt={`${user.name} avatar`}
        width={64}
        height={64}
        priority={false}
        placeholder="blur"
        blurDataURL="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQ..."
      />
      <h3>{user.name}</h3>
      <p>Score: {userStats.score}</p>
      <button onClick={handleEdit}>Edit</button>
    </div>
  );
});

// Lazy loading for non-critical components
const HeavyChart = lazy(() => import('./HeavyChart'));
const AdminPanel = dynamic(() => import('./AdminPanel'), {
  loading: () => <div>Loading admin panel...</div>,
  ssr: false, // Client-side only
});

// Virtualized list for large datasets
import { FixedSizeList as List } from 'react-window';

const VirtualizedUserList = ({ users }: { users: User[] }) => {
  const Row = ({ index, style }: { index: number; style: React.CSSProperties }) => (
    <div style={style}>
      <UserCard user={users[index]} onEdit={handleUserEdit} />
    </div>
  );
  
  return (
    <List
      height={600}
      itemCount={users.length}
      itemSize={100}
      width="100%"
    >
      {Row}
    </List>
  );
};

// Optimized data fetching with React Query
import { useQuery, useInfiniteQuery } from '@tanstack/react-query';

function useOptimizedUserData(userId: string) {
  return useQuery({
    queryKey: ['user', userId],
    queryFn: () => fetchUser(userId),
    staleTime: 5 * 60 * 1000, // 5 minutes
    cacheTime: 10 * 60 * 1000, // 10 minutes
    refetchOnWindowFocus: false,
    retry: 3,
  });
}

// Infinite scrolling for large lists
function useInfiniteUsers() {
  return useInfiniteQuery({
    queryKey: ['users'],
    queryFn: ({ pageParam = 0 }) => fetchUsers({ page: pageParam, limit: 20 }),
    getNextPageParam: (lastPage, pages) => {
      return lastPage.hasMore ? pages.length : undefined;
    },
    staleTime: 2 * 60 * 1000,
  });
}

// Performance monitoring hook
function usePerformanceMonitoring() {
  useEffect(() => {
    // Monitor Core Web Vitals
    import('web-vitals').then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
      getCLS(console.log);
      getFID(console.log);
      getFCP(console.log);
      getLCP(console.log);
      getTTFB(console.log);
    });
    
    // Monitor custom metrics
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.entryType === 'measure') {
          console.log(`${entry.name}: ${entry.duration}ms`);
        }
      }
    });
    
    observer.observe({ entryTypes: ['measure'] });
    
    return () => observer.disconnect();
  }, []);
}
```

### Bundle Optimization
```javascript
// ✅ GOOD: Next.js configuration for optimal bundles
// next.config.js
const nextConfig = {
  // Enable SWC minification
  swcMinify: true,
  
  // Optimize images
  images: {
    domains: ['example.com', 'cdn.example.com'],
    formats: ['image/webp', 'image/avif'],
    minimumCacheTTL: 60 * 60 * 24 * 30, // 30 days
  },
  
  // Bundle analyzer
  webpack: (config, { buildId, dev, isServer, defaultLoaders, webpack }) => {
    // Bundle analyzer in development
    if (!dev && !isServer) {
      const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');
      config.plugins.push(
        new BundleAnalyzerPlugin({
          analyzerMode: 'static',
          openAnalyzer: false,
          reportFilename: 'bundle-analyzer.html',
        })
      );
    }
    
    // Optimize chunks
    config.optimization.splitChunks = {
      chunks: 'all',
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all',
        },
        common: {
          name: 'common',
          minChunks: 2,
          chunks: 'all',
          enforce: true,
        },
      },
    };
    
    return config;
  },
  
  // Experimental features for performance
  experimental: {
    optimizeCss: true,
    scrollRestoration: true,
  },
  
  // Compression
  compress: true,
  
  // Headers for caching
  async headers() {
    return [
      {
        source: '/static/(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
```

### CSS Performance
```scss
// ✅ GOOD: Optimized CSS practices

// Use CSS custom properties for theming
:root {
  --primary-color: #007bff;
  --secondary-color: #6c757d;
  --font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --border-radius: 0.375rem;
  --transition-duration: 0.15s;
}

// Optimize animations with transform and opacity
.fade-in {
  opacity: 0;
  transform: translateY(20px);
  animation: fadeInUp 0.3s ease-out forwards;
}

@keyframes fadeInUp {
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

// Use will-change for performance-critical animations
.smooth-scroll {
  will-change: transform;
  transform: translateZ(0); // Force hardware acceleration
}

// Optimize for mobile with touch-action
.scrollable-area {
  touch-action: pan-y;
  -webkit-overflow-scrolling: touch;
}

// Critical CSS inlining
.above-fold {
  /* Critical styles that should be inlined */
  font-family: var(--font-family);
  line-height: 1.5;
  color: #333;
}

// Use containment for performance
.card {
  contain: layout style paint;
}

// Optimize images with aspect-ratio
.image-container {
  aspect-ratio: 16 / 9;
  overflow: hidden;
  
  img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }
}
```

### Image Optimization
```typescript
// ✅ GOOD: Advanced image optimization
import Image from 'next/image';
import { useState } from 'react';

// Responsive image component with lazy loading
const OptimizedImage = ({ src, alt, priority = false, ...props }) => {
  const [isLoading, setIsLoading] = useState(true);
  
  return (
    <div className="relative overflow-hidden">
      <Image
        src={src}
        alt={alt}
        fill
        priority={priority}
        quality={85}
        placeholder="blur"
        blurDataURL="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQ..."
        sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
        onLoadingComplete={() => setIsLoading(false)}
        className={`
          transition-opacity duration-300
          ${isLoading ? 'opacity-0' : 'opacity-100'}
        `}
        {...props}
      />
      {isLoading && (
        <div className="absolute inset-0 bg-gray-200 animate-pulse" />
      )}
    </div>
  );
};

// Image optimization service
class ImageOptimizationService {
  private readonly CDN_BASE = 'https://cdn.example.com';
  
  generateResponsiveUrl(src: string, width: number, quality = 85): string {
    const params = new URLSearchParams({
      w: width.toString(),
      q: quality.toString(),
      f: 'webp',
    });
    
    return `${this.CDN_BASE}/optimize?url=${encodeURIComponent(src)}&${params}`;
  }
  
  generateSrcSet(src: string, sizes: number[]): string {
    return sizes
      .map(size => `${this.generateResponsiveUrl(src, size)} ${size}w`)
      .join(', ');
  }
  
  // Generate blur placeholder
  async generateBlurDataUrl(src: string): Promise<string> {
    const tinyUrl = this.generateResponsiveUrl(src, 10, 20);
    
    try {
      const response = await fetch(tinyUrl);
      const buffer = await response.arrayBuffer();
      const base64 = Buffer.from(buffer).toString('base64');
      return `data:image/jpeg;base64,${base64}`;
    } catch {
      return 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQ...';
    }
  }
}

// Intersection Observer for lazy loading
const useLazyLoading = (threshold = 0.1) => {
  const [isVisible, setIsVisible] = useState(false);
  const [ref, setRef] = useState<HTMLElement | null>(null);
  
  useEffect(() => {
    if (!ref) return;
    
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
          observer.disconnect();
        }
      },
      { threshold }
    );
    
    observer.observe(ref);
    
    return () => observer.disconnect();
  }, [ref, threshold]);
  
  return [setRef, isVisible] as const;
};
```

## 🔧 Backend Performance Optimization

### Database Optimization
```sql
-- ✅ GOOD: Database optimization techniques

-- Proper indexing strategy
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_users_created_at ON users(created_at DESC);
CREATE INDEX CONCURRENTLY idx_posts_user_id_created_at ON posts(user_id, created_at DESC);

-- Composite index for common queries
CREATE INDEX CONCURRENTLY idx_orders_status_created_at 
ON orders(status, created_at DESC) 
WHERE status IN ('pending', 'processing');

-- Partial index for soft deletes
CREATE INDEX CONCURRENTLY idx_users_active 
ON users(id) 
WHERE deleted_at IS NULL;

-- Query optimization examples
-- ✅ GOOD: Efficient pagination
SELECT id, name, email, created_at
FROM users
WHERE created_at < $1  -- cursor-based pagination
ORDER BY created_at DESC
LIMIT 20;

-- ✅ GOOD: Efficient search with full-text search
SELECT id, name, email, 
       ts_rank(search_vector, plainto_tsquery($1)) as rank
FROM users
WHERE search_vector @@ plainto_tsquery($1)
ORDER BY rank DESC
LIMIT 20;

-- ✅ GOOD: Efficient aggregation
SELECT 
  DATE_TRUNC('day', created_at) as date,
  COUNT(*) as total_orders,
  SUM(total_amount) as total_revenue
FROM orders
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', created_at)
ORDER BY date DESC;

-- Database maintenance
-- Regular VACUUM and ANALYZE
VACUUM ANALYZE users;
VACUUM ANALYZE posts;

-- Update table statistics
ANALYZE;
```

### API Performance
```typescript
// ✅ GOOD: High-performance API implementation
import Redis from 'ioredis';
import { LRUCache } from 'lru-cache';

// Multi-level caching strategy
class CacheService {
  private redis: Redis;
  private memoryCache: LRUCache<string, any>;
  
  constructor() {
    this.redis = new Redis(process.env.REDIS_URL);
    this.memoryCache = new LRUCache({
      max: 1000,
      ttl: 5 * 60 * 1000, // 5 minutes
    });
  }
  
  async get<T>(key: string): Promise<T | null> {
    // L1: Memory cache
    const memoryResult = this.memoryCache.get(key);
    if (memoryResult) {
      return memoryResult as T;
    }
    
    // L2: Redis cache
    const redisResult = await this.redis.get(key);
    if (redisResult) {
      const parsed = JSON.parse(redisResult);
      this.memoryCache.set(key, parsed);
      return parsed as T;
    }
    
    return null;
  }
  
  async set(key: string, value: any, ttl = 3600): Promise<void> {
    const serialized = JSON.stringify(value);
    
    // Set in both caches
    this.memoryCache.set(key, value);
    await this.redis.setex(key, ttl, serialized);
  }
  
  async invalidate(pattern: string): Promise<void> {
    // Clear memory cache
    this.memoryCache.clear();
    
    // Clear Redis cache
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }
}

// Database connection pooling
class DatabaseService {
  private pool: Pool;
  
  constructor() {
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 20, // Maximum connections
      min: 5,  // Minimum connections
      idle: 10000, // 10 seconds
      acquire: 30000, // 30 seconds
      evict: 1000, // 1 second
    });
  }
  
  async query<T>(sql: string, params: any[] = []): Promise<T[]> {
    const client = await this.pool.connect();
    
    try {
      const start = Date.now();
      const result = await client.query(sql, params);
      const duration = Date.now() - start;
      
      // Log slow queries
      if (duration > 1000) {
        console.warn(`Slow query (${duration}ms):`, sql);
      }
      
      return result.rows;
    } finally {
      client.release();
    }
  }
}

// Request optimization middleware
function optimizeRequests() {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Enable compression
    res.setHeader('Content-Encoding', 'gzip');
    
    // Set cache headers for static content
    if (req.url.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg)$/)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
    
    // Enable HTTP/2 Server Push for critical resources
    if (req.httpVersion === '2.0') {
      res.setHeader('Link', '</css/critical.css>; rel=preload; as=style');
    }
    
    next();
  };
}

// Batch processing for database operations
class BatchProcessor {
  private batches: Map<string, any[]> = new Map();
  private timers: Map<string, NodeJS.Timeout> = new Map();
  
  async addToBatch<T>(
    batchKey: string,
    item: T,
    processor: (items: T[]) => Promise<void>,
    batchSize = 100,
    maxWaitTime = 1000
  ): Promise<void> {
    if (!this.batches.has(batchKey)) {
      this.batches.set(batchKey, []);
    }
    
    const batch = this.batches.get(batchKey)!;
    batch.push(item);
    
    // Process if batch is full
    if (batch.length >= batchSize) {
      await this.processBatch(batchKey, processor);
      return;
    }
    
    // Set timer for max wait time
    if (!this.timers.has(batchKey)) {
      const timer = setTimeout(async () => {
        await this.processBatch(batchKey, processor);
      }, maxWaitTime);
      
      this.timers.set(batchKey, timer);
    }
  }
  
  private async processBatch<T>(
    batchKey: string,
    processor: (items: T[]) => Promise<void>
  ): Promise<void> {
    const batch = this.batches.get(batchKey);
    if (!batch || batch.length === 0) return;
    
    // Clear timer
    const timer = this.timers.get(batchKey);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(batchKey);
    }
    
    // Process batch
    try {
      await processor(batch);
    } catch (error) {
      console.error(`Batch processing error for ${batchKey}:`, error);
    }
    
    // Clear batch
    this.batches.set(batchKey, []);
  }
}
```

### Server-Side Optimization
```typescript
// ✅ GOOD: Server optimization techniques

// Worker threads for CPU-intensive tasks
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';

class WorkerPool {
  private workers: Worker[] = [];
  private queue: Array<{ task: any; resolve: Function; reject: Function }> = [];
  private activeWorkers = 0;
  
  constructor(private maxWorkers = 4, private workerScript: string) {
    this.initializeWorkers();
  }
  
  private initializeWorkers(): void {
    for (let i = 0; i < this.maxWorkers; i++) {
      const worker = new Worker(this.workerScript);
      
      worker.on('message', (result) => {
        this.activeWorkers--;
        this.processQueue();
      });
      
      worker.on('error', (error) => {
        console.error('Worker error:', error);
        this.activeWorkers--;
        this.processQueue();
      });
      
      this.workers.push(worker);
    }
  }
  
  async execute<T>(task: any): Promise<T> {
    return new Promise((resolve, reject) => {
      this.queue.push({ task, resolve, reject });
      this.processQueue();
    });
  }
  
  private processQueue(): void {
    if (this.queue.length === 0 || this.activeWorkers >= this.maxWorkers) {
      return;
    }
    
    const { task, resolve, reject } = this.queue.shift()!;
    const worker = this.workers[this.activeWorkers];
    
    this.activeWorkers++;
    
    worker.postMessage(task);
    worker.once('message', resolve);
    worker.once('error', reject);
  }
}

// Memory management
class MemoryManager {
  private memoryThreshold = 0.8; // 80% of available memory
  
  monitorMemoryUsage(): void {
    setInterval(() => {
      const usage = process.memoryUsage();
      const totalMemory = require('os').totalmem();
      const memoryUsagePercent = usage.heapUsed / totalMemory;
      
      if (memoryUsagePercent > this.memoryThreshold) {
        console.warn('High memory usage detected:', {
          heapUsed: Math.round(usage.heapUsed / 1024 / 1024) + 'MB',
          heapTotal: Math.round(usage.heapTotal / 1024 / 1024) + 'MB',
          external: Math.round(usage.external / 1024 / 1024) + 'MB',
        });
        
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
      }
    }, 30000); // Check every 30 seconds
  }
  
  optimizeMemoryUsage(): void {
    // Optimize V8 flags for production
    process.env.NODE_OPTIONS = [
      '--max-old-space-size=4096',
      '--optimize-for-size',
      '--gc-interval=100',
    ].join(' ');
  }
}

// Response streaming for large datasets
class StreamingResponse {
  static async streamJsonArray<T>(
    res: Response,
    dataGenerator: AsyncGenerator<T>,
    transform?: (item: T) => any
  ): Promise<void> {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Transfer-Encoding', 'chunked');
    
    res.write('[');
    
    let isFirst = true;
    
    for await (const item of dataGenerator) {
      if (!isFirst) {
        res.write(',');
      }
      
      const processedItem = transform ? transform(item) : item;
      res.write(JSON.stringify(processedItem));
      
      isFirst = false;
    }
    
    res.write(']');
    res.end();
  }
  
  static async streamCsv<T>(
    res: Response,
    dataGenerator: AsyncGenerator<T>,
    headers: string[]
  ): Promise<void> {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Transfer-Encoding', 'chunked');
    
    // Write headers
    res.write(headers.join(',') + '\n');
    
    for await (const item of dataGenerator) {
      const row = headers.map(header => 
        JSON.stringify(item[header] || '')
      ).join(',');
      
      res.write(row + '\n');
    }
    
    res.end();
  }
}
```

## 📈 Performance Monitoring

### Real User Monitoring (RUM)
```typescript
// ✅ GOOD: Comprehensive performance monitoring
class PerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();
  private observer: PerformanceObserver;
  
  constructor() {
    this.initializeObserver();
    this.monitorWebVitals();
    this.monitorCustomMetrics();
  }
  
  private initializeObserver(): void {
    this.observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        this.recordMetric(entry.name, entry.duration || entry.value);
        
        // Send to analytics service
        this.sendToAnalytics({
          name: entry.name,
          value: entry.duration || entry.value,
          type: entry.entryType,
          timestamp: Date.now(),
        });
      }
    });
    
    this.observer.observe({ 
      entryTypes: ['measure', 'navigation', 'paint', 'largest-contentful-paint'] 
    });
  }
  
  private monitorWebVitals(): void {
    import('web-vitals').then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
      getCLS((metric) => this.handleWebVital('CLS', metric));
      getFID((metric) => this.handleWebVital('FID', metric));
      getFCP((metric) => this.handleWebVital('FCP', metric));
      getLCP((metric) => this.handleWebVital('LCP', metric));
      getTTFB((metric) => this.handleWebVital('TTFB', metric));
    });
  }
  
  private handleWebVital(name: string, metric: any): void {
    console.log(`${name}:`, metric.value);
    
    // Send to monitoring service
    this.sendToAnalytics({
      name,
      value: metric.value,
      rating: metric.rating,
      delta: metric.delta,
      id: metric.id,
      timestamp: Date.now(),
    });
  }
  
  // Custom performance measurements
  startMeasurement(name: string): void {
    performance.mark(`${name}-start`);
  }
  
  endMeasurement(name: string): number {
    performance.mark(`${name}-end`);
    performance.measure(name, `${name}-start`, `${name}-end`);
    
    const measure = performance.getEntriesByName(name, 'measure')[0];
    return measure.duration;
  }
  
  // Resource timing analysis
  analyzeResourceTiming(): ResourceTimingAnalysis {
    const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
    
    const analysis = {
      totalResources: resources.length,
      totalSize: 0,
      slowestResources: [] as Array<{ name: string; duration: number }>,
      resourceTypes: {} as Record<string, number>,
    };
    
    resources.forEach(resource => {
      const duration = resource.responseEnd - resource.requestStart;
      
      // Track resource types
      const type = this.getResourceType(resource.name);
      analysis.resourceTypes[type] = (analysis.resourceTypes[type] || 0) + 1;
      
      // Track slow resources
      if (duration > 1000) { // > 1 second
        analysis.slowestResources.push({
          name: resource.name,
          duration,
        });
      }
      
      // Estimate size (if available)
      if (resource.transferSize) {
        analysis.totalSize += resource.transferSize;
      }
    });
    
    analysis.slowestResources.sort((a, b) => b.duration - a.duration);
    
    return analysis;
  }
  
  private getResourceType(url: string): string {
    if (url.match(/\.(css)$/)) return 'css';
    if (url.match(/\.(js)$/)) return 'javascript';
    if (url.match(/\.(png|jpg|jpeg|gif|webp|svg)$/)) return 'image';
    if (url.match(/\.(woff|woff2|ttf|eot)$/)) return 'font';
    return 'other';
  }
  
  private recordMetric(name: string, value: number): void {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    
    const values = this.metrics.get(name)!;
    values.push(value);
    
    // Keep only last 100 measurements
    if (values.length > 100) {
      values.shift();
    }
  }
  
  private async sendToAnalytics(data: any): Promise<void> {
    try {
      await fetch('/api/analytics/performance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
    } catch (error) {
      console.error('Failed to send analytics:', error);
    }
  }
  
  getMetricSummary(name: string): MetricSummary | null {
    const values = this.metrics.get(name);
    if (!values || values.length === 0) return null;
    
    const sorted = [...values].sort((a, b) => a - b);
    
    return {
      count: values.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      median: sorted[Math.floor(sorted.length / 2)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      average: values.reduce((sum, val) => sum + val, 0) / values.length,
    };
  }
}

interface ResourceTimingAnalysis {
  totalResources: number;
  totalSize: number;
  slowestResources: Array<{ name: string; duration: number }>;
  resourceTypes: Record<string, number>;
}

interface MetricSummary {
  count: number;
  min: number;
  max: number;
  median: number;
  p95: number;
  average: number;
}
```

### Performance Testing
```javascript
// ✅ GOOD: Load testing with k6
// load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

export const options = {
  stages: [
    { duration: '2m', target: 10 }, // Ramp up
    { duration: '5m', target: 10 }, // Stay at 10 users
    { duration: '2m', target: 20 }, // Ramp up to 20 users
    { duration: '5m', target: 20 }, // Stay at 20 users
    { duration: '2m', target: 0 },  // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests under 500ms
    http_req_failed: ['rate<0.1'],    // Error rate under 10%
    errors: ['rate<0.1'],
  },
};

export default function () {
  // Test homepage
  const homeResponse = http.get('https://your-app.com');
  check(homeResponse, {
    'homepage status is 200': (r) => r.status === 200,
    'homepage loads in <2s': (r) => r.timings.duration < 2000,
  }) || errorRate.add(1);
  
  sleep(1);
  
  // Test API endpoint
  const apiResponse = http.get('https://your-app.com/api/users', {
    headers: { 'Authorization': 'Bearer token' },
  });
  
  check(apiResponse, {
    'API status is 200': (r) => r.status === 200,
    'API response time <500ms': (r) => r.timings.duration < 500,
    'API returns valid JSON': (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch {
        return false;
      }
    },
  }) || errorRate.add(1);
  
  sleep(1);
}

// Stress test configuration
export const stressTestOptions = {
  stages: [
    { duration: '10m', target: 100 }, // Ramp up to 100 users
    { duration: '30m', target: 100 }, // Stay at 100 users
    { duration: '5m', target: 200 },  // Spike to 200 users
    { duration: '10m', target: 200 }, // Stay at 200 users
    { duration: '10m', target: 0 },   // Ramp down
  ],
};
```

## ⚡ Performance Best Practices

### Code Splitting & Lazy Loading
```typescript
// ✅ GOOD: Strategic code splitting

// Route-based code splitting
const HomePage = lazy(() => import('./pages/HomePage'));
const ProfilePage = lazy(() => import('./pages/ProfilePage'));
const AdminPanel = lazy(() => 
  import('./pages/AdminPanel').then(module => ({
    default: module.AdminPanel
  }))
);

// Component-based code splitting
const HeavyChart = lazy(() => 
  import('./components/HeavyChart').then(module => ({
    default: module.HeavyChart
  }))
);

// Feature-based code splitting
const PaymentModule = lazy(() => import('./modules/payment'));

// Preload critical routes
const preloadRoute = (routeComponent: () => Promise<any>) => {
  const componentImport = routeComponent();
  return componentImport;
};

// Preload on hover
const PreloadLink = ({ to, children, ...props }) => {
  const handleMouseEnter = () => {
    // Preload the route component
    import(`./pages/${to}Page`);
  };
  
  return (
    <Link to={to} onMouseEnter={handleMouseEnter} {...props}>
      {children}
    </Link>
  );
};

// Smart loading states
const SmartSuspense = ({ children, fallback }) => {
  const [showFallback, setShowFallback] = useState(false);
  
  useEffect(() => {
    const timer = setTimeout(() => setShowFallback(true), 200);
    return () => clearTimeout(timer);
  }, []);
  
  return (
    <Suspense fallback={showFallback ? fallback : null}>
      {children}
    </Suspense>
  );
};
```

### Caching Strategies
```typescript
// ✅ GOOD: Multi-level caching implementation

// Service Worker for offline caching
// sw.js
const CACHE_NAME = 'app-v1';
const STATIC_CACHE = 'static-v1';
const DYNAMIC_CACHE = 'dynamic-v1';

const STATIC_ASSETS = [
  '/',
  '/static/css/main.css',
  '/static/js/main.js',
  '/manifest.json',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => cache.addAll(STATIC_ASSETS))
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  
  // Cache-first strategy for static assets
  if (request.url.includes('/static/')) {
    event.respondWith(
      caches.match(request)
        .then(response => response || fetch(request))
    );
    return;
  }
  
  // Network-first strategy for API calls
  if (request.url.includes('/api/')) {
    event.respondWith(
      fetch(request)
        .then(response => {
          const responseClone = response.clone();
          caches.open(DYNAMIC_CACHE)
            .then(cache => cache.put(request, responseClone));
          return response;
        })
        .catch(() => caches.match(request))
    );
    return;
  }
  
  // Stale-while-revalidate for pages
  event.respondWith(
    caches.match(request)
      .then(response => {
        const fetchPromise = fetch(request)
          .then(networkResponse => {
            caches.open(DYNAMIC_CACHE)
              .then(cache => cache.put(request, networkResponse.clone()));
            return networkResponse;
          });
        
        return response || fetchPromise;
      })
  );
});

// HTTP caching headers
const setCacheHeaders = (res: Response, type: 'static' | 'dynamic' | 'api') => {
  switch (type) {
    case 'static':
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      break;
    case 'dynamic':
      res.setHeader('Cache-Control', 'public, max-age=3600, stale-while-revalidate=86400');
      break;
    case 'api':
      res.setHeader('Cache-Control', 'private, max-age=300');
      break;
  }
};
```

## ✅ Performance Checklist

### Pre-Launch Performance Checklist
- [ ] Core Web Vitals meet target thresholds
- [ ] Lighthouse Performance score ≥ 90
- [ ] Bundle sizes within limits
- [ ] Images optimized and using modern formats
- [ ] Critical CSS inlined
- [ ] JavaScript code split appropriately
- [ ] Lazy loading implemented for non-critical content
- [ ] Service Worker configured for caching
- [ ] Database queries optimized with proper indexes
- [ ] API responses cached appropriately
- [ ] CDN configured for static assets
- [ ] Compression enabled (Gzip/Brotli)
- [ ] HTTP/2 or HTTP/3 enabled
- [ ] Performance monitoring implemented
- [ ] Load testing completed

### Ongoing Performance Monitoring
- [ ] Real User Monitoring (RUM) active
- [ ] Performance budgets enforced in CI/CD
- [ ] Regular performance audits scheduled
- [ ] Database performance monitored
- [ ] Server resource utilization tracked
- [ ] Third-party script performance monitored
- [ ] Performance regression alerts configured
- [ ] Regular load testing performed

---

*These performance standards should be adapted based on specific application requirements, user base, and technical constraints.*