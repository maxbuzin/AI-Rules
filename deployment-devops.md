# Deployment & DevOps Standards

## 🚀 Overview

This document establishes comprehensive deployment, DevOps, and infrastructure standards for Next.js 15 applications with Supabase backend integration. These guidelines ensure reliable, secure, and scalable deployment processes with proper monitoring and maintenance procedures, following the Simplicity First principle.

## 🏗️ Infrastructure as Code (IaC)

### Next.js 15 & Supabase Infrastructure

```dockerfile
# ✅ GOOD: Next.js 15 Docker configuration
# Dockerfile
FROM node:20-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./
RUN npm ci --only=production

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Next.js collects completely anonymous telemetry data about general usage.
# Learn more here: https://nextjs.org/telemetry
# Uncomment the following line in case you want to disable telemetry during the build.
# ENV NEXT_TELEMETRY_DISABLED 1

# Build Next.js 15 application
RUN npm run build

# Production image
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production
# ENV NEXT_TELEMETRY_DISABLED 1

# Create non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy built application
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]
```

```yaml
# ✅ GOOD: Supabase Environment Configuration
# .env.example
NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
SUPABASE_JWT_SECRET=your_jwt_secret
SUPABASE_DB_PASSWORD=your_database_password

# Next.js Configuration
NEXTAUTH_SECRET=your_nextauth_secret
NEXTAUTH_URL=http://localhost:3000

# Optional: Analytics and Monitoring
NEXT_PUBLIC_VERCEL_ANALYTICS_ID=your_analytics_id
```

```yaml
# ✅ GOOD: Docker Compose for local development
# docker-compose.yml
version: '3.8'
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - NEXT_PUBLIC_SUPABASE_URL=${NEXT_PUBLIC_SUPABASE_URL}
      - NEXT_PUBLIC_SUPABASE_ANON_KEY=${NEXT_PUBLIC_SUPABASE_ANON_KEY}
      - SUPABASE_SERVICE_ROLE_KEY=${SUPABASE_SERVICE_ROLE_KEY}
    volumes:
      - .:/app
      - /app/node_modules
      - /app/.next
    depends_on:
      - supabase
  
  supabase:
    image: supabase/supabase:latest
    ports:
      - "54321:54321"
    environment:
      - POSTGRES_PASSWORD=${SUPABASE_DB_PASSWORD}
    volumes:
      - supabase_data:/var/lib/postgresql/data

volumes:
  supabase_data:
```

```dockerignore
# ✅ GOOD: .dockerignore for Next.js 15
node_modules
npm-debug.log
.next
.git
.gitignore
README.md
Dockerfile
.dockerignore
coverage
.nyc_output
.env.local
.env.development.local
.env.test.local
.env.production.local
.env
supabase/.temp
```

### Container Orchestration
```yaml
# ✅ GOOD: Next.js 15 Kubernetes deployment with Supabase
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nextjs-app-deployment
  labels:
    app: nextjs-app
    version: v1
    framework: nextjs-15
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nextjs-app
  template:
    metadata:
      labels:
        app: nextjs-app
        version: v1
        framework: nextjs-15
    spec:
      containers:
      - name: nextjs-app
        image: your-registry/nextjs-app:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "3000"
        - name: HOSTNAME
          value: "0.0.0.0"
        - name: NEXT_PUBLIC_SUPABASE_URL
          valueFrom:
            secretKeyRef:
              name: supabase-secrets
              key: supabase-url
        - name: NEXT_PUBLIC_SUPABASE_ANON_KEY
          valueFrom:
            secretKeyRef:
              name: supabase-secrets
              key: supabase-anon-key
        - name: SUPABASE_SERVICE_ROLE_KEY
          valueFrom:
            secretKeyRef:
              name: supabase-secrets
              key: supabase-service-role-key
        - name: NEXTAUTH_SECRET
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: nextauth-secret
        - name: NEXTAUTH_URL
          value: "https://your-domain.com"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /api/ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          successThreshold: 1
          failureThreshold: 3
        securityContext:
          runAsNonRoot: true
          runAsUser: 1001
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: false  # Next.js needs write access for cache
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: nextjs-cache
          mountPath: /app/.next/cache
          readOnly: false
      volumes:
      - name: nextjs-cache
        emptyDir: {}

---
# ✅ GOOD: Supabase secrets configuration
apiVersion: v1
kind: Secret
metadata:
  name: supabase-secrets
type: Opaque
stringData:
  supabase-url: "https://your-project.supabase.co"
  supabase-anon-key: "your-anon-key"
  supabase-service-role-key: "your-service-role-key"

---
apiVersion: v1
kind: Service
metadata:
  name: app-service
spec:
  selector:
    app: web-app
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: ClusterIP

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - your-domain.com
    secretName: app-tls
  rules:
  - host: your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
```

### Infrastructure Monitoring
```yaml
# ✅ GOOD: Prometheus monitoring configuration
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'web-app'
    static_configs:
      - targets: ['app-service:3000']
    metrics_path: '/metrics'
    scrape_interval: 30s
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
      
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']

# Alert rules
# monitoring/alert_rules.yml
groups:
- name: web-app-alerts
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"
      
  - alert: HighResponseTime
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High response time detected"
      description: "95th percentile response time is {{ $value }} seconds"
      
  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.8
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage detected"
      description: "Memory usage is {{ $value | humanizePercentage }}"
```

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow
```yaml
# ✅ GOOD: Comprehensive CI/CD pipeline
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

env:
  NODE_VERSION: '18'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
          
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
        
    - name: Setup Supabase CLI
      uses: supabase/setup-cli@v1
      with:
        version: latest
        
    - name: Install dependencies
      run: npm ci
      
    - name: Start Supabase local development
      run: |
        supabase start
        supabase db reset --linked=false
      env:
        SUPABASE_ACCESS_TOKEN: ${{ secrets.SUPABASE_ACCESS_TOKEN }}
        
    - name: Run database migrations
      run: supabase db push
      
    - name: Seed test data
      run: supabase db seed
      
    - name: Run linting
      run: npm run lint
      
    - name: Run type checking
      run: npm run type-check
      
    - name: Run unit tests
      run: npm run test:unit
      env:
        NEXT_PUBLIC_SUPABASE_URL: http://localhost:54321
        NEXT_PUBLIC_SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY_LOCAL }}
        SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY_LOCAL }}
        
    - name: Run integration tests
      run: npm run test:integration
      env:
        NEXT_PUBLIC_SUPABASE_URL: http://localhost:54321
        NEXT_PUBLIC_SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY_LOCAL }}
        SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY_LOCAL }}
        
    - name: Test RLS policies
      run: npm run test:rls
      env:
        NEXT_PUBLIC_SUPABASE_URL: http://localhost:54321
        SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY_LOCAL }}
        
    - name: Run E2E tests
      run: npm run test:e2e
      env:
        NEXT_PUBLIC_SUPABASE_URL: http://localhost:54321
        NEXT_PUBLIC_SUPABASE_ANON_KEY: ${{ secrets.SUPABASE_ANON_KEY_LOCAL }}
        
    - name: Test mobile responsiveness (320px+)
      run: npm run test:responsive
      
    - name: Generate coverage report
      run: npm run test:coverage
      
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info
        
    - name: Build Next.js application
      run: npm run build
      env:
        NEXT_PUBLIC_SUPABASE_URL: ${{ secrets.NEXT_PUBLIC_SUPABASE_URL }}
        NEXT_PUBLIC_SUPABASE_ANON_KEY: ${{ secrets.NEXT_PUBLIC_SUPABASE_ANON_KEY }}
        
    - name: Run security audit
      run: npm audit --audit-level high
      
    - name: Run dependency check
      run: npx depcheck
      
    - name: Bundle size analysis
      run: npm run analyze
      
    - name: Test Supabase Edge Functions
      run: |
        supabase functions serve &
        sleep 10
        npm run test:edge-functions
        
    - name: Stop Supabase
      run: supabase stop
      if: always()
      
  security:
    runs-on: ubuntu-latest
    needs: test
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
        
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
        
    - name: Run CodeQL Analysis
      uses: github/codeql-action/analyze@v2
      with:
        languages: javascript
        
  build-and-push:
    runs-on: ubuntu-latest
    needs: [test, security]
    if: github.ref == 'refs/heads/main'
    
    permissions:
      contents: read
      packages: write
      
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
        
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
          type=raw,value=latest,enable={{is_default_branch}}
          
    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        
  deploy-staging:
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == 'refs/heads/develop'
    environment: staging
    
    steps:
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment"
        # Add deployment commands here
        
  deploy-production:
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == 'refs/heads/main'
    environment: production
    
    steps:
    - name: Deploy to production
      run: |
        echo "Deploying to production environment"
        # Add deployment commands here
        
    - name: Run smoke tests
      run: |
        echo "Running smoke tests"
        # Add smoke test commands here
        
    - name: Notify deployment
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#deployments'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
      if: always()
```

### Deployment Scripts
```bash
#!/bin/bash
# ✅ GOOD: Production deployment script
# scripts/deploy.sh

set -euo pipefail

# Configuration
APP_NAME="web-app"
ENVIRONMENT="${1:-production}"
IMAGE_TAG="${2:-latest}"
NAMESPACE="${APP_NAME}-${ENVIRONMENT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Pre-deployment checks
log "Starting deployment of ${APP_NAME} to ${ENVIRONMENT}"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    error "kubectl is not installed or not in PATH"
fi

# Check if we can connect to the cluster
if ! kubectl cluster-info &> /dev/null; then
    error "Cannot connect to Kubernetes cluster"
fi

# Check if namespace exists
if ! kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    log "Creating namespace ${NAMESPACE}"
    kubectl create namespace "${NAMESPACE}"
fi

# Backup current deployment
log "Creating backup of current deployment"
kubectl get deployment "${APP_NAME}-deployment" -n "${NAMESPACE}" -o yaml > "/tmp/${APP_NAME}-backup-$(date +%s).yaml" 2>/dev/null || true

# Update deployment image
log "Updating deployment image to ${IMAGE_TAG}"
kubectl set image deployment/${APP_NAME}-deployment \
    ${APP_NAME}=ghcr.io/your-org/${APP_NAME}:${IMAGE_TAG} \
    -n "${NAMESPACE}"

# Wait for rollout to complete
log "Waiting for rollout to complete..."
if kubectl rollout status deployment/${APP_NAME}-deployment -n "${NAMESPACE}" --timeout=300s; then
    log "Deployment successful!"
else
    error "Deployment failed or timed out"
fi

# Run health checks
log "Running health checks..."
sleep 10

# Check if pods are ready
READY_PODS=$(kubectl get pods -n "${NAMESPACE}" -l app=${APP_NAME} --field-selector=status.phase=Running -o jsonpath='{.items[*].status.containerStatuses[0].ready}' | tr ' ' '\n' | grep -c true || echo 0)
TOTAL_PODS=$(kubectl get pods -n "${NAMESPACE}" -l app=${APP_NAME} --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}' | wc -w)

if [ "${READY_PODS}" -eq "${TOTAL_PODS}" ] && [ "${TOTAL_PODS}" -gt 0 ]; then
    log "All ${TOTAL_PODS} pods are ready"
else
    error "Only ${READY_PODS}/${TOTAL_PODS} pods are ready"
fi

# Test application endpoint
log "Testing application endpoint..."
SERVICE_IP=$(kubectl get service ${APP_NAME}-service -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")

if [ -n "${SERVICE_IP}" ]; then
    if curl -f -s "http://${SERVICE_IP}/health" > /dev/null; then
        log "Health check passed"
    else
        warn "Health check failed, but deployment completed"
    fi
else
    log "Service IP not available, skipping external health check"
fi

# Clean up old replica sets
log "Cleaning up old replica sets..."
kubectl delete replicaset -n "${NAMESPACE}" -l app=${APP_NAME} --field-selector='status.replicas==0' || true

log "Deployment completed successfully!"
log "Application: ${APP_NAME}"
log "Environment: ${ENVIRONMENT}"
log "Image Tag: ${IMAGE_TAG}"
log "Namespace: ${NAMESPACE}"
```

## 🔍 Monitoring & Observability

### Application Monitoring
```typescript
// ✅ GOOD: Comprehensive application monitoring
import { createPrometheusMetrics } from 'prom-client';
import { Request, Response, NextFunction } from 'express';

// Metrics collection
class MetricsCollector {
  private httpRequestDuration: any;
  private httpRequestsTotal: any;
  private activeConnections: any;
  private databaseQueryDuration: any;
  private cacheHitRate: any;
  
  constructor() {
    this.initializeMetrics();
  }
  
  private initializeMetrics(): void {
    const promClient = require('prom-client');
    
    // HTTP request duration histogram
    this.httpRequestDuration = new promClient.Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
    });
    
    // HTTP requests counter
    this.httpRequestsTotal = new promClient.Counter({
      name: 'http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code'],
    });
    
    // Active connections gauge
    this.activeConnections = new promClient.Gauge({
      name: 'active_connections',
      help: 'Number of active connections',
    });
    
    // Database query duration
    this.databaseQueryDuration = new promClient.Histogram({
      name: 'database_query_duration_seconds',
      help: 'Duration of database queries in seconds',
      labelNames: ['query_type', 'table'],
      buckets: [0.01, 0.05, 0.1, 0.3, 0.5, 1, 3, 5],
    });
    
    // Cache hit rate
    this.cacheHitRate = new promClient.Counter({
      name: 'cache_requests_total',
      help: 'Total cache requests',
      labelNames: ['type', 'result'], // result: hit, miss
    });
    
    // Collect default metrics
    promClient.collectDefaultMetrics({ timeout: 5000 });
  }
  
  // Middleware for HTTP metrics
  httpMetricsMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const start = Date.now();
      
      res.on('finish', () => {
        const duration = (Date.now() - start) / 1000;
        const route = req.route?.path || req.path;
        
        this.httpRequestDuration
          .labels(req.method, route, res.statusCode.toString())
          .observe(duration);
          
        this.httpRequestsTotal
          .labels(req.method, route, res.statusCode.toString())
          .inc();
      });
      
      next();
    };
  }
  
  // Database query metrics
  recordDatabaseQuery(queryType: string, table: string, duration: number): void {
    this.databaseQueryDuration
      .labels(queryType, table)
      .observe(duration / 1000);
  }
  
  // Cache metrics
  recordCacheAccess(type: string, hit: boolean): void {
    this.cacheHitRate
      .labels(type, hit ? 'hit' : 'miss')
      .inc();
  }
  
  // Custom business metrics
  recordUserAction(action: string, userId: string): void {
    const userActionsCounter = new (require('prom-client')).Counter({
      name: 'user_actions_total',
      help: 'Total user actions',
      labelNames: ['action', 'user_type'],
    });
    
    // Determine user type (could be based on subscription, role, etc.)
    const userType = this.getUserType(userId);
    userActionsCounter.labels(action, userType).inc();
  }
  
  private getUserType(userId: string): string {
    // Implementation depends on your user system
    return 'standard'; // or 'premium', 'admin', etc.
  }
}

// Health check endpoints
class HealthCheckService {
  private dependencies: Map<string, () => Promise<boolean>> = new Map();
  
  constructor() {
    this.registerDependencies();
  }
  
  private registerDependencies(): void {
    // Database health check
    this.dependencies.set('database', async () => {
      try {
        await this.checkDatabase();
        return true;
      } catch {
        return false;
      }
    });
    
    // Redis health check
    this.dependencies.set('redis', async () => {
      try {
        await this.checkRedis();
        return true;
      } catch {
        return false;
      }
    });
    
    // External API health check
    this.dependencies.set('external_api', async () => {
      try {
        await this.checkExternalAPI();
        return true;
      } catch {
        return false;
      }
    });
  }
  
  async getHealthStatus(): Promise<HealthStatus> {
    const checks: Record<string, boolean> = {};
    let overallHealth = true;
    
    for (const [name, check] of this.dependencies) {
      try {
        checks[name] = await check();
        if (!checks[name]) {
          overallHealth = false;
        }
      } catch (error) {
        checks[name] = false;
        overallHealth = false;
      }
    }
    
    return {
      status: overallHealth ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      checks,
      uptime: process.uptime(),
      version: process.env.APP_VERSION || 'unknown',
    };
  }
  
  async getReadinessStatus(): Promise<ReadinessStatus> {
    // Readiness checks are typically lighter than health checks
    const isReady = await this.checkReadiness();
    
    return {
      status: isReady ? 'ready' : 'not_ready',
      timestamp: new Date().toISOString(),
    };
  }
  
  private async checkDatabase(): Promise<void> {
    // Simple query to check database connectivity
    await this.db.query('SELECT 1');
  }
  
  private async checkRedis(): Promise<void> {
    await this.redis.ping();
  }
  
  private async checkExternalAPI(): Promise<void> {
    const response = await fetch('https://api.external-service.com/health', {
      timeout: 5000,
    });
    
    if (!response.ok) {
      throw new Error('External API unhealthy');
    }
  }
  
  private async checkReadiness(): Promise<boolean> {
    // Check if application is ready to serve traffic
    // This might include checking if migrations are complete,
    // configuration is loaded, etc.
    return true;
  }
}

interface HealthStatus {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  checks: Record<string, boolean>;
  uptime: number;
  version: string;
}

interface ReadinessStatus {
  status: 'ready' | 'not_ready';
  timestamp: string;
}
```

### Logging Standards
```typescript
// ✅ GOOD: Structured logging implementation
import winston from 'winston';
import { Request, Response } from 'express';

// Structured logger configuration
class Logger {
  private logger: winston.Logger;
  
  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          return JSON.stringify({
            timestamp,
            level,
            message,
            service: process.env.SERVICE_NAME || 'web-app',
            version: process.env.APP_VERSION || 'unknown',
            environment: process.env.NODE_ENV || 'development',
            ...meta,
          });
        })
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ 
          filename: 'logs/error.log', 
          level: 'error',
          maxsize: 10485760, // 10MB
          maxFiles: 5,
        }),
        new winston.transports.File({ 
          filename: 'logs/combined.log',
          maxsize: 10485760, // 10MB
          maxFiles: 10,
        }),
      ],
    });
  }
  
  info(message: string, meta?: any): void {
    this.logger.info(message, meta);
  }
  
  warn(message: string, meta?: any): void {
    this.logger.warn(message, meta);
  }
  
  error(message: string, error?: Error, meta?: any): void {
    this.logger.error(message, {
      error: error ? {
        name: error.name,
        message: error.message,
        stack: error.stack,
      } : undefined,
      ...meta,
    });
  }
  
  debug(message: string, meta?: any): void {
    this.logger.debug(message, meta);
  }
  
  // Request logging middleware
  requestLogger() {
    return (req: Request, res: Response, next: Function) => {
      const start = Date.now();
      
      // Log request
      this.info('HTTP Request', {
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        userId: req.user?.id,
        requestId: req.id,
      });
      
      res.on('finish', () => {
        const duration = Date.now() - start;
        
        // Log response
        this.info('HTTP Response', {
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          duration,
          requestId: req.id,
        });
      });
      
      next();
    };
  }
  
  // Database query logging
  logDatabaseQuery(query: string, params: any[], duration: number, userId?: string): void {
    this.debug('Database Query', {
      query: query.replace(/\s+/g, ' ').trim(),
      paramCount: params.length,
      duration,
      userId,
    });
  }
  
  // Business event logging
  logBusinessEvent(event: string, data: any, userId?: string): void {
    this.info('Business Event', {
      event,
      data,
      userId,
    });
  }
  
  // Security event logging
  logSecurityEvent(event: string, details: any, severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'): void {
    this.warn('Security Event', {
      event,
      severity,
      details,
    });
  }
}

// Error tracking integration
class ErrorTracker {
  private sentryDsn: string;
  
  constructor() {
    this.sentryDsn = process.env.SENTRY_DSN || '';
    this.initializeSentry();
  }
  
  private initializeSentry(): void {
    if (!this.sentryDsn) return;
    
    const Sentry = require('@sentry/node');
    
    Sentry.init({
      dsn: this.sentryDsn,
      environment: process.env.NODE_ENV,
      release: process.env.APP_VERSION,
      tracesSampleRate: 0.1,
      beforeSend(event: any) {
        // Filter out sensitive information
        if (event.request) {
          delete event.request.cookies;
          delete event.request.headers?.authorization;
        }
        return event;
      },
    });
  }
  
  captureException(error: Error, context?: any): void {
    const Sentry = require('@sentry/node');
    
    Sentry.withScope((scope: any) => {
      if (context) {
        Object.keys(context).forEach(key => {
          scope.setContext(key, context[key]);
        });
      }
      
      Sentry.captureException(error);
    });
  }
  
  captureMessage(message: string, level: 'info' | 'warning' | 'error' = 'info'): void {
    const Sentry = require('@sentry/node');
    Sentry.captureMessage(message, level);
  }
}
```

## 🔒 Security in Deployment

### Secrets Management
```yaml
# ✅ GOOD: Kubernetes secrets configuration
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: web-app-production
type: Opaque
data:
  database-url: <base64-encoded-database-url>
  jwt-secret: <base64-encoded-jwt-secret>
  api-key: <base64-encoded-api-key>

---
# External secrets operator configuration
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: web-app-production
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "web-app"

---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: web-app-production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-url
    remoteRef:
      key: web-app/production
      property: database_url
  - secretKey: jwt-secret
    remoteRef:
      key: web-app/production
      property: jwt_secret
```

### Network Security
```yaml
# ✅ GOOD: Network policies for security
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-app-network-policy
  namespace: web-app-production
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 3000
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
    ports:
    - protocol: TCP
      port: 5432
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS
    - protocol: TCP
      port: 53   # DNS
    - protocol: UDP
      port: 53   # DNS
```

## 📊 Performance & Scaling

### Auto-scaling Configuration
```yaml
# ✅ GOOD: Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-app-hpa
  namespace: web-app-production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: app-deployment
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
      - type: Pods
        value: 2
        periodSeconds: 60
      selectPolicy: Max

---
# Vertical Pod Autoscaler
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: web-app-vpa
  namespace: web-app-production
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: app-deployment
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: web-app
      maxAllowed:
        cpu: 1
        memory: 2Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
```

## 🔄 Backup & Disaster Recovery

### Backup Strategy
```bash
#!/bin/bash
# ✅ GOOD: Automated backup script
# scripts/backup.sh

set -euo pipefail

# Configuration
BACKUP_TYPE="${1:-full}"
RETENTION_DAYS=30
S3_BUCKET="your-backup-bucket"
DATABASE_URL="${DATABASE_URL}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Database backup
backup_database() {
    log "Starting database backup..."
    
    local backup_file="db_backup_${TIMESTAMP}.sql.gz"
    
    # Create database dump
    pg_dump "${DATABASE_URL}" | gzip > "/tmp/${backup_file}"
    
    # Upload to S3
    aws s3 cp "/tmp/${backup_file}" "s3://${S3_BUCKET}/database/${backup_file}"
    
    # Clean up local file
    rm "/tmp/${backup_file}"
    
    log "Database backup completed: ${backup_file}"
}

# File system backup
backup_files() {
    log "Starting file system backup..."
    
    local backup_file="files_backup_${TIMESTAMP}.tar.gz"
    
    # Create tar archive of important directories
    tar -czf "/tmp/${backup_file}" \
        --exclude='node_modules' \
        --exclude='.git' \
        --exclude='logs' \
        /app/uploads \
        /app/config \
        /app/ssl
    
    # Upload to S3
    aws s3 cp "/tmp/${backup_file}" "s3://${S3_BUCKET}/files/${backup_file}"
    
    # Clean up local file
    rm "/tmp/${backup_file}"
    
    log "File system backup completed: ${backup_file}"
}

# Configuration backup
backup_config() {
    log "Starting configuration backup..."
    
    local backup_file="config_backup_${TIMESTAMP}.tar.gz"
    
    # Backup Kubernetes configurations
    kubectl get all,configmap,secret,pv,pvc -o yaml > "/tmp/k8s_config_${TIMESTAMP}.yaml"
    
    # Create tar archive
    tar -czf "/tmp/${backup_file}" \
        "/tmp/k8s_config_${TIMESTAMP}.yaml" \
        docker-compose.yml \
        .env.example
    
    # Upload to S3
    aws s3 cp "/tmp/${backup_file}" "s3://${S3_BUCKET}/config/${backup_file}"
    
    # Clean up local files
    rm "/tmp/${backup_file}" "/tmp/k8s_config_${TIMESTAMP}.yaml"
    
    log "Configuration backup completed: ${backup_file}"
}

# Clean up old backups
cleanup_old_backups() {
    log "Cleaning up backups older than ${RETENTION_DAYS} days..."
    
    # Delete old database backups
    aws s3 ls "s3://${S3_BUCKET}/database/" | \
        awk '{print $4}' | \
        while read -r file; do
            if [[ -n "$file" ]]; then
                file_date=$(echo "$file" | grep -oE '[0-9]{8}' | head -1)
                if [[ -n "$file_date" ]]; then
                    days_old=$(( ($(date +%s) - $(date -d "$file_date" +%s)) / 86400 ))
                    if [[ $days_old -gt $RETENTION_DAYS ]]; then
                        aws s3 rm "s3://${S3_BUCKET}/database/$file"
                        log "Deleted old backup: $file"
                    fi
                fi
            fi
        done
    
    log "Cleanup completed"
}

# Main execution
case "$BACKUP_TYPE" in
    "database")
        backup_database
        ;;
    "files")
        backup_files
        ;;
    "config")
        backup_config
        ;;
    "full")
        backup_database
        backup_files
        backup_config
        cleanup_old_backups
        ;;
    *)
        echo "Usage: $0 {database|files|config|full}"
        exit 1
        ;;
esac

log "Backup process completed successfully"
```

## ✅ Deployment Checklist

### Pre-Deployment Checklist
- [ ] All tests passing (unit, integration, E2E)
- [ ] Security scans completed
- [ ] Performance benchmarks met
- [ ] Database migrations tested
- [ ] Environment variables configured
- [ ] Secrets properly managed
- [ ] SSL certificates valid
- [ ] Monitoring and alerting configured
- [ ] Backup strategy implemented
- [ ] Rollback plan prepared
- [ ] Load balancer configured
- [ ] CDN configured for static assets
- [ ] DNS records updated
- [ ] Health checks implemented

### Post-Deployment Checklist
- [ ] Application responding to health checks
- [ ] All services running correctly
- [ ] Database connections working
- [ ] External integrations functioning
- [ ] Monitoring dashboards showing green
- [ ] No error alerts triggered
- [ ] Performance metrics within targets
- [ ] User acceptance testing passed
- [ ] Documentation updated
- [ ] Team notified of deployment
- [ ] Rollback tested (if applicable)

### Production Maintenance
- [ ] Regular security updates scheduled
- [ ] Automated backups running
- [ ] Log rotation configured
- [ ] Monitoring alerts tuned
- [ ] Capacity planning reviewed
- [ ] Disaster recovery tested
- [ ] Performance optimization ongoing
- [ ] Cost optimization reviewed

---

*These deployment and DevOps standards should be adapted based on specific infrastructure requirements, compliance needs, and organizational policies.*