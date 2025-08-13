# Next.js 15 & Supabase Project Rules & Standards

This directory contains comprehensive project rules specifically designed for Next.js 15 applications with Supabase backend integration. These rules establish consistent development practices, quality standards, and team processes following the **Simplicity First** principle.

## 📁 Directory Structure

```
default-project-rules/
├── README.md                    # This file - overview and quick start
├── core-standards.md           # Universal coding standards and conventions
├── architecture-guidelines.md  # Architectural patterns and design principles
├── quality-assurance.md        # Testing, performance, and quality standards
├── team-processes.md           # Collaboration workflows and escalation
├── security-standards.md       # Security practices and protocols
├── performance-optimization.md # Performance standards and optimization
└── deployment-devops.md        # Deployment, CI/CD, and infrastructure
```

## 🚀 **Simplicity First Principle**

All standards follow the implementation hierarchy:
1. **Vanilla JavaScript** - for simple interactions
2. **shadcn/ui** - for prebuilt UI patterns
3. **React.js** - for complex interactivity
4. **Next.js 15** - for full-stack routing and server components

## 📋 Complete Rule Set

This Next.js 15 & Supabase rule set includes:

### ✅ **Core Standards** (`core-standards.md`)
- Next.js 15 coding conventions and App Router structure
- shadcn/ui component organization and Tailwind CSS v4.1 standards
- Server Component vs Client Component patterns
- Supabase integration and TypeScript configurations

### 🏗️ **Architecture Guidelines** (`architecture-guidelines.md`)
- Next.js 15 App Router architecture with Server Components
- Supabase integration patterns and RLS policy design
- Mobile-first responsive design (320px+) with shadcn/ui
- Performance optimization for Core Web Vitals

### 🔍 **Quality Assurance** (`quality-assurance.md`)
- Server Component and Server Action testing with Jest
- RLS policy validation and Supabase integration testing
- Mobile responsiveness testing (320px to desktop)
- Core Web Vitals monitoring and performance standards

### 👥 **Team Processes** (`team-processes.md`)
- Full-stack role definitions for Next.js 15 & Supabase
- Development workflows with Simplicity First enforcement
- Code review processes focusing on client/server separation
- Task management for Server Components and RLS policies

### 🔒 **Security Standards** (`security-standards.md`)
- Supabase Row Level Security (RLS) implementation
- Next.js 15 client/server code separation
- Authentication with Supabase Auth and secure Edge Functions
- Environment variable protection and service key management

### ⚡ **Performance Optimization** (`performance-optimization.md`)
- Next.js 15 Server Component optimization and bundle splitting
- Mobile-first performance targets (320px+ viewports)
- Supabase query optimization and Edge Function performance
- Core Web Vitals monitoring with shadcn/ui components

### 🚀 **Deployment & DevOps** (`deployment-devops.md`)
- Next.js 15 Docker configuration and Kubernetes deployment
- Supabase CI/CD integration with automated migrations
- RLS policy testing and Edge Function deployment
- Mobile performance monitoring and Core Web Vitals tracking

## 🎯 Universal Principles

1. **Mobile-First Design**: All implementations start at 320px width
2. **Accessibility**: WCAG 2.1 AA compliance is mandatory
3. **Performance**: Core Web Vitals and performance budgets
4. **Type Safety**: Strict typing with comprehensive coverage
5. **Testing**: Minimum 80% code coverage with E2E validation
6. **Security**: Defense in depth with secure defaults
7. **Scalability**: Architecture ready for rapid expansion
8. **Documentation**: Self-documenting code with clear README files

## 🚀 Quick Start

1. Copy relevant rule files to your new project
2. Customize project-specific configurations
3. Set up automated quality gates
4. Configure CI/CD pipelines
5. Establish team workflows

## 📋 Universal Compliance Checklist

Before any code merge:
- [ ] All tests pass (unit + integration + E2E)
- [ ] Linting rules satisfied
- [ ] Type checking successful
- [ ] Accessibility standards met
- [ ] Performance targets achieved
- [ ] Security protocols followed
- [ ] Documentation updated
- [ ] Code review completed

## 📋 Standards Reference Matrix

| Standard Category | Authoritative Source | Cross-References |
|-------------------|---------------------|------------------|
| **Performance Targets** | `performance-optimization.md` | Referenced in `quality-assurance.md` |
| **Test Coverage Requirements** | `quality-assurance.md` | Referenced in `core-standards.md` |
| **Security Standards** | `security-standards.md` | Examples in `quality-assurance.md` |
| **Naming Conventions** | `core-standards.md` | Applied across all files |
| **Architecture Patterns** | `architecture-guidelines.md` | Implementation in other files |
| **Deployment Standards** | `deployment-devops.md` | CI/CD examples throughout |
| **Team Processes** | `team-processes.md` | Workflow references in other files |

> **Important**: When standards appear in multiple files, always refer to the authoritative source for the complete specification. Cross-references provide context-specific examples or summaries.

## ✅ Consistency Validation

When modifying these rules, ensure consistency by:

1. **Check Cross-References**: Update all files that reference modified standards
2. **Validate Metrics**: Ensure numeric targets use consistent operators (≤, ≥, <, >)
3. **Align Examples**: Update code examples to match security and performance requirements
4. **Review Dependencies**: Check that changes don't conflict with other standards

### Validation Checklist
- [ ] Performance targets consistent across files
- [ ] Security examples meet defined requirements
- [ ] Coverage thresholds align with testing strategy
- [ ] Cross-references updated when standards change
- [ ] No conflicting numeric values or operators

## 🔧 Customization Guide

These rules are designed to be:
- **Adaptable**: Modify for specific project needs
- **Extensible**: Add project-specific rules as needed
- **Scalable**: Support projects of any size
- **Technology-Agnostic**: Core principles apply regardless of stack

## 📝 Changelog

### Version 2.0.0 - January 2025
- 🚀 **Next.js 15 Integration**: Complete migration to Next.js 15 with App Router and Server Components
- 🗄️ **Supabase Backend**: Comprehensive Supabase integration patterns and RLS policies
- 🎨 **shadcn/ui Standards**: Component library standards and Tailwind CSS v4.1
- 📱 **Mobile-First Design**: Responsive design starting at 320px viewport
- 🎯 **Simplicity First**: Implementation hierarchy from vanilla JS to Next.js 15
- 🧪 **Server Component Testing**: Testing strategies for Server Components and Server Actions
- 🔐 **Supabase Auth**: Authentication patterns and Edge Functions integration
- 🚀 **Updated CI/CD**: Deployment pipelines for Next.js 15 and Supabase
- 👥 **Full-Stack Roles**: Team processes for modern full-stack development

### Version 1.1.0 - January 2025
- ✅ **Consistency Improvements**: Standardized performance targets across all files
- 📋 **Reference Matrix**: Added authoritative source mapping for all standards
- 🔗 **Cross-References**: Established clear links between related standards
- ✅ **Validation Framework**: Added consistency validation checklist
- 🎯 **Metric Alignment**: Unified operators and numeric formats throughout

### Version 1.0.0 - January 2025
- 🚀 **Initial Release**: Complete rule set with 7 comprehensive documents
- 📚 **Universal Standards**: Technology-agnostic development guidelines
- 🏗️ **Architecture Patterns**: Scalable design principles and examples
- 🔒 **Security Framework**: Comprehensive security standards and practices
- ⚡ **Performance Standards**: Core Web Vitals and optimization guidelines
- 🧪 **Quality Assurance**: Testing pyramid and coverage requirements
- 👥 **Team Processes**: Collaboration workflows and role definitions
- 🚀 **DevOps Standards**: CI/CD, deployment, and monitoring practices

---

*Version: 2.0.0*
*Last Updated: January 2025*