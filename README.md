# NestJS Authentication Boilerplate

A comprehensive, production-ready authentication system built with NestJS, PostgreSQL, TypeORM, and JWT. Features include user registration, email verification (OTP & token), password management, and refresh token support.

## 🚀 Features

- ✅ **User Registration** with email verification
- ✅ **Email Verification** supporting both OTP (6-digit code) and token-based verification
- ✅ **Login/Logout** with JWT access and refresh tokens
- ✅ **Token Refresh** mechanism for seamless authentication
- ✅ **Password Management** (forgot password, reset password, change password)
- ✅ **User Profile** management (get and update)
- ✅ **Email Notifications** for all authentication events
- ✅ **Rate Limiting** for security
- ✅ **Clean Architecture** following NestJS best practices
- ✅ **TypeORM** with PostgreSQL
- ✅ **Validation** using class-validator
- ✅ **Password Hashing** with bcrypt

## 📋 Prerequisites

- Node.js (v18 or higher)
- PostgreSQL (v14 or higher)
- pnpm (recommended) or npm

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd nest-auth-boilerplate
   ```

2. **Install dependencies**
   ```bash
   pnpm install
   ```

3. **Set up environment variables**
   
   Copy the `.env.example` file to `.env`:
   ```bash
   cp .env.example .env
   ```

4. **Create PostgreSQL database**
   ```bash
   createdb nest-auth
   ```
   
   Or using psql:
   ```sql
   CREATE DATABASE "nest-auth";
   ```

5. **Start the application**
   ```bash
   # Development mode with hot reload
   pnpm run start:dev

   # Production mode
   pnpm run build
   pnpm run start:prod
   ```

The API will be available at `http://localhost:3000/api`

## 📚 API Endpoints

All endpoints are prefixed with `/api/auth`

### Public Endpoints (No Authentication Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Login with email and password |
| POST | `/auth/refresh` | Refresh access token using refresh token |
| POST | `/auth/verify-email` | Verify email with OTP or token |
| POST | `/auth/resend-verification` | Resend verification email |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Reset password with OTP or token |

### Protected Endpoints (Authentication Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/logout` | Logout and revoke refresh tokens |
| POST | `/auth/change-password` | Change password (requires old password) |
| GET | `/auth/me` | Get current user profile |
| PUT | `/auth/me` | Update user profile |

## 📝 API Usage Examples

### 1. Register a New User

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

**Response:**
```json
{
  "message": "Registration successful. Please check your email to verify your account.",
  "userId": "uuid-here"
}
```

### 2. Verify Email

**Using OTP:**
```bash
curl -X POST http://localhost:3000/api/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "otp": "123456"
  }'
```

**Using Token:**
```bash
curl -X POST http://localhost:3000/api/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "verification-token-from-email"
  }'
```

### 3. Login

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

**Response:**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "isEmailVerified": true
  },
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 4. Get User Profile

```bash
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 5. Refresh Access Token

```bash
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### 6. Forgot Password

```bash
curl -X POST http://localhost:3000/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### 7. Reset Password

**Using OTP:**
```bash
curl -X POST http://localhost:3000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "otp": "123456",
    "newPassword": "NewSecurePass123!"
  }'
```

## 🔧 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment (development/production) | development |
| `PORT` | Application port | 3000 |
| `DB_HOST` | PostgreSQL host | localhost |
| `DB_PORT` | PostgreSQL port | 5432 |
| `DB_USERNAME` | Database username | postgres |
| `DB_PASSWORD` | Database password | Password@2 |
| `DB_DATABASE` | Database name | nest-auth |
| `JWT_ACCESS_SECRET` | Secret for access tokens | (change in production) |
| `JWT_ACCESS_EXPIRATION` | Access token expiration | 15m |
| `JWT_REFRESH_SECRET` | Secret for refresh tokens | (change in production) |
| `JWT_REFRESH_EXPIRATION` | Refresh token expiration | 7d |
| `MAIL_HOST` | SMTP host | sandbox.smtp.mailtrap.io |
| `MAIL_PORT` | SMTP port | 2525 |
| `MAIL_USER` | SMTP username | - |
| `MAIL_PASSWORD` | SMTP password | - |
| `MAIL_FROM` | From email address | noreply@nestauth.com |
| `MAIL_FROM_NAME` | From name | NestAuth |
| `OTP_EXPIRATION_MINUTES` | OTP expiration time | 10 |
| `RESET_TOKEN_EXPIRATION_HOURS` | Password reset token expiration | 1 |

## 🏗️ Project Structure

```
src/
├── auth/
│   ├── decorators/          # Custom decorators (CurrentUser, Public)
│   ├── dto/                 # Data Transfer Objects
│   ├── guards/              # Auth guards (JWT, RefreshToken)
│   ├── strategies/          # Passport strategies
│   ├── auth.controller.ts   # Auth endpoints
│   ├── auth.module.ts       # Auth module
│   └── auth.service.ts      # Auth business logic
├── config/
│   ├── database.config.ts   # TypeORM configuration
│   └── jwt.config.ts        # JWT configuration
├── entities/
│   ├── user.entity.ts
│   ├── refresh-token.entity.ts
│   ├── email-verification.entity.ts
│   └── password-reset.entity.ts
├── services/
│   └── email.service.ts     # Email service with templates
├── utils/
│   ├── hash.util.ts         # Password/token hashing
│   └── otp.util.ts          # OTP generation
├── app.module.ts
└── main.ts
```

## 🔐 Security Features

- **Password Hashing**: Bcrypt with 10 salt rounds
- **JWT Tokens**: Separate access and refresh tokens
- **Token Storage**: Refresh tokens are hashed and stored in database
- **Token Revocation**: Logout revokes all refresh tokens
- **Rate Limiting**: 10 requests per minute per IP
- **Email Verification**: Required before login
- **OTP Expiration**: 10 minutes for email verification
- **Reset Token Expiration**: 1 hour for password reset
- **Input Validation**: Class-validator for all DTOs
- **SQL Injection Protection**: TypeORM parameterized queries

## 📧 Email Templates

The boilerplate includes beautiful HTML email templates for:
- Email verification (with OTP and link)
- Password reset (with OTP and link)
- Welcome email (after verification)
- Password changed notification

## 🧪 Testing

```bash
# Unit tests
pnpm run test

# E2E tests
pnpm run test:e2e

# Test coverage
pnpm run test:cov
```

## 🧪 Testing

This project includes comprehensive unit tests for all authentication endpoints.

### Running Tests

```bash
# Run all tests
pnpm run test

# Run tests with coverage report
pnpm run test:cov

# Run tests in watch mode
pnpm run test:watch
```

### Test Coverage

- **56 tests** across 7 test suites
- **~78% code coverage**
- All 11 authentication endpoints tested
- Positive and negative test cases
- Guards, strategies, and utilities tested

See [TESTING.md](TESTING.md) for detailed test documentation.

## 🚀 Production Deployment

1. **Update environment variables**
   - Change JWT secrets to strong random strings
   - Update database credentials
   - Configure production SMTP settings

2. **Build the application**
   ```bash
   pnpm run build
   ```

3. **Run migrations** (if using migrations instead of synchronize)
   ```bash
   pnpm run migration:run
   ```

4. **Start the application**
   ```bash
   pnpm run start:prod
   ```

## 📄 License

This project is licensed under the UNLICENSED License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For issues and questions, please open an issue on GitHub.

---

**Built with ❤️ using NestJS**
