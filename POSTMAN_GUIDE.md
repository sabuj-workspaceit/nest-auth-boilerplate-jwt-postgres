# Postman Collection Guide

## Quick Start

1. **Import Collection**
   - Open Postman
   - Click "Import" button
   - Select `postman_collection.json`
   - Collection will appear in your workspace

2. **Configure Base URL** (Optional)
   - The collection uses `http://localhost:3000/api` by default
   - To change: Edit collection → Variables → Update `baseUrl`

3. **Start Testing**
   - Follow the numbered sequence in "Authentication" folder
   - Tokens are automatically saved after login

## Testing Flow

### Complete Authentication Flow

1. **Register User** → Creates new user, sends verification email
2. **Verify Email (OTP)** → Use OTP from Mailtrap email
3. **Login** → Get access & refresh tokens (auto-saved)
4. **Get Profile** → Test authenticated endpoint
5. **Update Profile** → Modify user information
6. **Logout** → Revoke tokens

### Password Reset Flow

1. **Forgot Password** → Request reset email
2. **Reset Password (OTP)** → Use OTP from email
3. **Login** → Login with new password

### Password Change Flow

1. **Login** → Get authenticated
2. **Change Password** → Change password while logged in
3. **Login** → Login with new password

## Environment Variables

The collection automatically manages these variables:

| Variable | Description | Auto-Updated |
|----------|-------------|--------------|
| `baseUrl` | API base URL | Manual |
| `accessToken` | JWT access token | After login/refresh |
| `refreshToken` | JWT refresh token | After login/refresh |
| `userId` | User ID | After registration |
| `verificationOtp` | Email verification OTP | Manual |
| `verificationToken` | Email verification token | Manual |

## Endpoints Overview

### Authentication (6 endpoints)

1. **POST /auth/register**
   - Register new user
   - Body: `email`, `password`, `firstName`, `lastName`
   - Response: `userId`, `message`

2. **POST /auth/verify-email**
   - Verify email with OTP or token
   - Body: `otp` OR `token`
   - Response: `message`

3. **POST /auth/resend-verification**
   - Resend verification email
   - Body: `email`
   - Response: `message`

4. **POST /auth/login**
   - Login user
   - Body: `email`, `password`
   - Response: `user`, `accessToken`, `refreshToken`

5. **POST /auth/refresh**
   - Refresh access token
   - Body: `refreshToken`
   - Response: `accessToken`, `refreshToken`

6. **POST /auth/logout** 🔒
   - Logout user
   - Body: `refreshToken`
   - Headers: `Authorization: Bearer {accessToken}`
   - Response: `message`

### Password Management (4 endpoints)

1. **POST /auth/forgot-password**
   - Request password reset
   - Body: `email`
   - Response: `message`

2. **POST /auth/reset-password**
   - Reset password with OTP or token
   - Body: `otp` OR `token`, `newPassword`
   - Response: `message`

3. **POST /auth/change-password** 🔒
   - Change password (authenticated)
   - Body: `oldPassword`, `newPassword`
   - Headers: `Authorization: Bearer {accessToken}`
   - Response: `message`

### User Profile (2 endpoints)

1. **GET /auth/me** 🔒
   - Get current user profile
   - Headers: `Authorization: Bearer {accessToken}`
   - Response: User object

2. **PUT /auth/me** 🔒
   - Update user profile
   - Body: `firstName`, `lastName`
   - Headers: `Authorization: Bearer {accessToken}`
   - Response: Updated user object

🔒 = Requires authentication (Bearer token)

## Checking Emails

Since we're using Mailtrap for development:

1. Go to [Mailtrap](https://mailtrap.io)
2. Login with your credentials
3. Navigate to your inbox
4. Check emails for:
   - Verification OTP (6-digit code)
   - Verification link (with token)
   - Password reset OTP
   - Password reset link
   - Welcome email
   - Password changed notification

## Tips

### Auto-Save Tokens
The collection includes test scripts that automatically save tokens after login and refresh. You don't need to manually copy/paste them.

### Testing Protected Endpoints
Protected endpoints automatically use the saved `accessToken`. Just make sure you're logged in first.

### Token Expiration
- Access token expires in 15 minutes
- If you get 401 Unauthorized, use "Refresh Token" endpoint
- Refresh token expires in 7 days

### Email Verification
- OTPs expire in 10 minutes
- Tokens expire in 10 minutes
- Use "Resend Verification" if expired

### Password Reset
- Reset OTPs expire in 1 hour
- Reset tokens expire in 1 hour
- Each reset invalidates previous reset requests

## Common Issues

### 401 Unauthorized
- Access token expired → Use refresh token endpoint
- Not logged in → Login first
- Invalid token → Login again

### 400 Bad Request
- Check request body format
- Ensure all required fields are provided
- Verify data types (string, number, etc.)

### Email Not Received
- Check Mailtrap inbox
- Verify email address in request
- Use "Resend Verification" endpoint

### OTP/Token Invalid
- OTP/Token may have expired (10 min for verification, 1 hour for reset)
- Request new OTP/Token
- Ensure you're using the latest OTP/Token

## Example Test Sequence

```
1. Register User
   ↓
2. Check Mailtrap for OTP
   ↓
3. Verify Email (use OTP from email)
   ↓
4. Login (tokens auto-saved)
   ↓
5. Get Profile (uses saved token)
   ↓
6. Update Profile
   ↓
7. Change Password
   ↓
8. Logout
   ↓
9. Login (with new password)
```

## Advanced Usage

### Testing Token Refresh
1. Login
2. Wait 15+ minutes (or manually expire token)
3. Try "Get Profile" → Should fail with 401
4. Use "Refresh Token"
5. Try "Get Profile" again → Should work

### Testing Multiple Users
1. Change email in "Register User"
2. Complete registration flow
3. Login with new user
4. Test endpoints with different users

### Testing Error Cases
- Try login with wrong password
- Try verify email with invalid OTP
- Try access protected endpoint without token
- Try reset password with expired OTP

---

**Happy Testing! 🚀**
