import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RefreshTokenGuard } from './guards/refresh-token.guard';
import { UnauthorizedException } from '@nestjs/common';

describe('AuthController', () => {
    let controller: AuthController;
    let authService: AuthService;

    const mockUser = {
        id: 'user-id-123',
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        isEmailVerified: true,
        isActive: true,
    };

    const mockAuthService = {
        register: jest.fn(),
        login: jest.fn(),
        refreshToken: jest.fn(),
        logout: jest.fn(),
        verifyEmail: jest.fn(),
        resendVerification: jest.fn(),
        forgotPassword: jest.fn(),
        resetPassword: jest.fn(),
        changePassword: jest.fn(),
        getProfile: jest.fn(),
        updateProfile: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [AuthController],
            providers: [
                {
                    provide: AuthService,
                    useValue: mockAuthService,
                },
            ],
        })
            .overrideGuard(JwtAuthGuard)
            .useValue({ canActivate: jest.fn(() => true) })
            .overrideGuard(RefreshTokenGuard)
            .useValue({ canActivate: jest.fn(() => true) })
            .compile();

        controller = module.get<AuthController>(AuthController);
        authService = module.get<AuthService>(AuthService);

        jest.clearAllMocks();
    });

    describe('register', () => {
        it('should register a new user', async () => {
            const registerDto = {
                email: 'newuser@example.com',
                password: 'Password123!',
                firstName: 'Jane',
                lastName: 'Smith',
            };

            const expectedResult = {
                message: 'Registration successful. Please check your email to verify your account.',
                userId: 'new-user-id',
            };

            mockAuthService.register.mockResolvedValue(expectedResult);

            const result = await controller.register(registerDto);

            expect(result).toEqual(expectedResult);
            expect(authService.register).toHaveBeenCalledWith(registerDto);
        });
    });

    describe('login', () => {
        it('should login a user and return tokens', async () => {
            const loginDto = {
                email: 'test@example.com',
                password: 'Password123!',
            };

            const expectedResult = {
                user: mockUser,
                accessToken: 'access-token',
                refreshToken: 'refresh-token',
            };

            mockAuthService.login.mockResolvedValue(expectedResult);

            const result = await controller.login(loginDto);

            expect(result).toEqual(expectedResult);
            expect(authService.login).toHaveBeenCalledWith(loginDto);
        });
    });

    describe('refresh', () => {
        it('should refresh access token', async () => {
            const refreshTokenDto = {
                refreshToken: 'valid-refresh-token',
            };

            const expectedResult = {
                accessToken: 'new-access-token',
                refreshToken: 'new-refresh-token',
            };

            mockAuthService.refreshToken.mockResolvedValue(expectedResult);

            const result = await controller.refresh(refreshTokenDto);

            expect(result).toEqual(expectedResult);
            expect(authService.refreshToken).toHaveBeenCalledWith(
                refreshTokenDto.refreshToken,
            );
        });
    });

    describe('logout', () => {
        it('should logout user', async () => {
            const refreshTokenDto = {
                refreshToken: 'refresh-token',
            };

            const expectedResult = {
                message: 'Logged out successfully',
            };

            mockAuthService.logout.mockResolvedValue(expectedResult);

            const result = await controller.logout(mockUser as any, refreshTokenDto);

            expect(result).toEqual(expectedResult);
            expect(authService.logout).toHaveBeenCalledWith(
                mockUser.id,
                refreshTokenDto.refreshToken,
            );
        });
    });

    describe('verifyEmail', () => {
        it('should verify email with OTP', async () => {
            const verifyDto = {
                otp: '123456',
            };

            const expectedResult = {
                message: 'Email verified successfully',
            };

            mockAuthService.verifyEmail.mockResolvedValue(expectedResult);

            const result = await controller.verifyEmail(verifyDto);

            expect(result).toEqual(expectedResult);
            expect(authService.verifyEmail).toHaveBeenCalledWith(verifyDto);
        });

        it('should verify email with token', async () => {
            const verifyDto = {
                token: 'verification-token',
            };

            const expectedResult = {
                message: 'Email verified successfully',
            };

            mockAuthService.verifyEmail.mockResolvedValue(expectedResult);

            const result = await controller.verifyEmail(verifyDto);

            expect(result).toEqual(expectedResult);
            expect(authService.verifyEmail).toHaveBeenCalledWith(verifyDto);
        });
    });

    describe('resendVerification', () => {
        it('should resend verification email', async () => {
            const resendDto = {
                email: 'test@example.com',
            };

            const expectedResult = {
                message: 'Verification email sent successfully',
            };

            mockAuthService.resendVerification.mockResolvedValue(expectedResult);

            const result = await controller.resendVerification(resendDto);

            expect(result).toEqual(expectedResult);
            expect(authService.resendVerification).toHaveBeenCalledWith(
                resendDto.email,
            );
        });
    });

    describe('forgotPassword', () => {
        it('should send password reset email', async () => {
            const forgotPasswordDto = {
                email: 'test@example.com',
            };

            const expectedResult = {
                message: 'If the email exists, a password reset link has been sent',
            };

            mockAuthService.forgotPassword.mockResolvedValue(expectedResult);

            const result = await controller.forgotPassword(forgotPasswordDto);

            expect(result).toEqual(expectedResult);
            expect(authService.forgotPassword).toHaveBeenCalledWith(
                forgotPasswordDto.email,
            );
        });
    });

    describe('resetPassword', () => {
        it('should reset password with OTP', async () => {
            const resetDto = {
                otp: '123456',
                newPassword: 'NewPassword123!',
            };

            const expectedResult = {
                message: 'Password reset successfully',
            };

            mockAuthService.resetPassword.mockResolvedValue(expectedResult);

            const result = await controller.resetPassword(resetDto);

            expect(result).toEqual(expectedResult);
            expect(authService.resetPassword).toHaveBeenCalledWith(resetDto);
        });

        it('should reset password with token', async () => {
            const resetDto = {
                token: 'reset-token',
                newPassword: 'NewPassword123!',
            };

            const expectedResult = {
                message: 'Password reset successfully',
            };

            mockAuthService.resetPassword.mockResolvedValue(expectedResult);

            const result = await controller.resetPassword(resetDto);

            expect(result).toEqual(expectedResult);
            expect(authService.resetPassword).toHaveBeenCalledWith(resetDto);
        });
    });

    describe('changePassword', () => {
        it('should change password for authenticated user', async () => {
            const changePasswordDto = {
                oldPassword: 'OldPassword123!',
                newPassword: 'NewPassword123!',
            };

            const expectedResult = {
                message: 'Password changed successfully',
            };

            mockAuthService.changePassword.mockResolvedValue(expectedResult);

            const result = await controller.changePassword(
                mockUser as any,
                changePasswordDto,
            );

            expect(result).toEqual(expectedResult);
            expect(authService.changePassword).toHaveBeenCalledWith(
                mockUser.id,
                changePasswordDto,
            );
        });
    });

    describe('getProfile', () => {
        it('should get user profile', async () => {
            const expectedResult = {
                id: mockUser.id,
                email: mockUser.email,
                firstName: mockUser.firstName,
                lastName: mockUser.lastName,
                isEmailVerified: mockUser.isEmailVerified,
                isActive: mockUser.isActive,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            mockAuthService.getProfile.mockResolvedValue(expectedResult);

            const result = await controller.getProfile(mockUser as any);

            expect(result).toEqual(expectedResult);
            expect(authService.getProfile).toHaveBeenCalledWith(mockUser.id);
        });
    });

    describe('updateProfile', () => {
        it('should update user profile', async () => {
            const updateDto = {
                firstName: 'UpdatedFirst',
                lastName: 'UpdatedLast',
            };

            const expectedResult = {
                id: mockUser.id,
                email: mockUser.email,
                firstName: updateDto.firstName,
                lastName: updateDto.lastName,
                isEmailVerified: mockUser.isEmailVerified,
                isActive: mockUser.isActive,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            mockAuthService.updateProfile.mockResolvedValue(expectedResult);

            const result = await controller.updateProfile(
                mockUser as any,
                updateDto,
            );

            expect(result).toEqual(expectedResult);
            expect(authService.updateProfile).toHaveBeenCalledWith(
                mockUser.id,
                updateDto,
            );
        });
    });
});
