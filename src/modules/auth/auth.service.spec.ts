
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from '../../entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { EmailVerification } from './entities/email-verification.entity';
import { PasswordReset } from './entities/password-reset.entity';
import { EmailService } from '../../services/email.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import {
    ConflictException,
    UnauthorizedException,
    NotFoundException,
    BadRequestException,
} from '@nestjs/common';
import * as hashUtil from '../../utils/hash.util';
import * as otpUtil from '../../utils/otp.util';

describe('AuthService', () => {
    let service: AuthService;
    let userRepository: any;
    let refreshTokenRepository: any;
    let emailVerificationRepository: any;
    let passwordResetRepository: any;
    let jwtService: JwtService;
    let configService: ConfigService;
    let emailService: EmailService;

    const mockUser = {
        id: 'user-id-123',
        email: 'test@example.com',
        password: 'hashedPassword',
        firstName: 'John',
        lastName: 'Doe',
        isEmailVerified: true,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    const mockUserRepository = {
        findOne: jest.fn(),
        create: jest.fn(),
        save: jest.fn(),
    };

    const mockRefreshTokenRepository = {
        findOne: jest.fn(),
        create: jest.fn(),
        save: jest.fn(),
        update: jest.fn(),
    };

    const mockEmailVerificationRepository = {
        find: jest.fn(),
        create: jest.fn(),
        save: jest.fn(),
        update: jest.fn(),
    };

    const mockPasswordResetRepository = {
        find: jest.fn(),
        create: jest.fn(),
        save: jest.fn(),
        update: jest.fn(),
    };

    const mockJwtService = {
        sign: jest.fn(),
        verify: jest.fn(),
    };

    const mockConfigService = {
        get: jest.fn(),
    };

    const mockEmailService = {
        sendVerificationEmail: jest.fn(),
        sendPasswordResetEmail: jest.fn(),
        sendWelcomeEmail: jest.fn(),
        sendPasswordChangedEmail: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                {
                    provide: getRepositoryToken(User),
                    useValue: mockUserRepository,
                },
                {
                    provide: getRepositoryToken(RefreshToken),
                    useValue: mockRefreshTokenRepository,
                },
                {
                    provide: getRepositoryToken(EmailVerification),
                    useValue: mockEmailVerificationRepository,
                },
                {
                    provide: getRepositoryToken(PasswordReset),
                    useValue: mockPasswordResetRepository,
                },
                {
                    provide: JwtService,
                    useValue: mockJwtService,
                },
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                {
                    provide: EmailService,
                    useValue: mockEmailService,
                },
            ],
        }).compile();

        service = module.get<AuthService>(AuthService);
        userRepository = module.get(getRepositoryToken(User));
        refreshTokenRepository = module.get(getRepositoryToken(RefreshToken));
        emailVerificationRepository = module.get(
            getRepositoryToken(EmailVerification),
        );
        passwordResetRepository = module.get(getRepositoryToken(PasswordReset));
        jwtService = module.get<JwtService>(JwtService);
        configService = module.get<ConfigService>(ConfigService);
        emailService = module.get<EmailService>(EmailService);

        // Reset all mocks before each test
        jest.clearAllMocks();
    });

    describe('register', () => {
        const registerDto = {
            email: 'newuser@example.com',
            password: 'Password123!',
            firstName: 'Jane',
            lastName: 'Smith',
        };

        it('should successfully register a new user', async () => {
            mockUserRepository.findOne.mockResolvedValue(null);
            mockUserRepository.create.mockReturnValue(mockUser);
            mockUserRepository.save.mockResolvedValue(mockUser);
            mockEmailVerificationRepository.create.mockReturnValue({});
            mockEmailVerificationRepository.save.mockResolvedValue({});
            mockConfigService.get.mockReturnValue(10);

            jest.spyOn(hashUtil, 'hashPassword').mockResolvedValue('hashedPassword');
            jest.spyOn(hashUtil, 'hashToken').mockResolvedValue('hashedToken');
            jest.spyOn(otpUtil, 'generateOTP').mockReturnValue('123456');

            const result = await service.register(registerDto);

            expect(result).toHaveProperty('message');
            expect(result).toHaveProperty('userId');
            expect(mockUserRepository.findOne).toHaveBeenCalledWith({
                where: { email: registerDto.email },
            });
            expect(mockUserRepository.create).toHaveBeenCalled();
            expect(mockUserRepository.save).toHaveBeenCalled();
            expect(mockEmailService.sendVerificationEmail).toHaveBeenCalled();
        });

        it('should throw ConflictException if user already exists', async () => {
            mockUserRepository.findOne.mockResolvedValue(mockUser);

            await expect(service.register(registerDto)).rejects.toThrow(
                ConflictException,
            );
            expect(mockUserRepository.create).not.toHaveBeenCalled();
        });
    });

    describe('login', () => {
        const loginDto = {
            email: 'test@example.com',
            password: 'Password123!',
        };

        it('should successfully login a user', async () => {
            mockUserRepository.findOne.mockResolvedValue(mockUser);
            mockJwtService.sign.mockReturnValue('mock-token');
            mockRefreshTokenRepository.create.mockReturnValue({});
            mockRefreshTokenRepository.save.mockResolvedValue({});
            mockConfigService.get.mockReturnValue('secret');

            jest.spyOn(hashUtil, 'comparePassword').mockResolvedValue(true);
            jest.spyOn(hashUtil, 'hashToken').mockResolvedValue('hashedToken');

            const result = await service.login(loginDto);

            expect(result).toHaveProperty('user');
            expect(result).toHaveProperty('accessToken');
            expect(result).toHaveProperty('refreshToken');
            expect(mockUserRepository.findOne).toHaveBeenCalledWith({
                where: { email: loginDto.email },
            });
        });

        it('should throw UnauthorizedException if user not found', async () => {
            mockUserRepository.findOne.mockResolvedValue(null);

            await expect(service.login(loginDto)).rejects.toThrow(
                UnauthorizedException,
            );
        });

        it('should throw UnauthorizedException if password is invalid', async () => {
            mockUserRepository.findOne.mockResolvedValue(mockUser);
            jest.spyOn(hashUtil, 'comparePassword').mockResolvedValue(false);

            await expect(service.login(loginDto)).rejects.toThrow(
                UnauthorizedException,
            );
        });

        it('should throw UnauthorizedException if user is not active', async () => {
            mockUserRepository.findOne.mockResolvedValue({
                ...mockUser,
                isActive: false,
            });
            jest.spyOn(hashUtil, 'comparePassword').mockResolvedValue(true);

            await expect(service.login(loginDto)).rejects.toThrow(
                UnauthorizedException,
            );
        });

        it('should throw UnauthorizedException if email is not verified', async () => {
            mockUserRepository.findOne.mockResolvedValue({
                ...mockUser,
                isEmailVerified: false,
            });
            jest.spyOn(hashUtil, 'comparePassword').mockResolvedValue(true);

            await expect(service.login(loginDto)).rejects.toThrow(
                UnauthorizedException,
            );
        });
    });

    describe('refreshToken', () => {
        const refreshToken = 'valid-refresh-token';

        it('should successfully refresh tokens', async () => {
            const mockStoredToken = {
                id: 'token-id',
                token: 'hashedToken',
                userId: mockUser.id,
                expiresAt: new Date(Date.now() + 86400000),
                isRevoked: false,
            };

            mockJwtService.verify.mockReturnValue({ sub: mockUser.id });
            mockRefreshTokenRepository.findOne.mockResolvedValue(mockStoredToken);
            mockUserRepository.findOne.mockResolvedValue(mockUser);
            mockJwtService.sign.mockReturnValue('new-token');
            mockRefreshTokenRepository.save.mockResolvedValue({});
            mockRefreshTokenRepository.create.mockReturnValue({});
            mockConfigService.get.mockReturnValue('secret');

            jest.spyOn(hashUtil, 'compareToken').mockResolvedValue(true);
            jest.spyOn(hashUtil, 'hashToken').mockResolvedValue('hashedToken');

            const result = await service.refreshToken(refreshToken);

            expect(result).toHaveProperty('accessToken');
            expect(result).toHaveProperty('refreshToken');
            expect(mockJwtService.verify).toHaveBeenCalled();
        });

        it('should throw UnauthorizedException if token is invalid', async () => {
            mockJwtService.verify.mockImplementation(() => {
                throw new Error('Invalid token');
            });

            await expect(service.refreshToken(refreshToken)).rejects.toThrow(
                UnauthorizedException,
            );
        });
    });

    describe('logout', () => {
        it('should successfully logout user', async () => {
            mockRefreshTokenRepository.update.mockResolvedValue({});

            const result = await service.logout(mockUser.id, 'refresh-token');

            expect(result).toHaveProperty('message');
            expect(mockRefreshTokenRepository.update).toHaveBeenCalledWith(
                { userId: mockUser.id, isRevoked: false },
                { isRevoked: true },
            );
        });
    });

    describe('verifyEmail', () => {
        it('should successfully verify email with OTP', async () => {
            const verifyDto = { otp: '123456' };
            const mockVerification = {
                id: 'verification-id',
                userId: mockUser.id,
                otp: 'hashedOtp',
                expiresAt: new Date(Date.now() + 600000),
                isUsed: false,
                user: mockUser,
            };

            mockEmailVerificationRepository.find.mockResolvedValue([
                mockVerification,
            ]);
            mockEmailVerificationRepository.save.mockResolvedValue({});
            mockUserRepository.save.mockResolvedValue(mockUser);

            jest.spyOn(hashUtil, 'compareToken').mockResolvedValue(true);

            const result = await service.verifyEmail(verifyDto);

            expect(result).toHaveProperty('message');
            expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalled();
        });

        it('should successfully verify email with token', async () => {
            const verifyDto = { token: 'verification-token' };
            const mockVerification = {
                id: 'verification-id',
                userId: mockUser.id,
                token: 'hashedToken',
                expiresAt: new Date(Date.now() + 600000),
                isUsed: false,
                user: mockUser,
            };

            mockEmailVerificationRepository.find.mockResolvedValue([
                mockVerification,
            ]);
            mockEmailVerificationRepository.save.mockResolvedValue({});
            mockUserRepository.save.mockResolvedValue(mockUser);

            jest.spyOn(hashUtil, 'compareToken').mockResolvedValue(true);

            const result = await service.verifyEmail(verifyDto);

            expect(result).toHaveProperty('message');
            expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalled();
        });

        it('should throw BadRequestException if neither OTP nor token provided', async () => {
            await expect(service.verifyEmail({})).rejects.toThrow(
                BadRequestException,
            );
        });

        it('should throw BadRequestException if verification code is invalid', async () => {
            const verifyDto = { otp: '123456' };
            mockEmailVerificationRepository.find.mockResolvedValue([]);

            await expect(service.verifyEmail(verifyDto)).rejects.toThrow(
                BadRequestException,
            );
        });
    });

    describe('resendVerification', () => {
        it('should successfully resend verification email', async () => {
            const unverifiedUser = { ...mockUser, isEmailVerified: false };
            mockUserRepository.findOne.mockResolvedValue(unverifiedUser);
            mockEmailVerificationRepository.update.mockResolvedValue({});
            mockEmailVerificationRepository.create.mockReturnValue({});
            mockEmailVerificationRepository.save.mockResolvedValue({});
            mockConfigService.get.mockReturnValue(10);

            jest.spyOn(hashUtil, 'hashToken').mockResolvedValue('hashedToken');
            jest.spyOn(otpUtil, 'generateOTP').mockReturnValue('123456');

            const result = await service.resendVerification(mockUser.email);

            expect(result).toHaveProperty('message');
            expect(mockEmailService.sendVerificationEmail).toHaveBeenCalled();
        });

        it('should throw NotFoundException if user not found', async () => {
            mockUserRepository.findOne.mockResolvedValue(null);

            await expect(service.resendVerification('test@example.com')).rejects.toThrow(
                NotFoundException,
            );
        });

        it('should throw BadRequestException if email already verified', async () => {
            mockUserRepository.findOne.mockResolvedValue(mockUser);

            await expect(service.resendVerification(mockUser.email)).rejects.toThrow(
                BadRequestException,
            );
        });
    });

    describe('forgotPassword', () => {
        it('should successfully send password reset email', async () => {
            mockUserRepository.findOne.mockResolvedValue(mockUser);
            mockPasswordResetRepository.update.mockResolvedValue({});
            mockPasswordResetRepository.create.mockReturnValue({});
            mockPasswordResetRepository.save.mockResolvedValue({});
            mockConfigService.get.mockReturnValue(1);

            jest.spyOn(hashUtil, 'hashToken').mockResolvedValue('hashedToken');
            jest.spyOn(otpUtil, 'generateOTP').mockReturnValue('123456');

            const result = await service.forgotPassword(mockUser.email);

            expect(result).toHaveProperty('message');
            expect(mockEmailService.sendPasswordResetEmail).toHaveBeenCalled();
        });

        it('should return generic message if user not found', async () => {
            mockUserRepository.findOne.mockResolvedValue(null);

            const result = await service.forgotPassword('nonexistent@example.com');

            expect(result).toHaveProperty('message');
            expect(mockEmailService.sendPasswordResetEmail).not.toHaveBeenCalled();
        });
    });

    describe('resetPassword', () => {
        const resetDto = {
            otp: '123456',
            newPassword: 'NewPassword123!',
        };

        it('should successfully reset password with OTP', async () => {
            const mockReset = {
                id: 'reset-id',
                userId: mockUser.id,
                otp: 'hashedOtp',
                expiresAt: new Date(Date.now() + 3600000),
                isUsed: false,
                user: mockUser,
            };

            mockPasswordResetRepository.find.mockResolvedValue([mockReset]);
            mockPasswordResetRepository.save.mockResolvedValue({});
            mockUserRepository.save.mockResolvedValue(mockUser);
            mockRefreshTokenRepository.update.mockResolvedValue({});

            jest.spyOn(hashUtil, 'compareToken').mockResolvedValue(true);
            jest.spyOn(hashUtil, 'hashPassword').mockResolvedValue('newHashedPassword');

            const result = await service.resetPassword(resetDto);

            expect(result).toHaveProperty('message');
            expect(mockEmailService.sendPasswordChangedEmail).toHaveBeenCalled();
        });

        it('should throw BadRequestException if neither OTP nor token provided', async () => {
            await expect(
                service.resetPassword({ newPassword: 'NewPassword123!' }),
            ).rejects.toThrow(BadRequestException);
        });

        it('should throw BadRequestException if reset code is invalid', async () => {
            mockPasswordResetRepository.find.mockResolvedValue([]);

            await expect(service.resetPassword(resetDto)).rejects.toThrow(
                BadRequestException,
            );
        });
    });

    describe('changePassword', () => {
        const changePasswordDto = {
            oldPassword: 'OldPassword123!',
            newPassword: 'NewPassword123!',
        };

        it('should successfully change password', async () => {
            mockUserRepository.findOne.mockResolvedValue(mockUser);
            mockUserRepository.save.mockResolvedValue(mockUser);
            mockRefreshTokenRepository.update.mockResolvedValue({});

            jest.spyOn(hashUtil, 'comparePassword').mockResolvedValue(true);
            jest.spyOn(hashUtil, 'hashPassword').mockResolvedValue('newHashedPassword');

            const result = await service.changePassword(mockUser.id, changePasswordDto);

            expect(result).toHaveProperty('message');
            expect(mockEmailService.sendPasswordChangedEmail).toHaveBeenCalled();
        });

        it('should throw NotFoundException if user not found', async () => {
            mockUserRepository.findOne.mockResolvedValue(null);

            await expect(
                service.changePassword('invalid-id', changePasswordDto),
            ).rejects.toThrow(NotFoundException);
        });

        it('should throw BadRequestException if old password is incorrect', async () => {
            mockUserRepository.findOne.mockResolvedValue(mockUser);
            jest.spyOn(hashUtil, 'comparePassword').mockResolvedValue(false);

            await expect(
                service.changePassword(mockUser.id, changePasswordDto),
            ).rejects.toThrow(BadRequestException);
        });
    });

    describe('getProfile', () => {
        it('should successfully get user profile', async () => {
            mockUserRepository.findOne.mockResolvedValue(mockUser);

            const result = await service.getProfile(mockUser.id);

            expect(result).toHaveProperty('id');
            expect(result).toHaveProperty('email');
            expect(result).toHaveProperty('firstName');
            expect(result).toHaveProperty('lastName');
            expect(result).not.toHaveProperty('password');
        });

        it('should throw NotFoundException if user not found', async () => {
            mockUserRepository.findOne.mockResolvedValue(null);

            await expect(service.getProfile('invalid-id')).rejects.toThrow(
                NotFoundException,
            );
        });
    });

    describe('updateProfile', () => {
        const updateDto = {
            firstName: 'UpdatedFirst',
            lastName: 'UpdatedLast',
        };

        it('should successfully update user profile', async () => {
            const updatedUser = { ...mockUser, ...updateDto };
            mockUserRepository.findOne.mockResolvedValue(mockUser);
            mockUserRepository.save.mockResolvedValue(updatedUser);

            const result = await service.updateProfile(mockUser.id, updateDto);

            expect(result.firstName).toBe(updateDto.firstName);
            expect(result.lastName).toBe(updateDto.lastName);
            expect(mockUserRepository.save).toHaveBeenCalled();
        });

        it('should throw NotFoundException if user not found', async () => {
            mockUserRepository.findOne.mockResolvedValue(null);

            await expect(
                service.updateProfile('invalid-id', updateDto),
            ).rejects.toThrow(NotFoundException);
        });
    });
});
