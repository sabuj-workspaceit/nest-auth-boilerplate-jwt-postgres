
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

jest.mock('otpauth', () => {
    return {
        Secret: class {
            base32 = 'mockSecret';
            static fromBase32() {
                return new this();
            }
        },
        TOTP: class {
            constructor() { }
            toString() {
                return 'otpauthUrl';
            }
            validate() {
                return 0; // Returns delta (number) on success, null on failure
            }
        },
    };
});

jest.mock('qrcode', () => ({
    toDataURL: jest.fn(),
}));

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
        phone: '1234567890',
        avatarUrl: 'http://example.com/avatar.jpg',
        isEmailVerified: true,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    const mockUserRepository = {
        findOne: jest.fn(),
        create: jest.fn(),
        save: jest.fn(),
        update: jest.fn(),
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
                relations: ['roles', 'roles.permissions'],
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

        it('should successfully login even if email is not verified', async () => {
            mockUserRepository.findOne.mockResolvedValue({
                ...mockUser,
                isEmailVerified: false,
            });
            mockJwtService.sign.mockReturnValue('mock-token');
            mockRefreshTokenRepository.create.mockReturnValue({});
            mockRefreshTokenRepository.save.mockResolvedValue({});
            mockConfigService.get.mockReturnValue('secret');

            jest.spyOn(hashUtil, 'comparePassword').mockResolvedValue(true);
            jest.spyOn(hashUtil, 'hashToken').mockResolvedValue('hashedToken');

            const result = await service.login(loginDto);

            expect(result).toHaveProperty('user');
            expect(result.user.isEmailVerified).toBe(false);
            expect(result).toHaveProperty('accessToken');
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

        it('should successfully update email if unique', async () => {
            const updateEmailDto = { email: 'newemail@example.com' };
            const updatedUser = {
                ...mockUser,
                email: updateEmailDto.email,
                isEmailVerified: false,
            };

            mockUserRepository.findOne.mockResolvedValueOnce(mockUser); // Initial find
            mockUserRepository.findOne.mockResolvedValueOnce(null); // Check uniqueness
            mockUserRepository.save.mockResolvedValue(updatedUser);

            const result = await service.updateProfile(mockUser.id, updateEmailDto);

            expect(result.email).toBe(updateEmailDto.email);
            expect(result.isEmailVerified).toBe(false);
            expect(mockUserRepository.save).toHaveBeenCalled();
        });

        it('should throw ConflictException if new email already exists', async () => {
            const updateEmailDto = { email: 'existing@example.com' };

            mockUserRepository.findOne.mockResolvedValueOnce(mockUser); // Initial find
            mockUserRepository.findOne.mockResolvedValueOnce({ ...mockUser, id: 'other-user', email: 'existing@example.com' }); // Check uniqueness

            await expect(
                service.updateProfile(mockUser.id, updateEmailDto),
            ).rejects.toThrow(ConflictException);
        });

        it('should throw NotFoundException if user not found', async () => {
            mockUserRepository.findOne.mockResolvedValue(null);

            await expect(
                service.updateProfile('invalid-id', updateDto),
            ).rejects.toThrow(NotFoundException);
        });
    });

    describe('TwoFactorAuth', () => {
        const mockSecret = 'mockSecret';
        const mockQrCodeUrl = 'mockQrCodeUrl';
        const mockCode = '123456';

        describe('generateTwoFactorSecret', () => {
            it('should generate a 2FA secret and QR code URL', async () => {
                require('qrcode').toDataURL.mockResolvedValue(mockQrCodeUrl);
                mockUserRepository.update.mockResolvedValue({});

                const result = await service.generateTwoFactorSecret(mockUser as any);

                expect(result).toEqual({
                    secret: mockSecret,
                    qrCodeUrl: mockQrCodeUrl,
                });
                expect(mockUserRepository.update).toHaveBeenCalledWith(
                    { id: mockUser.id },
                    { twoFactorAuthenticationSecret: mockSecret },
                );
            });
        });

        describe('enableTwoFactor', () => {
            it('should enable 2FA if code is valid', async () => {
                const userWithSecret = { ...mockUser, twoFactorAuthenticationSecret: mockSecret };
                // TOTP.validate is mocked to return 0 (truthy) by default
                mockUserRepository.update.mockResolvedValue({});

                const result = await service.enableTwoFactor(userWithSecret as any, mockCode);

                expect(result).toEqual({ message: '2FA enabled successfully' });
                expect(mockUserRepository.update).toHaveBeenCalledWith(
                    { id: mockUser.id },
                    { isTwoFactorEnabled: true },
                );
            });

            it('should throw BadRequestException if secret not generated', async () => {
                const userWithoutSecret = { ...mockUser, twoFactorAuthenticationSecret: null };

                await expect(service.enableTwoFactor(userWithoutSecret as any, mockCode)).rejects.toThrow(
                    BadRequestException,
                );
            });

            it('should throw BadRequestException if code is invalid', async () => {
                const userWithSecret = { ...mockUser, twoFactorAuthenticationSecret: mockSecret };
                // Override mock for this test
                const OTPAuth = require('otpauth');
                const originalValidate = OTPAuth.TOTP.prototype.validate;
                OTPAuth.TOTP.prototype.validate = () => null; // return null for failure

                try {
                    await expect(service.enableTwoFactor(userWithSecret as any, mockCode)).rejects.toThrow(
                        BadRequestException,
                    );
                } finally {
                    OTPAuth.TOTP.prototype.validate = originalValidate;
                }
            });
        });

        describe('loginWith2fa', () => {
            it('should return tokens if 2FA code is valid', async () => {
                const user2fa = { ...mockUser, isTwoFactorEnabled: true, twoFactorAuthenticationSecret: mockSecret };
                mockUserRepository.findOne.mockResolvedValue(user2fa);
                // validate returns 0 (truthy) by default
                mockJwtService.sign.mockReturnValue('mock-token');
                mockRefreshTokenRepository.create.mockReturnValue({});
                mockRefreshTokenRepository.save.mockResolvedValue({});
                mockConfigService.get.mockReturnValue('secret');
                jest.spyOn(hashUtil, 'hashToken').mockResolvedValue('hashedToken');


                const result = await service.loginWith2fa(mockUser.email, mockCode);

                expect(result).toHaveProperty('accessToken');
                expect(result).toHaveProperty('refreshToken');
            });

            it('should throw UnauthorizedException if user not found', async () => {
                mockUserRepository.findOne.mockResolvedValue(null);
                await expect(service.loginWith2fa(mockUser.email, mockCode)).rejects.toThrow(
                    UnauthorizedException
                );
            });

            it('should throw BadRequestException if 2FA is not enabled', async () => {
                const userNo2fa = { ...mockUser, isTwoFactorEnabled: false };
                mockUserRepository.findOne.mockResolvedValue(userNo2fa);

                await expect(service.loginWith2fa(mockUser.email, mockCode)).rejects.toThrow(
                    BadRequestException
                );
            });

            it('should throw UnauthorizedException if 2FA code is invalid', async () => {
                const user2fa = { ...mockUser, isTwoFactorEnabled: true, twoFactorAuthenticationSecret: mockSecret };
                mockUserRepository.findOne.mockResolvedValue(user2fa);

                const OTPAuth = require('otpauth');
                const originalValidate = OTPAuth.TOTP.prototype.validate;
                OTPAuth.TOTP.prototype.validate = () => null;

                try {
                    await expect(service.loginWith2fa(mockUser.email, mockCode)).rejects.toThrow(
                        UnauthorizedException
                    );
                } finally {
                    OTPAuth.TOTP.prototype.validate = originalValidate;
                }
            });
        });
    });
});
