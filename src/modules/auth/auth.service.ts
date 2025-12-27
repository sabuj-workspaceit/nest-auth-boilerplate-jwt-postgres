import {
    Injectable,
    BadRequestException,
    UnauthorizedException,
    NotFoundException,
    ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
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
import { hashPassword, comparePassword, hashToken, compareToken } from '../../utils/hash.util';
import { generateOTP } from '../../utils/otp.util';
import { randomUUID } from 'crypto';
import * as OTPAuth from 'otpauth';
import { toDataURL } from 'qrcode';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>,
        @InjectRepository(RefreshToken)
        private refreshTokenRepository: Repository<RefreshToken>,
        @InjectRepository(EmailVerification)
        private emailVerificationRepository: Repository<EmailVerification>,
        @InjectRepository(PasswordReset)
        private passwordResetRepository: Repository<PasswordReset>,
        private jwtService: JwtService,
        private configService: ConfigService,
        private emailService: EmailService,
    ) { }

    async register(registerDto: RegisterDto) {
        const { email, password, firstName, lastName } = registerDto;

        // Check if user already exists
        const existingUser = await this.userRepository.findOne({
            where: { email },
        });

        if (existingUser) {
            throw new ConflictException('User with this email already exists');
        }

        // Hash password
        const hashedPassword = await hashPassword(password);

        // Create user
        const user = this.userRepository.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            isEmailVerified: false,
            isActive: true,
        });

        await this.userRepository.save(user);

        // Generate verification OTP and token
        await this.createEmailVerification(user);

        return {
            message: 'Registration successful. Please check your email to verify your account.',
            userId: user.id,
        };
    }

    async login(loginDto: LoginDto) {
        const { email, password } = loginDto;

        // Find user
        const user = await this.userRepository.findOne({ where: { email } });

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Check password
        const isPasswordValid = await comparePassword(password, user.password);

        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Check if user is active
        if (!user.isActive) {
            throw new UnauthorizedException('Account is deactivated');
        }

        // Check if email is verified
        if (!user.isEmailVerified) {
            throw new UnauthorizedException('Please verify your email before logging in');
        }

        if (user.isTwoFactorEnabled) {
            return {
                requires2fa: true,
                message: '2FA verification required',
                user: {
                    id: user.id,
                    email: user.email,
                },
            };
        }

        // Generate tokens
        const tokens = await this.generateTokens(user);

        return {
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                isEmailVerified: user.isEmailVerified,
            },
            ...tokens,
        };
    }

    async refreshToken(refreshToken: string) {
        try {
            // Verify refresh token
            const payload = this.jwtService.verify(refreshToken, {
                secret: this.configService.get<string>('jwt.refresh.secret'),
            });

            // Find refresh token in database
            const storedToken = await this.refreshTokenRepository.findOne({
                where: {
                    userId: payload.sub,
                    isRevoked: false,
                    expiresAt: MoreThan(new Date()),
                },
            });

            if (!storedToken) {
                throw new UnauthorizedException('Invalid refresh token');
            }

            // Verify token hash
            const isTokenValid = await compareToken(refreshToken, storedToken.token);

            if (!isTokenValid) {
                throw new UnauthorizedException('Invalid refresh token');
            }

            // Get user
            const user = await this.userRepository.findOne({
                where: { id: payload.sub },
            });

            if (!user || !user.isActive) {
                throw new UnauthorizedException('User not found or inactive');
            }

            // Revoke old refresh token
            storedToken.isRevoked = true;
            await this.refreshTokenRepository.save(storedToken);

            // Generate new tokens
            const tokens = await this.generateTokens(user);

            return tokens;
        } catch (error) {
            throw new UnauthorizedException('Invalid or expired refresh token');
        }
    }

    async logout(userId: string, refreshToken: string) {
        // Revoke all refresh tokens for this user
        await this.refreshTokenRepository.update(
            { userId, isRevoked: false },
            { isRevoked: true },
        );

        return { message: 'Logged out successfully' };
    }

    async verifyEmail(verifyEmailDto: VerifyEmailDto) {
        const { otp, token } = verifyEmailDto;

        if (!otp && !token) {
            throw new BadRequestException('Either OTP or token must be provided');
        }

        let verification: EmailVerification | undefined;

        if (otp) {
            // Find all non-used verifications and check OTP
            const verifications = await this.emailVerificationRepository.find({
                where: {
                    isUsed: false,
                    expiresAt: MoreThan(new Date()),
                },
                relations: ['user'],
            });

            for (const v of verifications) {
                if (v.otp && (await compareToken(otp, v.otp))) {
                    verification = v;
                    break;
                }
            }
        } else if (token) {
            // Find all non-used verifications and check token
            const verifications = await this.emailVerificationRepository.find({
                where: {
                    isUsed: false,
                    expiresAt: MoreThan(new Date()),
                },
                relations: ['user'],
            });

            for (const v of verifications) {
                if (v.token && (await compareToken(token, v.token))) {
                    verification = v;
                    break;
                }
            }
        }

        if (!verification) {
            throw new BadRequestException('Invalid or expired verification code');
        }

        // Mark verification as used
        verification.isUsed = true;
        await this.emailVerificationRepository.save(verification);

        // Update user
        const user = verification.user;
        user.isEmailVerified = true;
        await this.userRepository.save(user);

        // Send welcome email
        await this.emailService.sendWelcomeEmail(user.email, user.firstName);

        return { message: 'Email verified successfully' };
    }

    async resendVerification(email: string) {
        const user = await this.userRepository.findOne({ where: { email } });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        if (user.isEmailVerified) {
            throw new BadRequestException('Email is already verified');
        }

        // Invalidate old verifications
        await this.emailVerificationRepository.update(
            { userId: user.id, isUsed: false },
            { isUsed: true },
        );

        // Create new verification
        await this.createEmailVerification(user);

        return { message: 'Verification email sent successfully' };
    }

    async forgotPassword(email: string) {
        const user = await this.userRepository.findOne({ where: { email } });

        if (!user) {
            // Don't reveal if user exists
            return { message: 'If the email exists, a password reset link has been sent' };
        }

        // Invalidate old password resets
        await this.passwordResetRepository.update(
            { userId: user.id, isUsed: false },
            { isUsed: true },
        );

        // Generate OTP and token
        const otp = generateOTP();
        const token = randomUUID();

        const hashedOtp = await hashToken(otp);
        const hashedToken = await hashToken(token);

        const expirationHours = this.configService.get<number>('RESET_TOKEN_EXPIRATION_HOURS') || 1;
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + expirationHours);

        // Save password reset
        const passwordReset = this.passwordResetRepository.create({
            userId: user.id,
            otp: hashedOtp,
            token: hashedToken,
            expiresAt,
            isUsed: false,
        });

        await this.passwordResetRepository.save(passwordReset);

        // Send email
        await this.emailService.sendPasswordResetEmail(user.email, otp, token);

        return { message: 'If the email exists, a password reset link has been sent' };
    }

    async resetPassword(resetPasswordDto: ResetPasswordDto) {
        const { otp, token, newPassword } = resetPasswordDto;

        if (!otp && !token) {
            throw new BadRequestException('Either OTP or token must be provided');
        }

        let passwordReset: PasswordReset | undefined;

        if (otp) {
            const resets = await this.passwordResetRepository.find({
                where: {
                    isUsed: false,
                    expiresAt: MoreThan(new Date()),
                },
                relations: ['user'],
            });

            for (const r of resets) {
                if (r.otp && (await compareToken(otp, r.otp))) {
                    passwordReset = r;
                    break;
                }
            }
        } else if (token) {
            const resets = await this.passwordResetRepository.find({
                where: {
                    isUsed: false,
                    expiresAt: MoreThan(new Date()),
                },
                relations: ['user'],
            });

            for (const r of resets) {
                if (r.token && (await compareToken(token, r.token))) {
                    passwordReset = r;
                    break;
                }
            }
        }

        if (!passwordReset) {
            throw new BadRequestException('Invalid or expired reset code');
        }

        // Mark as used
        passwordReset.isUsed = true;
        await this.passwordResetRepository.save(passwordReset);

        // Update password
        const user = passwordReset.user;
        user.password = await hashPassword(newPassword);
        await this.userRepository.save(user);

        // Revoke all refresh tokens
        await this.refreshTokenRepository.update(
            { userId: user.id },
            { isRevoked: true },
        );

        // Send notification email
        await this.emailService.sendPasswordChangedEmail(user.email, user.firstName);

        return { message: 'Password reset successfully' };
    }

    async changePassword(userId: string, changePasswordDto: ChangePasswordDto) {
        const { oldPassword, newPassword } = changePasswordDto;

        const user = await this.userRepository.findOne({ where: { id: userId } });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        // Verify old password
        const isPasswordValid = await comparePassword(oldPassword, user.password);

        if (!isPasswordValid) {
            throw new BadRequestException('Current password is incorrect');
        }

        // Update password
        user.password = await hashPassword(newPassword);
        await this.userRepository.save(user);

        // Revoke all refresh tokens
        await this.refreshTokenRepository.update(
            { userId: user.id },
            { isRevoked: true },
        );

        // Send notification email
        await this.emailService.sendPasswordChangedEmail(user.email, user.firstName);

        return { message: 'Password changed successfully' };
    }

    async getProfile(userId: string) {
        const user = await this.userRepository.findOne({ where: { id: userId } });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        return {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            isEmailVerified: user.isEmailVerified,
            isActive: user.isActive,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };
    }

    async updateProfile(userId: string, updateProfileDto: UpdateProfileDto) {
        const user = await this.userRepository.findOne({ where: { id: userId } });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        if (updateProfileDto.firstName) {
            user.firstName = updateProfileDto.firstName;
        }

        if (updateProfileDto.lastName) {
            user.lastName = updateProfileDto.lastName;
        }

        await this.userRepository.save(user);

        return {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            isEmailVerified: user.isEmailVerified,
            isActive: user.isActive,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };
    }

    async generateTwoFactorSecret(user: User) {
        const secret = new OTPAuth.Secret().base32;
        const totp = new OTPAuth.TOTP({
            issuer: 'NEST_AUTH_APP',
            label: user.email,
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: OTPAuth.Secret.fromBase32(secret),
        });
        const otpauthUrl = totp.toString();

        await this.userRepository.update(
            { id: user.id },
            { twoFactorAuthenticationSecret: secret },
        );

        return {
            secret,
            qrCodeUrl: await toDataURL(otpauthUrl),
        };
    }

    async enableTwoFactor(user: User, code: string) {
        if (!user.twoFactorAuthenticationSecret) {
            throw new BadRequestException('2FA secret not generated');
        }

        const totp = new OTPAuth.TOTP({
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: OTPAuth.Secret.fromBase32(user.twoFactorAuthenticationSecret),
        });

        const isValid = totp.validate({
            token: code,
            window: 1,
        }) !== null;

        if (!isValid) {
            throw new BadRequestException('Invalid authentication code');
        }

        await this.userRepository.update(
            { id: user.id },
            { isTwoFactorEnabled: true },
        );

        return { message: '2FA enabled successfully' };
    }

    async verifyTwoFactor(user: User, code: string) {
        if (!user.isTwoFactorEnabled || !user.twoFactorAuthenticationSecret) {
            throw new BadRequestException('2FA is not enabled for this user');
        }

        const totp = new OTPAuth.TOTP({
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: OTPAuth.Secret.fromBase32(user.twoFactorAuthenticationSecret),
        });

        const isValid = totp.validate({
            token: code,
            window: 1,
        }) !== null;

        if (!isValid) {
            throw new UnauthorizedException('Invalid 2FA code');
        }

        return true;
    }

    async loginWith2fa(email: string, code: string) {
        const user = await this.userRepository.findOne({ where: { email } });

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        if (!user.isTwoFactorEnabled) {
            throw new BadRequestException('2FA is not enabled for this user');
        }

        const totp = new OTPAuth.TOTP({
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: OTPAuth.Secret.fromBase32(user.twoFactorAuthenticationSecret),
        });

        const isCodeValid = totp.validate({
            token: code,
            window: 1,
        }) !== null;

        if (!isCodeValid) {
            throw new UnauthorizedException('Invalid 2FA code');
        }

        return this.generateTokens(user);
    }

    // Helper methods
    private async generateTokens(user: User) {
        const payload = { sub: user.id, email: user.email };

        // @ts-ignore - JWT library type issue, works fine at runtime
        const accessToken = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('jwt.access.secret') || 'secret',
            expiresIn: (this.configService.get<string>('jwt.access.expiresIn') || '15m') as string,
        });

        // @ts-ignore - JWT library type issue, works fine at runtime
        const refreshToken = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('jwt.refresh.secret') || 'secret',
            expiresIn: (this.configService.get<string>('jwt.refresh.expiresIn') || '7d') as string,
        });

        // Hash and store refresh token
        const hashedRefreshToken = await hashToken(refreshToken);

        const expiresAt = new Date();
        const expirationDays = 7; // 7 days for refresh token
        expiresAt.setDate(expiresAt.getDate() + expirationDays);

        const refreshTokenEntity = this.refreshTokenRepository.create({
            token: hashedRefreshToken,
            userId: user.id,
            expiresAt,
            isRevoked: false,
        });

        await this.refreshTokenRepository.save(refreshTokenEntity);

        return {
            accessToken,
            refreshToken,
        };
    }

    private async createEmailVerification(user: User) {
        const otp = generateOTP();
        const token = randomUUID();

        const hashedOtp = await hashToken(otp);
        const hashedToken = await hashToken(token);

        const expirationMinutes = this.configService.get<number>('OTP_EXPIRATION_MINUTES') || 10;
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + expirationMinutes);

        const verification = this.emailVerificationRepository.create({
            userId: user.id,
            otp: hashedOtp,
            token: hashedToken,
            expiresAt,
            isUsed: false,
        });

        await this.emailVerificationRepository.save(verification);

        // Send verification email
        await this.emailService.sendVerificationEmail(user.email, otp, token);
    }
}
