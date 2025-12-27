import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from '../../entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { EmailVerification } from './entities/email-verification.entity';
import { PasswordReset } from './entities/password-reset.entity';
import { EmailService } from '../../services/email.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Module({
    imports: [
        TypeOrmModule.forFeature([
            User,
            RefreshToken,
            EmailVerification,
            PasswordReset,
        ]),
        PassportModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            // @ts-ignore - JWT library type issue, works fine at runtime
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('jwt.access.secret') || 'secret',
                signOptions: {
                    expiresIn: (configService.get<string>('jwt.access.expiresIn') || '15m') as string,
                },
            }),
            inject: [ConfigService],
        }),
    ],
    controllers: [AuthController],
    providers: [
        AuthService,
        EmailService,
        JwtStrategy,
        RefreshTokenStrategy,
        JwtAuthGuard,
    ],
    exports: [AuthService, JwtAuthGuard],
})
export class AuthModule { }
