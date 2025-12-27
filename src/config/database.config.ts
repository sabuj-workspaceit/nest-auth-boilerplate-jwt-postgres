import { registerAs } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { User } from '../entities/user.entity';
import { RefreshToken } from '../modules/auth/entities/refresh-token.entity';
import { EmailVerification } from '../modules/auth/entities/email-verification.entity';
import { PasswordReset } from '../modules/auth/entities/password-reset.entity';
import { Role } from '../entities/role.entity';
import { Permission } from '../entities/permission.entity';

export default registerAs(
    'database',
    (): TypeOrmModuleOptions => ({
        type: 'postgres',
        url: process.env.DATABASE_URL,
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        username: process.env.DB_USERNAME || 'postgres',
        password: process.env.DB_PASSWORD || 'password',
        database: process.env.DB_DATABASE || 'nest-auth',
        entities: [User, RefreshToken, EmailVerification, PasswordReset, Role, Permission],
        synchronize: process.env.NODE_ENV === 'development',
        logging: process.env.NODE_ENV === 'development',
    }),
);
