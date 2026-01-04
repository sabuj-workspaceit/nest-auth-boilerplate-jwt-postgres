import { IsString, IsOptional, IsBoolean, IsArray, IsUUID, IsEmail, MinLength } from 'class-validator';

export class UpdateUserDto {
    @IsOptional()
    @IsString()
    firstName?: string;

    @IsOptional()
    @IsString()
    lastName?: string;

    @IsEmail()
    @IsOptional()
    email?: string;

    @IsOptional()
    @IsString()
    phone?: string;

    @IsOptional()
    @IsString()
    avatarUrl?: string;

    @IsOptional()
    @IsBoolean()
    isActive?: boolean;

    @IsOptional()
    @IsBoolean()
    isEmailVerified?: boolean;

    @IsOptional()
    @IsArray()
    @IsUUID('4', { each: true })
    roles?: string[];

    @IsOptional()
    @IsString()
    @MinLength(6)
    password?: string;
}
