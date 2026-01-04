import { IsEmail, IsOptional, IsString } from 'class-validator';

export class UpdateProfileDto {
    @IsString()
    @IsOptional()
    firstName?: string;

    @IsString()
    @IsOptional()
    lastName?: string;

    @IsString()
    @IsOptional()
    phone?: string;

    @IsString()
    @IsOptional()
    avatarUrl?: string;

    @IsEmail()
    @IsOptional()
    email?: string;
}
