import {
    IsNotEmpty,
    IsOptional,
    IsString,
    MinLength,
    ValidateIf,
} from 'class-validator';

export class ResetPasswordDto {
    @ValidateIf((o) => !o.token)
    @IsString()
    @IsOptional()
    otp?: string;

    @ValidateIf((o) => !o.otp)
    @IsString()
    @IsOptional()
    token?: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    newPassword: string;
}
