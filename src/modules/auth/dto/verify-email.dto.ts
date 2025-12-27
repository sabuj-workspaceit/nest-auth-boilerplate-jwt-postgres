import { IsOptional, IsString, ValidateIf } from 'class-validator';

export class VerifyEmailDto {
    @ValidateIf((o) => !o.token)
    @IsString()
    @IsOptional()
    otp?: string;

    @ValidateIf((o) => !o.otp)
    @IsString()
    @IsOptional()
    token?: string;
}
