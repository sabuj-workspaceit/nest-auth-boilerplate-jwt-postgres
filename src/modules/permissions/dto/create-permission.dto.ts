import { IsString, IsNotEmpty, IsOptional } from 'class-validator';

export class CreatePermissionDto {
    @IsString()
    @IsNotEmpty()
    slug: string;

    @IsString()
    @IsOptional()
    description?: string;

    @IsString()
    @IsOptional()
    parentId?: string;
}
