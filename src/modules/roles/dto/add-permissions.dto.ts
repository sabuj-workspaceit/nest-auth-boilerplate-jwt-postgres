import { IsArray, IsUUID } from 'class-validator';

export class AddPermissionsDto {
    @IsArray()
    @IsUUID('4', { each: true })
    permissionIds: string[];
}
