import { IsArray, IsUUID, ArrayNotEmpty } from 'class-validator';

export class AssignRolesToUsersDto {
    @IsArray()
    @ArrayNotEmpty()
    @IsUUID('4', { each: true })
    userIds: string[];

    @IsArray()
    @ArrayNotEmpty()
    @IsUUID('4', { each: true })
    roleIds: string[];
}
