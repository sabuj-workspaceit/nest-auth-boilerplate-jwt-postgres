import {
    Controller,
    Get,
    Post,
    Body,
    Patch,
    Param,
    Delete,
    UseGuards,
} from '@nestjs/common';
import { RolesService } from './roles.service';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AddPermissionsDto } from './dto/add-permissions.dto';
import { PermissionsGuard } from '../../common/guards/permissions.guard';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';

@Controller('roles')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class RolesController {
    constructor(private readonly rolesService: RolesService) { }

    @Post()
    @RequirePermissions('roles.manage', 'roles.create')
    create(@Body() createRoleDto: CreateRoleDto) {
        return this.rolesService.create(createRoleDto);
    }

    @Get()
    @RequirePermissions('roles.manage', 'roles.read')
    findAll() {
        return this.rolesService.findAll();
    }

    @Get(':id')
    @RequirePermissions('roles.manage', 'roles.read')
    findOne(@Param('id') id: string) {
        return this.rolesService.findOne(id);
    }

    @Patch(':id')
    @RequirePermissions('roles.manage', 'roles.update')
    update(@Param('id') id: string, @Body() updateRoleDto: UpdateRoleDto) {
        return this.rolesService.update(id, updateRoleDto);
    }

    @Delete(':id')
    @RequirePermissions('roles.manage', 'roles.delete')
    remove(@Param('id') id: string) {
        return this.rolesService.remove(id);
    }

    @Post(':id/permissions')
    @RequirePermissions('roles.manage', 'roles.assign-permission')
    setPermissions(@Param('id') id: string, @Body() addPermissionDto: AddPermissionsDto) {
        return this.rolesService.setPermissions(id, addPermissionDto);
    }
}
