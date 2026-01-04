import { Controller, Get, Post, Body, Param, UseGuards, Patch, Delete, Query, Put } from '@nestjs/common';
import { UsersService } from './users.service';
import { AssignRolesDto } from './dto/assign-roles.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../../common/guards/permissions.guard';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersFilterDto } from './dto/users-filter.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { AssignRolesToUsersDto } from './dto/assign-roles-to-users.dto';

@Controller('users')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Post(':id/roles')
    @RequirePermissions('users.manage', 'users.assign-role', 'roles.manage')
    assignRoles(@Param('id') id: string, @Body() assignRolesDto: AssignRolesDto) {
        return this.usersService.assignRoles(id, assignRolesDto);
    }

    @Post('assign-roles')
    @RequirePermissions('users.manage', 'users.assign-role', 'roles.manage')
    assignRolesToUsers(@Body() assignRolesToUsersDto: AssignRolesToUsersDto) {
        return this.usersService.assignRolesToUsers(assignRolesToUsersDto);
    }

    @Get()
    @RequirePermissions('users.manage', 'users.read')
    findAll(@Query() filterDto: UsersFilterDto) {
        return this.usersService.findAll(filterDto);
    }

    @Get(':id')
    @RequirePermissions('users.manage', 'users.read')
    findOne(@Param('id') id: string) {
        return this.usersService.findOne(id);
    }

    @Post()
    @RequirePermissions('users.manage', 'users.create')
    create(@Body() createUserDto: CreateUserDto) {
        return this.usersService.create(createUserDto);
    }

    @Patch(':id')
    @RequirePermissions('users.manage', 'users.update')
    update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
        return this.usersService.update(id, updateUserDto);
    }

    @Delete(':id')
    @RequirePermissions('users.manage', 'users.delete')
    remove(@Param('id') id: string) {
        return this.usersService.remove(id);
    }

    @Get(':id/roles')
    @RequirePermissions('users.manage', 'users.read', 'roles.manage', 'roles.read')
    getRoles(@Param('id') id: string) {
        return this.usersService.getRoles(id);
    }

    @Get(':id/permissions')
    @RequirePermissions('users.manage', 'users.read', 'permissions.manage', 'permissions.read')
    getPermissions(@Param('id') id: string) {
        return this.usersService.getPermissions(id);
    }

}
