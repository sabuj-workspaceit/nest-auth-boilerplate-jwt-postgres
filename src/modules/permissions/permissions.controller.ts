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
import { PermissionsService } from './permissions.service';
import { CreatePermissionDto } from './dto/create-permission.dto';
import { UpdatePermissionDto } from './dto/update-permission.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../../common/guards/permissions.guard';
import { RequirePermissions } from '../../common/decorators/permissions.decorator';

@Controller('permissions')
@UseGuards(JwtAuthGuard, PermissionsGuard) // Protect all routes
export class PermissionsController {
    constructor(private readonly permissionsService: PermissionsService) { }

    @Post()
    @RequirePermissions('permissions.manage', 'permissions.create')
    create(@Body() createPermissionDto: CreatePermissionDto) {
        return this.permissionsService.create(createPermissionDto);
    }

    @Get()
    @RequirePermissions('permissions.manage', 'permissions.read')
    findAll() {
        return this.permissionsService.findAll();
    }

    @Get(':id')
    @RequirePermissions('permissions.manage', 'permissions.read')
    findOne(@Param('id') id: string) {
        return this.permissionsService.findOne(id);
    }

    @Patch(':id')
    @RequirePermissions('permissions.manage', 'permissions.update')
    update(
        @Param('id') id: string,
        @Body() updatePermissionDto: UpdatePermissionDto,
    ) {
        return this.permissionsService.update(id, updatePermissionDto);
    }

    @Delete(':id')
    @RequirePermissions('permissions.manage', 'permissions.delete')
    remove(@Param('id') id: string) {
        return this.permissionsService.remove(id);
    }
}
