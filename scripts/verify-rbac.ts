
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { RolesService } from '../src/modules/roles/roles.service';
import { PermissionsService } from '../src/modules/permissions/permissions.service';
import { DataSource } from 'typeorm';

async function bootstrap() {
    const app = await NestFactory.createApplicationContext(AppModule);
    const rolesService = app.get(RolesService);
    const permissionsService = app.get(PermissionsService);
    const dataSource = app.get(DataSource);

    console.log('Starting verification...');

    try {
        // 1. Create permissions
        console.log('Creating permissions...');
        const parentPermission = await permissionsService.create({
            slug: 'users.manage',
            description: 'Manage users',
        });
        console.log('Parent permission created:', parentPermission.slug);

        const childPermission = await permissionsService.create({
            slug: 'users.create',
            description: 'Create users',
            parentId: parentPermission.id,
        });
        console.log('Child permission created:', childPermission.slug);

        // 2. Create Role with permission
        console.log('Creating role...');
        const adminRole = await rolesService.create({
            name: 'ADMIN_TEST_' + Date.now(),
            description: 'Administrator role',
            permissionIds: [parentPermission.id, childPermission.id],
        });
        console.log('Role created:', adminRole.name);

        // 3. Verify Role has permissions
        const fetchedRole = await rolesService.findOne(adminRole.id);
        console.log('Fetched Role Permissions:', fetchedRole.permissions.map(p => p.slug));

        if (fetchedRole.permissions.length === 2) {
            console.log('SUCCESS: Role has correct number of permissions.');
        } else {
            console.error('FAILURE: Role does not have correct number of permissions.');
        }

    } catch (error) {
        console.error('Verification failed:', error);
    } finally {
        await app.close();
    }
}

bootstrap();
