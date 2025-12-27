
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { UsersService } from '../src/modules/users/users.service';
import { RolesService } from '../src/modules/roles/roles.service';
import { AuthService } from '../src/modules/auth/auth.service';
import { PermissionsService } from '../src/modules/permissions/permissions.service';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    await app.init();

    const usersService = app.get(UsersService);
    const rolesService = app.get(RolesService);
    const authService = app.get(AuthService);
    const permissionsService = app.get(PermissionsService);

    console.log('Starting guard verification...');

    try {
        // 1. Setup Data
        console.log('Setting up data...');
        // Create Permission
        const allPermissions = await permissionsService.findAll();
        let permission = allPermissions.find(p => p.slug === 'users.manage');
        if (!permission) {
            permission = await permissionsService.create({ slug: 'users.manage', description: 'Manage users' });
        }

        // Create Role with Permission
        const managerRole = await rolesService.create({
            name: 'MANAGER_' + Date.now(),
            description: 'Manager role',
            permissionIds: [permission.id],
        });

        // Create Role WITHOUT Permission
        const userRole = await rolesService.create({
            name: 'USER_' + Date.now(),
            description: 'User role',
            permissionIds: [],
        });

        // Create Manager User
        const managerEmail = `manager_${Date.now()}@example.com`;
        const managerRegister = await authService.register({
            email: managerEmail,
            password: 'password123',
            firstName: 'Manager',
            lastName: 'User',
        });
        // Manually verify email for login
        const manager = await usersService.findOne(managerRegister.userId);
        manager.isEmailVerified = true;
        await usersService['usersRepository'].save(manager);
        await usersService.assignRoles(manager.id, { roleIds: [managerRole.id] });

        // Login Manager
        const managerLogin = await authService.login({ email: managerEmail, password: 'password123' });
        if (!('accessToken' in managerLogin)) {
            throw new Error('Manager login failed or requires 2FA');
        }
        const managerToken = managerLogin.accessToken;

        // Create Normal User
        const userEmail = `user_${Date.now()}@example.com`;
        const userRegister = await authService.register({
            email: userEmail,
            password: 'password123',
            firstName: 'Normal',
            lastName: 'User',
        });
        // Manually verify email
        const normalUser = await usersService.findOne(userRegister.userId);
        normalUser.isEmailVerified = true;
        await usersService['usersRepository'].save(normalUser);
        await usersService.assignRoles(normalUser.id, { roleIds: [userRole.id] });

        // Login Normal User
        const userLogin = await authService.login({ email: userEmail, password: 'password123' });
        if (!('accessToken' in userLogin)) {
            throw new Error('User login failed or requires 2FA');
        }
        const userToken = userLogin.accessToken;


        // 2. Test Access
        console.log('Testing access...');

        // Scenario 1: Manager (With Permission) tries to assign role -> Should Succeed (201)
        // We'll try to assign a role to themselves just for testing the endpoint access
        await request(app.getHttpServer())
            .post(`/users/${manager.id}/roles`)
            .set('Authorization', `Bearer ${managerToken}`)
            .send({ roleIds: [managerRole.id] })
            .expect(201)
            .then(() => console.log('SUCCESS: Manager can access protected route.'));

        // Scenario 2: Normal User (Without Permission) tries to assign role -> Should Fail (403)
        await request(app.getHttpServer())
            .post(`/users/${normalUser.id}/roles`)
            .set('Authorization', `Bearer ${userToken}`)
            .send({ roleIds: [userRole.id] })
            .expect(403)
            .then(() => console.log('SUCCESS: Normal User cannot access protected route.'));

    } catch (error) {
        console.error('Verification failed:', error);
    } finally {
        await app.close();
    }
}

bootstrap();
