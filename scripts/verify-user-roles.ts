import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { UsersService } from '../src/modules/users/users.service';
import { RolesService } from '../src/modules/roles/roles.service';
import { AuthService } from '../src/modules/auth/auth.service';

async function bootstrap() {
    const app = await NestFactory.createApplicationContext(AppModule);
    const usersService = app.get(UsersService);
    const rolesService = app.get(RolesService);
    const authService = app.get(AuthService);

    console.log('Starting verification...');

    try {
        // 1. Create a Role
        console.log('Creating role...');
        const role = await rolesService.create({
            name: 'USER_MANAGER_' + Date.now(),
            description: 'Can manage users',
        });
        console.log('Role created:', role.name);

        // 2. Create a User (Register)
        const email = `testuser_${Date.now()}@example.com`;
        console.log('Creating user:', email);
        const registerResult = await authService.register({
            email,
            password: 'password123',
            firstName: 'Test',
            lastName: 'User',
        });
        const userId = registerResult.userId;
        console.log('User created:', userId);

        // 3. Assign Role to User
        console.log('Assigning role to user...');
        await usersService.assignRoles(userId, { roleIds: [role.id] });
        console.log('Role assigned.');

        // 4. Verify User has Role
        console.log('Verifying user roles...');
        const user = await usersService.findOne(userId);
        const hasRole = user.roles.some((r) => r.id === role.id);

        if (hasRole) {
            console.log('SUCCESS: User has the assigned role.');
            console.log('User Roles:', user.roles.map(r => r.name));
        } else {
            console.error('FAILURE: User does not have the assigned role.');
        }

    } catch (error) {
        console.error('Verification failed:', error);
    } finally {
        await app.close();
    }
}

bootstrap();
