import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Role } from '../src/entities/role.entity';
import { Permission } from '../src/entities/permission.entity';
import { User } from '../src/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

async function bootstrap() {
    const app = await NestFactory.createApplicationContext(AppModule);

    const roleRepo = app.get<Repository<Role>>(getRepositoryToken(Role));
    const permissionRepo = app.get<Repository<Permission>>(getRepositoryToken(Permission));
    const userRepo = app.get<Repository<User>>(getRepositoryToken(User));

    console.log('🌱 Starting database seeding...');

    // 1. Create Permissions
    const permissionsData = [
        { slug: 'users.manage', description: 'Manage users' },
        { slug: 'users.create', description: 'Create users' },
        { slug: 'users.read', description: 'Read users' },
        { slug: 'users.update', description: 'Update users' },
        { slug: 'users.delete', description: 'Delete users' },
        { slug: 'users.assign-role', description: 'Assign roles to users' },

        { slug: 'roles.manage', description: 'Manage roles' },
        { slug: 'roles.create', description: 'Create roles' },
        { slug: 'roles.read', description: 'Read roles' },
        { slug: 'roles.update', description: 'Update roles' },
        { slug: 'roles.delete', description: 'Delete roles' },
        { slug: 'roles.assign-permission', description: 'Assign permissions to roles' },

        { slug: 'permissions.manage', description: 'Manage permissions' },
        { slug: 'permissions.create', description: 'Create permissions' },
        { slug: 'permissions.read', description: 'Read permissions' },
        { slug: 'permissions.update', description: 'Update permissions' },
        { slug: 'permissions.delete', description: 'Delete permissions' },
    ];

    const permissions: Permission[] = [];
    for (const p of permissionsData) {
        let permission = await permissionRepo.findOne({ where: { slug: p.slug } });
        if (!permission) {
            permission = await permissionRepo.save(permissionRepo.create(p));
            console.log(`✅ Created permission: ${p.slug}`);
        } else {
            console.log(`ℹ️  Permission already exists: ${p.slug}`);
        }
        permissions.push(permission);
    }

    // 2. Create Super Admin Role
    const roleName = 'SUPER_ADMIN';
    let superAdminRole = await roleRepo.findOne({
        where: { name: roleName },
        relations: ['permissions'],
    });

    if (!superAdminRole) {
        superAdminRole = await roleRepo.save(roleRepo.create({
            name: roleName,
            description: 'Super Administrator with full access',
            permissions: permissions,
        }));
        console.log(`✅ Created role: ${roleName}`);
    } else {
        // Update permissions if needed
        superAdminRole.permissions = permissions;
        await roleRepo.save(superAdminRole);
        console.log(`ℹ️  Role already exists: ${roleName} (Permissions updated)`);
    }

    // 3. Create Super Admin User
    const adminEmail = 'superadmin@yopmail.com';
    const adminPassword = 'password';

    let adminUser = await userRepo.findOne({
        where: { email: adminEmail },
        relations: ['roles'],
    });

    if (!adminUser) {
        const hashedPassword = await bcrypt.hash(adminPassword, 10);
        adminUser = await userRepo.save(userRepo.create({
            email: adminEmail,
            password: hashedPassword,
            firstName: 'Super',
            lastName: 'Admin',
            avatarUrl: 'https://gravatar.com/avatar/bc8cab4ba5c5d2d99b4f07e171bda77f?s=400&d=robohash&r=x',
            isEmailVerified: true,
            isActive: true,
            roles: [superAdminRole],
        }));
        console.log(`✅ Created Super Admin user: ${adminEmail}`);
        console.log(`🔑 Password: ${adminPassword}`);
    } else {
        // Ensure role is assigned
        const hasRole = adminUser.roles.some(r => r.id === superAdminRole.id);
        if (!hasRole) {
            adminUser.roles.push(superAdminRole);
            await userRepo.save(adminUser);
            console.log(`✅ Assigned ${roleName} role to existing user: ${adminEmail}`);
        } else {
            console.log(`ℹ️  User already exists and has role: ${adminEmail}`);
        }
    }

    console.log('✅ Seeding complete!');
    await app.close();
}

bootstrap();
