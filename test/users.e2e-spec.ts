import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { Repository } from 'typeorm';
import { User } from './../src/entities/user.entity';
import { Permission } from './../src/entities/permission.entity';
import { Role } from './../src/entities/role.entity';
import { getRepositoryToken } from '@nestjs/typeorm';

import { EmailService } from './../src/services/email.service';

describe('UsersController (e2e)', () => {
    let app: INestApplication;
    let accessToken: string; // Token for user WITH permissions
    let noPermsAccessToken: string; // Token for user WITHOUT permissions
    let targetUserId: string; // User to be assigned roles
    let roleId: string;
    let userRepository: Repository<User>;
    let permissionRepository: Repository<Permission>;
    let roleRepository: Repository<Role>;

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        })
            .overrideProvider(EmailService)
            .useValue({
                sendVerificationEmail: jest.fn().mockResolvedValue(true),
                sendPasswordResetEmail: jest.fn().mockResolvedValue(true),
                sendWelcomeEmail: jest.fn().mockResolvedValue(true),
                sendPasswordChangedEmail: jest.fn().mockResolvedValue(true),
            })
            .compile();

        app = moduleFixture.createNestApplication();
        await app.init();

        userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
        permissionRepository = moduleFixture.get<Repository<Permission>>(getRepositoryToken(Permission));
        roleRepository = moduleFixture.get<Repository<Role>>(getRepositoryToken(Role));

        // 1. Setup Admin User (with users.manage permission)
        const adminEmail = `admin-user-${Date.now()}@example.com`;
        // Register
        const adminReg = await request(app.getHttpServer())
            .post('/auth/register')
            .send({ email: adminEmail, password: 'Password123!', firstName: 'Admin', lastName: 'User' });
        const adminId = adminReg.body.userId;
        // Verify
        await userRepository.update({ id: adminId }, { isEmailVerified: true });

        // Create Permission
        let perm = await permissionRepository.findOne({ where: { slug: 'users.manage' } });
        if (!perm) {
            perm = await permissionRepository.save(permissionRepository.create({ slug: 'users.manage', description: 'Manage Users' }));
        }

        // Create Admin Role with Permission
        const adminRole = await roleRepository.save(roleRepository.create({ name: `ADMIN_ROLE_${Date.now()}`, description: 'Admin' }));

        let rolesPerm = await permissionRepository.findOne({ where: { slug: 'roles.manage' } });
        if (!rolesPerm) {
            rolesPerm = await permissionRepository.save(permissionRepository.create({ slug: 'roles.manage', description: 'Manage Roles' }));
        }

        adminRole.permissions = [perm, rolesPerm];
        await roleRepository.save(adminRole);

        // Assign Admin Role to Admin User directly in DB
        const adminUser = await userRepository.findOne({ where: { id: adminId }, relations: ['roles'] });
        if (adminUser) {
            adminUser.roles = [adminRole];
            await userRepository.save(adminUser);
        }

        // Login Admin
        const adminLogin = await request(app.getHttpServer()).post('/auth/login').send({ email: adminEmail, password: 'Password123!' });
        accessToken = adminLogin.body.accessToken;


        // 2. Setup "No Permission" User
        const normalEmail = `normal-user-${Date.now()}@example.com`;
        await request(app.getHttpServer()).post('/auth/register').send({ email: normalEmail, password: 'Password123!', firstName: 'Normal', lastName: 'User' });
        await userRepository.update({ email: normalEmail }, { isEmailVerified: true });
        const normalLogin = await request(app.getHttpServer()).post('/auth/login').send({ email: normalEmail, password: 'Password123!' });
        noPermsAccessToken = normalLogin.body.accessToken;

        // 3. Setup Target User (to be modified)
        const targetEmail = `target-user-${Date.now()}@example.com`;
        const targetReg = await request(app.getHttpServer()).post('/auth/register').send({ email: targetEmail, password: 'Password123!', firstName: 'Target', lastName: 'User' });
        targetUserId = targetReg.body.userId;
        await userRepository.update({ email: targetEmail }, { isEmailVerified: true });

        // 4. Create a role to assign
        const testRole = await roleRepository.save(roleRepository.create({ name: `TEST_ASSIGN_ROLE_${Date.now()}`, description: 'Role to be assigned' }));
        roleId = testRole.id;
    });

    afterAll(async () => {
        await app.close();
    });

    describe('/users/:id/roles (POST)', () => {
        it('should forbid user without permission', async () => {
            await request(app.getHttpServer())
                .post(`/users/${targetUserId}/roles`)
                .set('Authorization', `Bearer ${noPermsAccessToken}`)
                .send({ roleIds: [roleId] })
                .expect(403);
        });

        it('should allow user with users.manage permission to assign role', async () => {
            await request(app.getHttpServer())
                .post(`/users/${targetUserId}/roles`)
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ roleIds: [roleId] })
                .expect(201);

            // Verify role assignment
            const updatedUser = await userRepository.findOne({ where: { id: targetUserId }, relations: ['roles'] });
            expect(updatedUser).toBeDefined();
            if (updatedUser) {
                expect(updatedUser.roles.some(r => r.id === roleId)).toBe(true);
            }
        });
    });

    describe('/users (GET)', () => {
        it('should forbid user without permission', async () => {
            await request(app.getHttpServer())
                .get('/users')
                .set('Authorization', `Bearer ${noPermsAccessToken}`)
                .expect(403);
        });

        it('should return paginated users for admin', async () => {
            const response = await request(app.getHttpServer())
                .get('/users')
                .set('Authorization', `Bearer ${accessToken}`)
                .query({ page: 1, limit: 10 })
                .expect(200);

            expect(response.body).toHaveProperty('data');
            expect(response.body).toHaveProperty('totalResults');
            expect(Array.isArray(response.body.data)).toBe(true);
            expect(response.body.data.length).toBeGreaterThan(0);
        });

        it('should filter users by search term', async () => {
            const response = await request(app.getHttpServer())
                .get('/users')
                .set('Authorization', `Bearer ${accessToken}`)
                .query({ search: 'Target' }) // Matches target user
                .expect(200);

            expect(response.body.data.length).toBeGreaterThan(0);
            expect(response.body.data[0].email).toContain('target');
        });
    });

    describe('/users/:id (GET)', () => {
        it('should return user profile', async () => {
            const response = await request(app.getHttpServer())
                .get(`/users/${targetUserId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(response.body.id).toBe(targetUserId);
            expect(response.body).toHaveProperty('email');
        });
    });

    describe('/users/:id (PATCH)', () => {
        it('should forbid user without permission', async () => {
            await request(app.getHttpServer())
                .patch(`/users/${targetUserId}`)
                .set('Authorization', `Bearer ${noPermsAccessToken}`)
                .send({ firstName: 'UpdatedName' })
                .expect(403);
        });

        it('should update user details', async () => {
            const newName = 'UpdatedTargetName';
            const newPhone = '9876543210';
            const newAvatar = 'http://example.com/new-avatar.jpg';

            const response = await request(app.getHttpServer())
                .patch(`/users/${targetUserId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ firstName: newName, phone: newPhone, avatarUrl: newAvatar })
                .expect(200);

            expect(response.body.firstName).toBe(newName);
            expect(response.body.phone).toBe(newPhone);
            expect(response.body.avatarUrl).toBe(newAvatar);

            const updatedUser = await userRepository.findOne({ where: { id: targetUserId } });
            expect(updatedUser?.firstName).toBe(newName);
            expect(updatedUser?.phone).toBe(newPhone);
            expect(updatedUser?.avatarUrl).toBe(newAvatar);
        });
    });

    describe('/users/:id/roles (GET)', () => {
        it('should return user roles', async () => {
            const response = await request(app.getHttpServer())
                .get(`/users/${targetUserId}/roles`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            // We assigned a role in previous test
            expect(response.body.length).toBeGreaterThan(0);
            expect(response.body[0].id).toBe(roleId);
        });
    });

    describe('/users/:id/permissions (GET)', () => {
        it('should return user permissions (from roles)', async () => {
            // Need to ensure the assigned role has some permission to test this fully, 
            // but for now just checking array return is enough structure test
            const response = await request(app.getHttpServer())
                .get(`/users/${targetUserId}/permissions`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
        });
    });

    describe('/users/:id (DELETE)', () => {
        it('should forbid user without permission', async () => {
            await request(app.getHttpServer())
                .delete(`/users/${targetUserId}`)
                .set('Authorization', `Bearer ${noPermsAccessToken}`)
                .expect(403);
        });

        it('should delete user', async () => {
            await request(app.getHttpServer())
                .delete(`/users/${targetUserId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            const deletedUser = await userRepository.findOne({ where: { id: targetUserId } });
            expect(deletedUser).toBeNull();
        });
    });
});
