import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { Repository } from 'typeorm';
import { User } from './../src/entities/user.entity';
import { Permission } from './../src/entities/permission.entity';
import { Role } from './../src/entities/role.entity';
import { getRepositoryToken } from '@nestjs/typeorm';

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
        }).compile();

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
        // Link permission manually (since we don't have a service here, we use raw query or entity manager ideally, but let's try assuming a relation save)
        // Actually, we can use the `roles/:id` or just update the entity directly if we loaded relations. 
        // Easier: Create role, then insert into role_permissions
        // We can't access join table directly easily with pure repository without `createQueryBuilder` or loading the entity with relations.
        // Let's assume we can assign the permission to the role via standard TypeORM save if we set the array.
        adminRole.permissions = [perm];
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
});
