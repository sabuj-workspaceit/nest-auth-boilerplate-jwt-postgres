import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { Repository } from 'typeorm';
import { User } from './../src/entities/user.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Role } from './../src/entities/role.entity';

describe('RolesController (e2e)', () => {
    let app: INestApplication;
    let accessToken: string;
    let roleRepository: Repository<Role>;
    let userRepository: Repository<User>;

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        app = moduleFixture.createNestApplication();
        await app.init();

        roleRepository = moduleFixture.get<Repository<Role>>(getRepositoryToken(Role));
        userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));

        // Create a test user and get access token
        const testUserEmail = `test-roles-${Date.now()}@example.com`;
        const testUserPassword = 'TestPassword123!';

        // Register
        await request(app.getHttpServer())
            .post('/auth/register')
            .send({
                email: testUserEmail,
                password: testUserPassword,
                firstName: 'Test',
                lastName: 'User',
            });

        // Manually verify email (skip OTP)
        await userRepository.update({ email: testUserEmail }, { isEmailVerified: true });

        // Login
        const loginResponse = await request(app.getHttpServer())
            .post('/auth/login')
            .send({
                email: testUserEmail,
                password: testUserPassword,
            });

        accessToken = loginResponse.body.accessToken;
    });

    afterAll(async () => {
        await app.close();
    });

    describe('/roles', () => {
        let createdRoleId: string;

        it('should create a new role', async () => {
            const createRoleDto = {
                name: `TEST_ROLE_${Date.now()}`,
                description: 'Test Role Description',
            };

            const response = await request(app.getHttpServer())
                .post('/roles')
                .set('Authorization', `Bearer ${accessToken}`)
                .send(createRoleDto)
                .expect(201);

            expect(response.body).toHaveProperty('id');
            expect(response.body.name).toBe(createRoleDto.name);
            expect(response.body.description).toBe(createRoleDto.description);
            createdRoleId = response.body.id;
        });

        it('should get all roles', async () => {
            const response = await request(app.getHttpServer())
                .get('/roles')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBeGreaterThan(0);
        });

        it('should get a role by id', async () => {
            const response = await request(app.getHttpServer())
                .get(`/roles/${createdRoleId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(response.body.id).toBe(createdRoleId);
        });

        it('should update a role', async () => {
            const updateRoleDto = {
                description: 'Updated Description',
            };

            const response = await request(app.getHttpServer())
                .patch(`/roles/${createdRoleId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .send(updateRoleDto)
                .expect(200);

            expect(response.body.description).toBe(updateRoleDto.description);
        });

        it('should delete a role', async () => {
            await request(app.getHttpServer())
                .delete(`/roles/${createdRoleId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            // Verify it's gone
            await request(app.getHttpServer())
                .get(`/roles/${createdRoleId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(404);
        });
    });
});
