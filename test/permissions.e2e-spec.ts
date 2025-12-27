import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { Repository } from 'typeorm';
import { User } from './../src/entities/user.entity';
import { getRepositoryToken } from '@nestjs/typeorm';

describe('PermissionsController (e2e)', () => {
    let app: INestApplication;
    let accessToken: string;
    let userRepository: Repository<User>;

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        app = moduleFixture.createNestApplication();
        await app.init();

        userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));

        // Create a test user and get access token
        const testUserEmail = `test-perms-${Date.now()}@example.com`;
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

    describe('/permissions', () => {
        let createdPermissionId: string;

        it('should create a new permission', async () => {
            const createPermissionDto = {
                slug: `test.permission.${Date.now()}`,
                description: 'Test Permission Description',
            };

            const response = await request(app.getHttpServer())
                .post('/permissions')
                .set('Authorization', `Bearer ${accessToken}`)
                .send(createPermissionDto)
                .expect(201);

            expect(response.body).toHaveProperty('id');
            expect(response.body.slug).toBe(createPermissionDto.slug);
            expect(response.body.description).toBe(createPermissionDto.description);
            createdPermissionId = response.body.id;
        });

        it('should get all permissions', async () => {
            const response = await request(app.getHttpServer())
                .get('/permissions')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBeGreaterThan(0);
        });

        it('should get a permission by id', async () => {
            const response = await request(app.getHttpServer())
                .get(`/permissions/${createdPermissionId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            expect(response.body.id).toBe(createdPermissionId);
        });

        it('should update a permission', async () => {
            const updatePermissionDto = {
                description: 'Updated Permission Description',
            };

            const response = await request(app.getHttpServer())
                .patch(`/permissions/${createdPermissionId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .send(updatePermissionDto)
                .expect(200);

            expect(response.body.description).toBe(updatePermissionDto.description);
        });

        it('should delete a permission', async () => {
            await request(app.getHttpServer())
                .delete(`/permissions/${createdPermissionId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);

            // Verify it's gone
            await request(app.getHttpServer())
                .get(`/permissions/${createdPermissionId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(404);
        });
    });
});
