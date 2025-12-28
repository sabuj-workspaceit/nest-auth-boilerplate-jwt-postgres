import { Test, TestingModule } from '@nestjs/testing';
import { Controller, Get, INestApplication } from '@nestjs/common';
import request from 'supertest';
import { Reflector } from '@nestjs/core';
import { ResponseInterceptor } from '../src/common/interceptors/response.interceptor';
import { HttpExceptionFilter } from '../src/common/filters/http-exception.filter';
import { ResponseMessage } from '../src/common/decorators/response-message.decorator';

@Controller('test')
class TestController {
    @Get('success')
    @ResponseMessage('Custom success message')
    success() {
        return { foo: 'bar' };
    }

    @Get('default-message')
    defaultMessage() {
        return { foo: 'baz' };
    }

    @Get('error')
    error() {
        throw new Error('Test error');
    }
}

describe('Response Format (e2e)', () => {
    let app: INestApplication;

    beforeEach(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            controllers: [TestController],
        }).compile();

        app = moduleFixture.createNestApplication();

        // Manually replicate main.ts setup
        const reflector = app.get(Reflector);
        app.useGlobalInterceptors(new ResponseInterceptor(reflector));
        app.useGlobalFilters(new HttpExceptionFilter());

        await app.init();
    });

    afterAll(async () => {
        await app.close();
    });

    it('/test/success (GET) should return formatted response with custom message', () => {
        return request(app.getHttpServer())
            .get('/test/success')
            .expect(200)
            .expect((res) => {
                expect(res.body).toEqual({
                    success: true,
                    message: 'Custom success message',
                    data: { foo: 'bar' },
                    errors: null,
                });
            });
    });

    it('/test/default-message (GET) should return formatted response with default message', () => {
        return request(app.getHttpServer())
            .get('/test/default-message')
            .expect(200)
            .expect((res) => {
                expect(res.body).toEqual({
                    success: true,
                    message: 'Operation successful',
                    data: { foo: 'baz' },
                    errors: null,
                });
            });
    });

    it('/test/error (GET) should return formatted error', () => {
        return request(app.getHttpServer())
            .get('/test/error')
            .expect(500)
            .expect((res) => {
                expect(res.body).toEqual({
                    success: false,
                    message: 'Test error',
                    data: null, // Depending on filter implementation, data might be null or undefined. My filter says null.
                    errors: null,
                });
            });
    });
});
