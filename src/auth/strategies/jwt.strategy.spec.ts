import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from './jwt.strategy';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../../entities/user.entity';

describe('JwtStrategy', () => {
    let strategy: JwtStrategy;
    let userRepository: any;

    const mockUser = {
        id: 'user-id-123',
        email: 'test@example.com',
        isActive: true,
    };

    const mockUserRepository = {
        findOne: jest.fn(),
    };

    const mockConfigService = {
        get: jest.fn().mockReturnValue('test-secret'),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                JwtStrategy,
                {
                    provide: ConfigService,
                    useValue: mockConfigService,
                },
                {
                    provide: getRepositoryToken(User),
                    useValue: mockUserRepository,
                },
            ],
        }).compile();

        strategy = module.get<JwtStrategy>(JwtStrategy);
        userRepository = module.get(getRepositoryToken(User));

        jest.clearAllMocks();
    });

    describe('validate', () => {
        it('should return user if found and active', async () => {
            const payload = { sub: 'user-id-123', email: 'test@example.com' };
            mockUserRepository.findOne.mockResolvedValue(mockUser);

            const result = await strategy.validate(payload);

            expect(result).toEqual(mockUser);
            expect(userRepository.findOne).toHaveBeenCalledWith({
                where: { id: payload.sub },
            });
        });

        it('should throw UnauthorizedException if user not found', async () => {
            const payload = { sub: 'invalid-id', email: 'test@example.com' };
            mockUserRepository.findOne.mockResolvedValue(null);

            await expect(strategy.validate(payload)).rejects.toThrow(
                UnauthorizedException,
            );
        });

        it('should throw UnauthorizedException if user is inactive', async () => {
            const payload = { sub: 'user-id-123', email: 'test@example.com' };
            mockUserRepository.findOne.mockResolvedValue({
                ...mockUser,
                isActive: false,
            });

            await expect(strategy.validate(payload)).rejects.toThrow(
                UnauthorizedException,
            );
        });
    });
});
