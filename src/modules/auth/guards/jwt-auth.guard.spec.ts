import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtAuthGuard } from './jwt-auth.guard';
import { IS_PUBLIC_KEY } from '../../../common/decorators/public.decorator';

describe('JwtAuthGuard', () => {
    let guard: JwtAuthGuard;
    let reflector: Reflector;

    beforeEach(() => {
        reflector = new Reflector();
        guard = new JwtAuthGuard(reflector);
    });

    describe('canActivate', () => {
        it('should return true for public routes', () => {
            const mockContext = {
                getHandler: jest.fn(),
                getClass: jest.fn(),
                switchToHttp: jest.fn(),
            } as unknown as ExecutionContext;

            jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);

            const result = guard.canActivate(mockContext);

            expect(result).toBe(true);
            expect(reflector.getAllAndOverride).toHaveBeenCalledWith(IS_PUBLIC_KEY, [
                mockContext.getHandler(),
                mockContext.getClass(),
            ]);
        });
    });
});
