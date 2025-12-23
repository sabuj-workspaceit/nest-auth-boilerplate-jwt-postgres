import { hashPassword, comparePassword, hashToken, compareToken } from './hash.util';
import * as bcrypt from 'bcrypt';

jest.mock('bcrypt');

describe('Hash Utilities', () => {
    const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('hashPassword', () => {
        it('should hash password with bcrypt', async () => {
            const password = 'TestPassword123!';
            const hashedPassword = 'hashed_password';

            mockBcrypt.hash.mockResolvedValue(hashedPassword as never);

            const result = await hashPassword(password);

            expect(result).toBe(hashedPassword);
            expect(bcrypt.hash).toHaveBeenCalledWith(password, 10);
        });
    });

    describe('comparePassword', () => {
        it('should return true for matching passwords', async () => {
            const password = 'TestPassword123!';
            const hashedPassword = 'hashed_password';

            mockBcrypt.compare.mockResolvedValue(true as never);

            const result = await comparePassword(password, hashedPassword);

            expect(result).toBe(true);
            expect(bcrypt.compare).toHaveBeenCalledWith(password, hashedPassword);
        });

        it('should return false for non-matching passwords', async () => {
            const password = 'TestPassword123!';
            const hashedPassword = 'hashed_password';

            mockBcrypt.compare.mockResolvedValue(false as never);

            const result = await comparePassword(password, hashedPassword);

            expect(result).toBe(false);
        });
    });

    describe('hashToken', () => {
        it('should hash token with bcrypt', async () => {
            const token = 'test-token-123';
            const hashedToken = 'hashed_token';

            mockBcrypt.hash.mockResolvedValue(hashedToken as never);

            const result = await hashToken(token);

            expect(result).toBe(hashedToken);
            expect(bcrypt.hash).toHaveBeenCalledWith(token, 10);
        });
    });

    describe('compareToken', () => {
        it('should return true for matching tokens', async () => {
            const token = 'test-token-123';
            const hashedToken = 'hashed_token';

            mockBcrypt.compare.mockResolvedValue(true as never);

            const result = await compareToken(token, hashedToken);

            expect(result).toBe(true);
            expect(bcrypt.compare).toHaveBeenCalledWith(token, hashedToken);
        });

        it('should return false for non-matching tokens', async () => {
            const token = 'test-token-123';
            const hashedToken = 'hashed_token';

            mockBcrypt.compare.mockResolvedValue(false as never);

            const result = await compareToken(token, hashedToken);

            expect(result).toBe(false);
        });
    });
});
