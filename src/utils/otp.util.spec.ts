import { generateOTP } from './otp.util';

describe('OTP Utilities', () => {
    describe('generateOTP', () => {
        it('should generate a 6-digit OTP', () => {
            const otp = generateOTP();

            expect(otp).toHaveLength(6);
            expect(otp).toMatch(/^\d{6}$/);
        });

        it('should generate different OTPs on multiple calls', () => {
            const otp1 = generateOTP();
            const otp2 = generateOTP();
            const otp3 = generateOTP();

            // While it's theoretically possible for two OTPs to be the same,
            // it's extremely unlikely with 1,000,000 possible combinations
            const otps = new Set([otp1, otp2, otp3]);
            expect(otps.size).toBeGreaterThan(1);
        });

        it('should generate OTP within valid range', () => {
            const otp = generateOTP();
            const otpNumber = parseInt(otp, 10);

            expect(otpNumber).toBeGreaterThanOrEqual(100000);
            expect(otpNumber).toBeLessThanOrEqual(999999);
        });
    });
});
