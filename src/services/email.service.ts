import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailService {
    private transporter: nodemailer.Transporter;

    constructor(private configService: ConfigService) {
        this.transporter = nodemailer.createTransport({
            host: this.configService.get<string>('MAIL_HOST'),
            port: this.configService.get<number>('MAIL_PORT'),
            auth: {
                user: this.configService.get<string>('MAIL_USER'),
                pass: this.configService.get<string>('MAIL_PASSWORD'),
            },
        });
    }

    async sendVerificationEmail(
        email: string,
        otp: string,
        token: string,
    ): Promise<void> {
        const verificationUrl = `${this.configService.get<string>('APP_URL')}/auth/verify-email?token=${token}`;

        await this.transporter.sendMail({
            from: `"${this.configService.get<string>('MAIL_FROM_NAME')}" <${this.configService.get<string>('MAIL_FROM')}>`,
            to: email,
            subject: 'Verify Your Email Address',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Email Verification</h2>
          <p>Thank you for registering! Please verify your email address.</p>
          
          <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0;">Your Verification Code:</h3>
            <p style="font-size: 32px; font-weight: bold; color: #4CAF50; letter-spacing: 5px; margin: 10px 0;">${otp}</p>
            <p style="color: #666; font-size: 14px;">This code will expire in 10 minutes.</p>
          </div>
          
          <p>Alternatively, you can click the button below to verify your email:</p>
          
          <a href="${verificationUrl}" 
             style="display: inline-block; background-color: #4CAF50; color: white; padding: 12px 30px; 
                    text-decoration: none; border-radius: 5px; margin: 20px 0;">
            Verify Email
          </a>
          
          <p style="color: #666; font-size: 12px; margin-top: 30px;">
            If you didn't create an account, please ignore this email.
          </p>
        </div>
      `,
        });
    }

    async sendPasswordResetEmail(
        email: string,
        otp: string,
        token: string,
    ): Promise<void> {
        const resetUrl = `${this.configService.get<string>('APP_URL')}/auth/reset-password?token=${token}`;

        await this.transporter.sendMail({
            from: `"${this.configService.get<string>('MAIL_FROM_NAME')}" <${this.configService.get<string>('MAIL_FROM')}>`,
            to: email,
            subject: 'Reset Your Password',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>We received a request to reset your password.</p>
          
          <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0;">Your Reset Code:</h3>
            <p style="font-size: 32px; font-weight: bold; color: #FF5722; letter-spacing: 5px; margin: 10px 0;">${otp}</p>
            <p style="color: #666; font-size: 14px;">This code will expire in 1 hour.</p>
          </div>
          
          <p>Alternatively, you can click the button below to reset your password:</p>
          
          <a href="${resetUrl}" 
             style="display: inline-block; background-color: #FF5722; color: white; padding: 12px 30px; 
                    text-decoration: none; border-radius: 5px; margin: 20px 0;">
            Reset Password
          </a>
          
          <p style="color: #666; font-size: 12px; margin-top: 30px;">
            If you didn't request a password reset, please ignore this email or contact support if you have concerns.
          </p>
        </div>
      `,
        });
    }

    async sendWelcomeEmail(email: string, firstName: string): Promise<void> {
        await this.transporter.sendMail({
            from: `"${this.configService.get<string>('MAIL_FROM_NAME')}" <${this.configService.get<string>('MAIL_FROM')}>`,
            to: email,
            subject: 'Welcome to NestAuth!',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Welcome, ${firstName}!</h2>
          <p>Your email has been successfully verified.</p>
          <p>You can now access all features of your account.</p>
          
          <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0;">Getting Started</h3>
            <ul style="color: #666;">
              <li>Complete your profile</li>
              <li>Explore our features</li>
              <li>Connect with others</li>
            </ul>
          </div>
          
          <p style="color: #666; font-size: 12px; margin-top: 30px;">
            If you have any questions, feel free to contact our support team.
          </p>
        </div>
      `,
        });
    }

    async sendPasswordChangedEmail(
        email: string,
        firstName: string,
    ): Promise<void> {
        await this.transporter.sendMail({
            from: `"${this.configService.get<string>('MAIL_FROM_NAME')}" <${this.configService.get<string>('MAIL_FROM')}>`,
            to: email,
            subject: 'Password Changed Successfully',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Changed</h2>
          <p>Hello ${firstName},</p>
          <p>Your password has been successfully changed.</p>
          
          <div style="background-color: #fff3cd; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
            <p style="margin: 0; color: #856404;">
              <strong>Security Notice:</strong> If you didn't make this change, please contact our support team immediately.
            </p>
          </div>
          
          <p style="color: #666; font-size: 12px; margin-top: 30px;">
            This is an automated security notification.
          </p>
        </div>
      `,
        });
    }
}
