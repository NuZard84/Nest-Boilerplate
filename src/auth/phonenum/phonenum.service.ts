import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as twilio from 'twilio';
import * as crypto from 'crypto';
import { RedisService } from 'src/redis/redis.service';
import { PrismaService } from 'prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class PhonenumService {
  private readonly logger = new Logger(PhonenumService.name);
  private readonly client: twilio.Twilio;

  private readonly MAX_ATTEMPTS = 3;
  private readonly OTP_TTL = 600;
  private readonly COOLDOWN_TTL = 60;
  private readonly OTP_LENGTH = 6;
  private readonly MAX_OTP_REQUESTS_PER_HOUR = 5;

  constructor(
    private redis: RedisService,
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {
    this.client = twilio.default(
      process.env.TWILIO_ACC_SID,
      process.env.TWILIO_AUTH_TOKEN,
    );
  }

  async normalizePhoneNum(phoneNum: string): Promise<string> {
    // Remove all spaces, dashes, parentheses, and other non-digit characters except +
    let cleaned = phoneNum.replace(/[\s\-\(\)\.]/g, '');

    if (cleaned.startsWith('+')) {
      return cleaned;
    }

    return `+${cleaned}`;
  }

  async generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
  }

  async isInCooldown(phoneNum: string) {
    const key = `cooldown:${phoneNum}`;
    return await this.redis.exists(key);
  }

  private async checkRateLimit(phoneNumber: string): Promise<void> {
    const rateLimitKey = `rate_limit:${phoneNumber}`;
    const currentCount = await this.redis.incr(rateLimitKey);

    if (currentCount === 1) {
      await this.redis.expire(rateLimitKey, 3600);
    }

    if (currentCount > this.MAX_OTP_REQUESTS_PER_HOUR) {
      throw new BadRequestException(
        `Too many OTP requests. Maximum ${this.MAX_OTP_REQUESTS_PER_HOUR} requests per hour allowed.`,
      );
    }
  }

  async sendOTP(
    phoneNumber: string,
  ): Promise<{ success: boolean; message: string; normalizedPhone?: string }> {
    try {
      const num = await this.normalizePhoneNum(phoneNumber);

      if (await this.isInCooldown(num)) {
        return {
          success: false,
          message: 'Too many requests. Please try again later.',
        };
      }

      await this.checkRateLimit(num);

      const otp = await this.generateOTP();

      await this.redis.set(`otp:${num}`, otp, this.OTP_TTL);

      const cooldownKey = `cooldown:${num}`;
      await this.redis.set(cooldownKey, '1', this.COOLDOWN_TTL);

      const attemptKey = `attempts:${num}`;
      await this.redis.del(attemptKey);

      const sms = await this.client.messages.create({
        to: num,
        from: process.env.TWILIO_PHONE_NUMBER,
        body: `Here is your OTP from Upayee ${otp} to authorize your account. This code will expire in 10 minutes. Do not share this with anyone.`,
      });

      this.logger.log(`OTP sent to ${num}: ${otp}`);

      return {
        success: true,
        message: 'OTP sent successfully',
        normalizedPhone: num,
      };
    } catch (error) {
      this.logger.error('Error sending OTP:', error);

      if (
        error instanceof BadRequestException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      // handle Twilio-specific errors
      if (error.code) {
        switch (error.code) {
          case 21211:
            throw new BadRequestException('Invalid phone number format');
          case 21614:
            throw new BadRequestException(
              'Phone number is not a valid mobile number',
            );
          case 21408:
            throw new BadRequestException(
              'Permission to send SMS to this number is denied',
            );
          case 21610:
            throw new BadRequestException(
              'Phone number is not verified (trial account)',
            );
          default:
            throw new BadRequestException(
              `SMS delivery failed: ${error.message}`,
            );
        }
      }

      throw new BadRequestException('Failed to send OTP. Please try again.');
    }
  }

  async verifyOTP(
    phoneNumber: string,
    otp: string,
  ): Promise<{ user: any; accessToken: string; refreshToken: string }> {
    try {
      const num = await this.normalizePhoneNum(phoneNumber);

      // check attempt limit
      const attemptKey = `attempts:${num}`;
      const attempts = await this.redis.get(attemptKey);
      const attemptCount = attempts ? parseInt(attempts) : 0;

      if (attemptCount >= this.MAX_ATTEMPTS) {
        throw new BadRequestException(
          'Too many failed attempts. Please request a new OTP.',
        );
      }

      const storedOTP = await this.redis.get(`otp:${num}`);

      if (!storedOTP) {
        throw new BadRequestException(
          'OTP expired or not found. Please request a new one.',
        );
      }

      if (storedOTP !== otp) {
        await this.redis.incr(attemptKey);
        await this.redis.expire(attemptKey, this.OTP_TTL);
        throw new BadRequestException('Invalid OTP. Please try again.');
      }

      await this.redis.del(`otp:${num}`);
      await this.redis.del(attemptKey);

      let user = await this.prisma.user.findUnique({
        where: { phoneNumber: num },
      });

      if (!user) {
        user = await this.prisma.user.create({
          data: {
            phoneNumber: num,
            isPhoneVerified: true,
          },
        });
        this.logger.log(`New user created with phone: ${num}`);
      } else {
        await this.prisma.user.update({
          where: { id: user.id },
          data: { isPhoneVerified: true },
        });
      }

      const payload = {
        sub: user.id,
        email: user.email ?? null,
        phoneNumber: user.phoneNumber ?? null,
        isPhoneVerified: user.isPhoneVerified ?? false,
      };

      const accessToken = this.jwtService.sign(payload, {
        expiresIn: String(process.env.EXPIRE_ACCESS_TOKEN),
      });
      const refreshToken = this.jwtService.sign(payload, {
        expiresIn: String(process.env.EXPIRE_REFRESH_TOKEN),
      });

      await this.prisma.user.update({
        where: { id: user.id },
        data: { refreshToken },
      });

      this.logger.log(`User authenticated via phone: ${num}`);

      return { user, accessToken, refreshToken };
    } catch (error) {
      this.logger.error('Error verifying OTP:', error);

      if (
        error instanceof BadRequestException ||
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException
      ) {
        throw error;
      }

      throw new BadRequestException(
        'OTP verification failed. Please try again.',
      );
    }
  }

  async resendOTP(
    phoneNumber: string,
  ): Promise<{ success: boolean; message: string }> {
    try {
      const num = await this.normalizePhoneNum(phoneNumber);

      if (await this.isInCooldown(num)) {
        throw new BadRequestException(
          'Too many requests. Please try again later.',
        );
      }

      await this.checkRateLimit(num);

      const otp = await this.generateOTP();

      await this.redis.set(`otp:${num}`, otp, this.OTP_TTL);

      const cooldownKey = `cooldown:${num}`;
      await this.redis.set(cooldownKey, '1', this.COOLDOWN_TTL);

      const sms = await this.client.messages.create({
        body: `Here is your OTP from Upayee ${otp} to authorize your account. This code will expire in 10 minutes. Do not share this with anyone.`,
        to: num,
        from: process.env.TWILIO_PHONE_NUMBER,
      });

      this.logger.log(`OTP resent to ${num}: ${otp}`);

      return {
        success: true,
        message: 'OTP resent successfully',
      };
    } catch (error) {
      this.logger.error('Error resending OTP:', error);

      if (
        error instanceof BadRequestException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      throw new BadRequestException('Failed to resend OTP. Please try again.');
    }
  }
}
