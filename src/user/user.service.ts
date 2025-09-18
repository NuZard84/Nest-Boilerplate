import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { PhonenumService } from 'src/auth/phonenum/phonenum.service';
import { RedisService } from 'src/redis/redis.service';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);
  constructor(
    private prisma: PrismaService,
    private phonenumService: PhonenumService,
    private redis: RedisService,
  ) {}

  async updateName(userId: string, name: string) {
    try {
      const user = await this.prisma.user.update({
        where: { id: userId },
        data: { name },
      });

      return user;
    } catch (error) {
      this.logger.error('Error updating name:', error);
      await this.prisma.handleDatabaseError(error, 'updateName');
      throw error;
    }
  }

  async validateExistingUserPhonenum(userId: string, phoneNumber: string) {
    try {
      const num = await this.phonenumService.normalizePhoneNum(phoneNumber);

      const currentUser = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (currentUser?.isPhoneVerified) {
        throw new BadRequestException(
          'User already has a verified phone number',
        );
      }

      const userWithPhone = await this.prisma.user.findFirst({
        where: {
          phoneNumber: num,
          id: { not: userId },
        },
      });

      if (userWithPhone) {
        throw new BadRequestException(
          'This phone number is already in use by another user',
        );
      }

      if (!currentUser) {
        throw new NotFoundException('User not found');
      }

      const user = await this.prisma.user.update({
        where: { id: userId },
        data: { phoneNumber: num },
      });

      return user;
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }

      this.logger.error('Error verifying existing user phone number:', error);
      await this.prisma.handleDatabaseError(
        error,
        'verifyExistingUserPhonenum',
      );
      throw error;
    }
  }
}
