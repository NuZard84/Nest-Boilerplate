import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { AuthModule } from '../auth/auth.module';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { UnauthorizedException } from '@nestjs/common';

@Module({
  imports: [AuthModule],
  controllers: [UserController],
})
export class UserModule {}
