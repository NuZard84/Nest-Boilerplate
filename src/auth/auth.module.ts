import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auh.controller';
import { GoogleStrategy } from './google/google.strategy';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';
import { PhonenumService } from './phonenum/phonenum.service';
import { RedisModule } from 'src/redis/redis.module';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: {
        expiresIn: String(process.env.EXPIRE_ACCESS_TOKEN),
      },
    }),
    RedisModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, GoogleStrategy, JwtStrategy, PhonenumService],
  exports: [PhonenumService],
})
export class AuthModule {}
