import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { PhonenumService } from './phonenum/phonenum.service';
import { Throttle } from '@nestjs/throttler';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';

@Controller('api/auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private phonenumService: PhonenumService,
  ) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  googleLogin() {}

  @Get('callback/google')
  @UseGuards(AuthGuard('google'))
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  googleCallback(@Req() req) {
    return req.user;
  }

  @Post('refresh')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async refresh(@Body() body: RefreshTokenDto) {
    try {
      const tokens = await this.authService.refreshAccessToken(
        body.refreshToken,
      );
      if (!tokens) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      return tokens;
    } catch (error) {
      throw new UnauthorizedException('Token refresh failed');
    }
  }

  @Post('phone/send-otp')
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  async sendOtp(@Body() body: SendOtpDto) {
    return await this.phonenumService.sendOTP(body.phoneNumber);
  }

  @Post('phone/verify-otp')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async verifyOtp(@Body() body: VerifyOtpDto) {
    return await this.phonenumService.verifyOTP(body.phoneNumber, body.otp);
  }

  @Post('phone/resend-otp')
  @Throttle({ default: { limit: 2, ttl: 60000 } })
  async resendOtp(@Body() body: ResendOtpDto) {
    return await this.phonenumService.resendOTP(body.phoneNumber);
  }
}
