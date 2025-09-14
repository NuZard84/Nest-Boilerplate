import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { Throttle } from '@nestjs/throttler';

@Controller('user')
export class UserController {
  @Get('me')
  @UseGuards(JwtAuthGuard) // protect this route
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  getProfile(@Req() req) {
    // req.user comes from JwtStrategy.validate
    return {
      message: 'This is a protected route!',
      user: req.user,
    };
  }
}
