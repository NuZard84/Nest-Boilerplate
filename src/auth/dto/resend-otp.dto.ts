import { IsString, IsNotEmpty } from 'class-validator';

export class ResendOtpDto {
  @IsString()
  @IsNotEmpty()
  phoneNumber: string;
}


