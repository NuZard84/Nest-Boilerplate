import { IsString, IsNotEmpty } from 'class-validator';

export class VerifyNumberDto {
  @IsString()
  @IsNotEmpty()
  phoneNumber: string;
}
