import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginUserWithEmailDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
