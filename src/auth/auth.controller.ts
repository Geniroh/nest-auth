import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserWithEmailDto } from './dto/createUserDto';
import { User } from 'src/schemas/user.schema';
import { LoginUserWithEmailDto } from './dto/loginUserDto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signUpUser(@Body() payload: CreateUserWithEmailDto): Promise<User> {
    return this.authService.createUserWithEmail(payload);
  }

  @Post('login')
  async sigInUser(
    @Body() payload: LoginUserWithEmailDto,
    @Res() response: Response,
  ) {
    const { access_token, refreshToken } =
      await this.authService.loginWithEmailAndPassword(payload);

    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      // secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return response.json({ access_token });
  }

  @Get('refresh')
  async refreshToken(@Req() request, @Res() response) {
    const token = request.cookies['refreshToken'];

    const { access_token, refreshToken } =
      await this.authService.generateRefreshToken(token);

    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      // secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return response.json({ access_token });
  }
}
