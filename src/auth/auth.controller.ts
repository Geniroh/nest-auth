import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  // UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserWithEmailDto } from './dto/createUserDto';
import { User } from 'src/schemas/user.schema';
import { LoginUserWithEmailDto } from './dto/loginUserDto';
import { Response } from 'express';
import { lastValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
// import { AuthGuard } from './guard/auth.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly httpService: HttpService,
  ) {}

  @Post('signup')
  async signUpUser(@Body() payload: CreateUserWithEmailDto): Promise<User> {
    return this.authService.createUserWithEmail(payload);
  }

  @Get('signup/google')
  async signUpWithGoogle(@Res() res: Response) {
    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth`;
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const redirectUri = process.env.GOOGLE_REDIRECT_URL;
    const scope = 'profile email';
    const responseType = 'code';

    const authUrl = `${googleAuthUrl}?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=${responseType}&scope=${scope}`;

    return res.redirect(authUrl);
  }

  @Get('google/callback')
  async googleAuthCallback(@Query('code') code: string, @Res() res: Response) {
    if (!code) {
      return res.status(400).send('Authorization code not provided');
    }

    try {
      // Exchange the authorization code for access and refresh tokens
      const tokenResponse = await lastValueFrom(
        this.httpService.post('https://oauth2.googleapis.com/token', null, {
          params: {
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            code,
            grant_type: 'authorization_code',
            redirect_uri: process.env.GOOGLE_REDIRECT_URL,
          },
        }),
      );

      // Log the data received from Google
      console.log('Token Response:', tokenResponse.data);

      // Optionally, you could redirect or respond with a success message
      return res
        .status(200)
        .json({ message: 'Google authentication successful' });
    } catch (error) {
      console.error('Error during Google callback:', error);
      return res
        .status(500)
        .json({ message: 'Failed to authenticate with Google' });
    }
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

// // In AuthService
// async googleLogin(tokenResponse: any): Promise<{ access_token: string; refreshToken: string }> {
//   try {
//     // 1. Use Google token to retrieve user info
//     const { data: userInfo } = await lastValueFrom(
//       this.httpService.get('https://www.googleapis.com/oauth2/v2/userinfo', {
//         headers: { Authorization: `Bearer ${tokenResponse.access_token}` },
//       }),
//     );

//     // 2. Check if user exists
//     let user = await this.userModel.findOne({ email: userInfo.email });

//     // 3. Create new user if they don't exist
//     if (!user) {
//       user = await this.userModel.create({
//         email: userInfo.email,
//         firstName: userInfo.given_name,
//         lastName: userInfo.family_name,
//         // Set a default or random password, ideally hashed
//         password: await bcrypt.hash('defaultPasswordOrRandomString', 10),
//       });
//     }

//     // 4. Issue JWT and refresh tokens
//     const tokenPayload = { sub: user._id, email: user.email };
//     const access_token = await this.jwtService.signAsync(tokenPayload, {
//       secret: process.env.JWT_SECRET,
//       expiresIn: '15m',
//     });
//     const refreshToken = await this.jwtService.signAsync(tokenPayload, {
//       secret: process.env.JWT_REFRESH_SECRET,
//       expiresIn: '7d',
//     });

//     // Optionally, store the refresh token in the database
//     user.refreshToken = refreshToken;
//     await user.save();

//     return { access_token, refreshToken };
//   } catch (error) {
//     throw new HttpException('Google login failed', HttpStatus.UNAUTHORIZED);
//   }
// }
