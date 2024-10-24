import {
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from 'src/schemas/user.schema';
import { CreateUserWithEmailDto } from './dto/createUserDto';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { LoginUserWithEmailDto } from './dto/loginUserDto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async createUserWithEmail(payload: CreateUserWithEmailDto): Promise<User> {
    try {
      const newUser = await this.userModel.create(payload);
      return newUser;
    } catch (error) {
      this.logger.error('Error Creating User', error);
      throw new HttpException(
        { status: HttpStatus.INTERNAL_SERVER_ERROR, error },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async loginWithEmailAndPassword(
    payload: LoginUserWithEmailDto,
  ): Promise<{ access_token: string; refreshToken: string }> {
    try {
      const user = await this.userModel.findOne({ email: payload.email });

      if (!user) throw new UnauthorizedException();

      const isPasswordValid = await bcrypt.compare(
        payload.password,
        user.password,
      );
      if (!isPasswordValid) throw new UnauthorizedException();

      const tokenPayload = { sub: user._id, email: user.email };
      const access_token = await this.jwtService.signAsync(tokenPayload, {
        secret: process.env.JWT_SECRET,
        expiresIn: '15m',
      });
      const refreshToken = this.jwtService.sign(
        { sub: user._id, email: user.email },
        {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: '7d', // longer-lived refresh token
        },
      );
      await this.userModel.findByIdAndUpdate(user._id, {
        refreshToken,
      });

      return { access_token, refreshToken };
    } catch (error) {
      this.logger.error('Error Logging in user with email', error);
      throw new HttpException(
        { status: HttpStatus.INTERNAL_SERVER_ERROR, error },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async findAllUsers(): Promise<User[]> {
    try {
      const allUsers = await this.userModel.find();
      return allUsers;
    } catch (error) {
      this.logger.error('Error fetching all users', error);
      throw new HttpException(
        { status: HttpStatus.NOT_FOUND, error },
        HttpStatus.NOT_FOUND,
      );
    }
  }

  async generateRefreshToken(token: string) {
    if (!token) throw new UnauthorizedException('No refresh token');

    try {
      const payload = this.jwtService.verify(token, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      const user = await this.userModel.findById(payload.sub);
      if (!user || user.refreshToken !== token)
        throw new UnauthorizedException('Invalid token');

      const newAccessToken = this.jwtService.sign(
        { sub: user._id, email: user.email },
        {
          secret: process.env.JWT_SECRET,
          expiresIn: '15m',
        },
      );

      const newRefreshToken = this.jwtService.sign(
        { sub: user._id, email: user.email },
        {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: '7d',
        },
      );
      user.refreshToken = newRefreshToken;
      await user.save();

      return { access_token: newAccessToken, refreshToken: newRefreshToken };
    } catch (error) {
      throw new UnauthorizedException('Token verification failed');
    }
  }
}
