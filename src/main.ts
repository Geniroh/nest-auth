import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DuplicateKeyExceptionFilter } from './middleware/customDuplicateErrorFilter';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
  app.useGlobalFilters(new DuplicateKeyExceptionFilter());
  app.use(cookieParser());
  await app.listen(8080);
}
bootstrap();
