import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import * as bcrypt from 'bcryptjs';

export type UserDocument = HydratedDocument<User>;

@Schema()
export class User {
  @Prop({
    lowercase: true,
  })
  firstName: string;

  @Prop({
    lowercase: true,
  })
  lastName: string;

  @Prop({
    lowercase: true,
    required: true,
    unique: true,
  })
  email: string;

  @Prop()
  phoneNumber: string;

  @Prop()
  password: string;

  @Prop()
  role: string;

  @Prop()
  refreshToken: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Hash password before saving
UserSchema.pre<UserDocument>('save', async function (next) {
  if (this.password) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});
