import { User } from '../entities/user.entity';

export interface SignInResponse {
  user: User;
  token: string;
}
