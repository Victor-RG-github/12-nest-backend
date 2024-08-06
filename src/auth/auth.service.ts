import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { SignInDto } from './dto/sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from './interfaces/jwt-payload.interface';
import { SignInResponse } from './interfaces/sign-in-response.interface';
import { RegisterDTO } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      //Desestructuramos
      const { password, ...userData } = createUserDto;
      //Encriptamos el password y transformamos a documento.
      const newUser = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData,
      });

      // Guarda el document y devuelve una promesa
      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} ya existe`);
      }
      throw new InternalServerErrorException('Error no controlado');
    }
  }

  async register(registerDTO: RegisterDTO): Promise<SignInResponse> {
    const { email } = await this.create({ ...registerDTO });
    return this.signIn({ email, password: registerDTO.password });
  }

  async signIn(signInDto: SignInDto): Promise<SignInResponse> {
    console.log(signInDto);
    const { email, password } = signInDto;
    const user = await this.userModel.findOne({ email });

    if (!user) throw new UnauthorizedException('Credenciales no válidas');

    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('Credenciales no válidas');
    }

    const { password: _, ...validUser } = user.toJSON();
    const token = await this.getJWTToken({ id: user.id });

    //return { ...validUser, token }; //Otra forma
    return { user: validUser, token };
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  private getJWTToken(payload: JWTPayload) {
    return this.jwtService.signAsync(payload, {
      secret: process.env.JWT_SEED,
      expiresIn: '60s',
    });
  }
}
