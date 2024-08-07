import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { SignInDto } from './dto/sign-in.dto';
import { RegisterUserDTO } from './dto/register-user.dto';
import { AuthGuard } from './guards/auth/auth.guard';
import { User } from './entities/user.entity';
import { SignInResponse } from './interfaces/sign-in-response.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/sign-in')
  signIn(@Body() signInDTO: SignInDto) {
    return this.authService.signIn(signInDTO);
  }

  @Post('/register')
  register(@Body() registerDTO: RegisterUserDTO) {
    return this.authService.register(registerDTO);
  }

  @Get('/check-token')
  @UseGuards(AuthGuard)
  checkToken(@Request() req: Request): SignInResponse {
    const user = req['user'] as User;
    return {
      user,
      token: this.authService.getJWTToken({ id: user._id }),
    };
  }

  @Get()
  @UseGuards(AuthGuard)
  findAll(@Request() request: Request) {
    return this.authService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.authService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.authService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
