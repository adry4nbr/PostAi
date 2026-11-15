import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import sanitizeHtml from 'sanitize-html';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

export interface RegisterResponse {
  id: string;
  name: string;
  email: string;
}

export interface LoginResponse {
  accessToken: string;
}

// Hash bcrypt de custo 12 gerado na inicialização para comparação em tempo constante
// quando o usuário não existe ou não possui senha (ex: conta criada via Google).
const DUMMY_BCRYPT_HASH = bcrypt.hashSync('dummy-password', 12);

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto): Promise<RegisterResponse> {
    const normalizedEmail = dto.email.trim().toLowerCase();

    // Sanitização contra XSS removendo quaisquer tags ou atributos HTML
    const sanitizedName = sanitizeHtml(dto.name.trim(), {
      allowedTags: [],
      allowedAttributes: {},
    })
      .replace(/&amp;/g, '&')
      .trim();

    if (sanitizedName.length < 2 || sanitizedName.length > 80) {
      throw new BadRequestException('O nome deve ter entre 2 e 80 caracteres');
    }

    // Hash de senha com bcrypt cost factor 12 executado antes da checagem
    // para equalizar a latência e mitigar enumeração de contas via timing attack.
    const passwordHash = await bcrypt.hash(dto.password, 12);

    const existingUser = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
      select: { id: true },
    });

    if (existingUser) {
      throw new BadRequestException('Não foi possível concluir o cadastro');
    }

    try {
      const user = await this.prisma.user.create({
        data: {
          name: sanitizedName,
          email: normalizedEmail,
          passwordHash,
        },
        select: {
          id: true,
          name: true,
          email: true,
        },
      });

      return user;
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new BadRequestException('Não foi possível concluir o cadastro');
      }
      throw error;
    }
  }

  async login(dto: LoginDto): Promise<LoginResponse> {
    const normalizedEmail = dto.email.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
      select: {
        id: true,
        passwordHash: true,
      },
    });

    // Se o usuário não existir ou não tiver passwordHash (conta Google),
    // executa bcrypt.compare contra um hash falso para igualar a latência da resposta
    // e prevenir enumeração de contas via timing attack.
    const hashToCompare = user?.passwordHash ?? DUMMY_BCRYPT_HASH;
    const isPasswordValid = await bcrypt.compare(dto.password, hashToCompare);

    if (!user || !user.passwordHash || !isPasswordValid) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    const accessToken = await this.jwtService.signAsync({ sub: user.id });

    return { accessToken };
  }
}
