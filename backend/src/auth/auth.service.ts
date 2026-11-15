import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import type { CookieOptions, Response } from 'express';
import { OAuth2Client, type TokenPayload } from 'google-auth-library';
import sanitizeHtml from 'sanitize-html';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { GoogleLoginDto } from './dto/google-login.dto';

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
  private readonly googleClient: OAuth2Client;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.googleClient = new OAuth2Client(
      this.configService.get<string>('GOOGLE_CLIENT_ID'),
    );
  }

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

  async login(dto: LoginDto, res: Response): Promise<LoginResponse> {
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

    return this.issueSessionTokens(user.id, res);
  }

  async refresh(
    rawRefreshToken: string | undefined,
    res: Response,
  ): Promise<LoginResponse> {
    // 1. Sem cookie → UnauthorizedException('Sessão inválida')
    if (!rawRefreshToken) {
      throw new UnauthorizedException('Sessão inválida');
    }

    // 2. Calcular SHA-256 e buscar por hashedToken
    const hashedToken = crypto
      .createHash('sha256')
      .update(rawRefreshToken)
      .digest('hex');

    const tokenRecord = await this.prisma.refreshToken.findUnique({
      where: { hashedToken },
    });

    // Não achou ou expirado → mesma exceção (e limpar cookie)
    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      this.clearRefreshTokenCookie(res);
      throw new UnauthorizedException('Sessão inválida');
    }

    // 3. Achou mas isRevoked = true (REUSO, possível roubo) → revogar TODOS os refresh tokens do usuário
    // (updateMany isRevoked = true), limpar cookie, mesma exceção.
    if (tokenRecord.isRevoked) {
      await this.prisma.refreshToken.updateMany({
        where: { userId: tokenRecord.userId },
        data: { isRevoked: true },
      });
      this.clearRefreshTokenCookie(res);
      throw new UnauthorizedException('Sessão inválida');
    }

    // 4. Válido → em uma prisma.$transaction: revogar o atual e criar o novo.
    // Setar o novo cookie e retornar { accessToken } novo.
    const newRawRefreshToken = crypto.randomBytes(48).toString('base64url');
    const newHashedToken = crypto
      .createHash('sha256')
      .update(newRawRefreshToken)
      .digest('hex');

    const expiresAt = this.getRefreshTokenExpiresAt();

    await this.prisma.$transaction([
      this.prisma.refreshToken.update({
        where: { id: tokenRecord.id },
        data: { isRevoked: true },
      }),
      this.prisma.refreshToken.create({
        data: {
          userId: tokenRecord.userId,
          hashedToken: newHashedToken,
          expiresAt,
        },
      }),
    ]);

    this.setRefreshTokenCookie(res, newRawRefreshToken);

    const accessToken = await this.jwtService.signAsync({
      sub: tokenRecord.userId,
    });

    return { accessToken };
  }

  async logout(
    rawRefreshToken: string | undefined,
    res: Response,
  ): Promise<void> {
    if (rawRefreshToken) {
      const hashedToken = crypto
        .createHash('sha256')
        .update(rawRefreshToken)
        .digest('hex');

      await this.prisma.refreshToken.updateMany({
        where: { hashedToken, isRevoked: false },
        data: { isRevoked: true },
      });
    }

    this.clearRefreshTokenCookie(res);
  }

  async googleLogin(
    dto: GoogleLoginDto,
    res: Response,
  ): Promise<LoginResponse> {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    let payload: TokenPayload | undefined;

    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken: dto.idToken,
        audience: clientId,
      });
      payload = ticket.getPayload();
    } catch {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    if (
      !payload ||
      typeof payload.email !== 'string' ||
      payload.email_verified !== true ||
      typeof payload.sub !== 'string'
    ) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    const normalizedEmail = payload.email.trim().toLowerCase();
    const googleId = payload.sub;

    const rawName = typeof payload.name === 'string' ? payload.name : '';
    let sanitizedName = sanitizeHtml(rawName.trim(), {
      allowedTags: [],
      allowedAttributes: {},
    })
      .replace(/&amp;/g, '&')
      .trim();

    if (sanitizedName.length < 2 || sanitizedName.length > 80) {
      const localPart = normalizedEmail.split('@')[0] ?? 'User';
      sanitizedName = localPart.slice(0, 80);
      if (sanitizedName.length < 2) {
        sanitizedName = 'User';
      }
    }

    // 1. Achou usuário por googleId (payload.sub) → segue para emitir tokens.
    const userByGoogleId = await this.prisma.user.findUnique({
      where: { googleId },
      select: { id: true },
    });

    if (userByGoogleId) {
      return this.issueSessionTokens(userByGoogleId.id, res);
    }

    // 2. Senão, achou por e-mail → em $transaction: gravar googleId, zerar passwordHash (null)
    // e revogar TODOS os refresh tokens desse usuário. Depois emitir tokens.
    const userByEmail = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
      select: { id: true },
    });

    if (userByEmail) {
      await this.prisma.$transaction([
        this.prisma.user.update({
          where: { id: userByEmail.id },
          data: {
            googleId,
            passwordHash: null,
          },
        }),
        this.prisma.refreshToken.updateMany({
          where: { userId: userByEmail.id },
          data: { isRevoked: true },
        }),
      ]);

      return this.issueSessionTokens(userByEmail.id, res);
    }

    // 3. Senão → criar usuário (passwordHash null, googleId, name, email).
    const newUser = await this.prisma.user.create({
      data: {
        name: sanitizedName,
        email: normalizedEmail,
        googleId,
        passwordHash: null,
      },
      select: { id: true },
    });

    return this.issueSessionTokens(newUser.id, res);
  }

  private async issueSessionTokens(
    userId: string,
    res: Response,
  ): Promise<LoginResponse> {
    const rawRefreshToken = crypto.randomBytes(48).toString('base64url');
    const hashedToken = crypto
      .createHash('sha256')
      .update(rawRefreshToken)
      .digest('hex');

    const expiresAt = this.getRefreshTokenExpiresAt();

    await this.prisma.refreshToken.create({
      data: {
        userId,
        hashedToken,
        expiresAt,
      },
    });

    this.setRefreshTokenCookie(res, rawRefreshToken);

    const accessToken = await this.jwtService.signAsync({ sub: userId });

    return { accessToken };
  }

  private getRefreshTokenExpiresAt(): Date {
    const ttlDays =
      Number(this.configService.get<string>('REFRESH_TOKEN_TTL_DAYS', '30')) ||
      30;
    return new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000);
  }

  private getCookieOptions(): CookieOptions {
    const ttlDays =
      Number(this.configService.get<string>('REFRESH_TOKEN_TTL_DAYS', '30')) ||
      30;
    const isProduction =
      this.configService.get<string>('NODE_ENV') === 'production';

    return {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/auth',
      maxAge: ttlDays * 24 * 60 * 60 * 1000,
    };
  }

  private setRefreshTokenCookie(res: Response, rawToken: string): void {
    res.cookie('refresh_token', rawToken, this.getCookieOptions());
  }

  private clearRefreshTokenCookie(res: Response): void {
    const isProduction =
      this.configService.get<string>('NODE_ENV') === 'production';

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/auth',
    });
  }
}
