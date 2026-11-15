import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import type { Response } from 'express';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { MailService } from '../mail/mail.service';

const mockVerifyIdToken = jest.fn();

jest.mock('google-auth-library', () => ({
  OAuth2Client: jest.fn().mockImplementation(() => ({
    verifyIdToken: mockVerifyIdToken,
  })),
}));

jest.mock('bcrypt', () => ({
  hashSync: jest.fn().mockReturnValue('mocked_dummy_bcrypt_hash'),
  hash: jest.fn().mockResolvedValue('mocked_hashed_password'),
  compare: jest.fn().mockResolvedValue(true),
}));

jest.mock('sanitize-html', () => {
  return jest.fn().mockImplementation((text: string) => {
    return text.replace(/<[^>]*>/g, '');
  });
});

jest.mock('@nestjs/jwt', () => ({
  JwtService: jest.fn().mockImplementation(() => ({
    signAsync: jest.fn(),
    verifyAsync: jest.fn(),
  })),
}));

jest.mock('@nestjs/config', () => ({
  ConfigService: jest.fn().mockImplementation(() => ({
    get: jest.fn(),
    getOrThrow: jest.fn(),
  })),
}));

jest.mock('crypto', () => {
  const actualCrypto = jest.requireActual<typeof import('crypto')>('crypto');
  return {
    ...actualCrypto,
    randomBytes: jest.fn().mockReturnValue({
      toString: jest.fn().mockReturnValue('mocked_raw_refresh_token_base64url'),
    }),
  };
});

jest.mock('../prisma/prisma.service', () => ({
  PrismaService: jest.fn().mockImplementation(() => ({
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    refreshToken: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    passwordReset: {
      findUnique: jest.fn(),
      create: jest.fn(),
      deleteMany: jest.fn(),
    },
    $transaction: jest.fn(),
  })),
}));

jest.mock('../mail/mail.service', () => ({
  MailService: jest.fn().mockImplementation(() => ({
    sendPasswordReset: jest.fn(),
  })),
}));

const mockedBcrypt = jest.mocked(bcrypt);

type MockPrismaUser = {
  findUnique: jest.Mock;
  create: jest.Mock;
  update: jest.Mock;
};

type MockPrismaRefreshToken = {
  findUnique: jest.Mock;
  create: jest.Mock;
  update: jest.Mock;
  updateMany: jest.Mock;
};

type MockPrismaPasswordReset = {
  findUnique: jest.Mock;
  create: jest.Mock;
  deleteMany: jest.Mock;
};

type MockPrismaService = {
  user: MockPrismaUser;
  refreshToken: MockPrismaRefreshToken;
  passwordReset: MockPrismaPasswordReset;
  $transaction: jest.Mock;
};

type MockJwtService = {
  signAsync: jest.Mock;
  verifyAsync: jest.Mock;
};

type MockConfigService = {
  get: jest.Mock;
  getOrThrow: jest.Mock;
};

type MockMailService = {
  sendPasswordReset: jest.Mock;
};

type MockResponse = {
  cookie: jest.Mock;
  clearCookie: jest.Mock;
};

describe('AuthService', () => {
  let service: AuthService;
  let prismaMock: MockPrismaService;
  let jwtServiceMock: MockJwtService;
  let mailServiceMock: MockMailService;

  const createMockResponse = (): { res: Response; mockRes: MockResponse } => {
    const mockRes: MockResponse = {
      cookie: jest.fn(),
      clearCookie: jest.fn(),
    };
    return { res: mockRes as unknown as Response, mockRes };
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const prismaInstance: MockPrismaService = {
      user: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
      refreshToken: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
      },
      passwordReset: {
        findUnique: jest.fn(),
        create: jest.fn(),
        deleteMany: jest.fn(),
      },
      $transaction: jest
        .fn()
        .mockImplementation((promises: Promise<unknown>[]) =>
          Promise.all(promises),
        ),
    };

    const jwtInstance: MockJwtService = {
      signAsync: jest.fn(),
      verifyAsync: jest.fn(),
    };

    const configInstance: MockConfigService = {
      get: jest
        .fn()
        .mockImplementation((key: string, defaultValue?: string) => {
          if (key === 'REFRESH_TOKEN_TTL_DAYS') return '30';
          if (key === 'NODE_ENV') return 'test';
          if (key === 'GOOGLE_CLIENT_ID') return 'mock-google-client-id';
          if (key === 'FRONTEND_URL') return 'http://localhost:3000';
          return defaultValue;
        }),
      getOrThrow: jest.fn().mockImplementation((key: string) => {
        if (key === 'GOOGLE_CLIENT_ID') return 'mock-google-client-id';
        return `mocked-${key}`;
      }),
    };

    const mailInstance: MockMailService = {
      sendPasswordReset: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prismaInstance },
        { provide: JwtService, useValue: jwtInstance },
        { provide: ConfigService, useValue: configInstance },
        { provide: MailService, useValue: mailInstance },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prismaMock = prismaInstance;
    jwtServiceMock = jwtInstance;
    mailServiceMock = mailInstance;
  });

  describe('register', () => {
    it('deve normalizar o email com trim e lowercase ao registrar', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      prismaMock.user.create.mockResolvedValue({
        id: 'user-id-1',
        name: 'Carlos',
        email: 'carlos@example.com',
      });

      await service.register({
        name: 'Carlos',
        email: '  Carlos@Example.COM  ',
        password: 'password123',
      });

      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'carlos@example.com' },
        select: { id: true },
      });

      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: {
          name: 'Carlos',
          email: 'carlos@example.com',
          passwordHash: 'mocked_hashed_password',
        },
        select: {
          id: true,
          name: true,
          email: true,
        },
      });
    });

    it('deve sanitizar o nome removendo tags HTML (<b>Ana</b> → Ana)', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      prismaMock.user.create.mockResolvedValue({
        id: 'user-id-2',
        name: 'Ana',
        email: 'ana@example.com',
      });

      await service.register({
        name: '<b>Ana</b>',
        email: 'ana@example.com',
        password: 'password123',
      });

      expect(prismaMock.user.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ name: 'Ana' }),
        }),
      );
    });

    it('deve preservar "&" literal após sanitização ("A & B" → "A & B")', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      prismaMock.user.create.mockResolvedValue({
        id: 'user-id-3',
        name: 'A & B',
        email: 'ab@example.com',
      });

      await service.register({
        name: 'A & B',
        email: 'ab@example.com',
        password: 'password123',
      });

      expect(prismaMock.user.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ name: 'A & B' }),
        }),
      );
    });

    it('deve retornar apenas { id, name, email }, sem password_hash', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      prismaMock.user.create.mockResolvedValue({
        id: 'user-id-4',
        name: 'Maria',
        email: 'maria@example.com',
      });

      const result = await service.register({
        name: 'Maria',
        email: 'maria@example.com',
        password: 'password123',
      });

      const response = result;
      expect(response).toEqual({
        id: 'user-id-4',
        name: 'Maria',
        email: 'maria@example.com',
      });
      expect(response).not.toHaveProperty('password_hash');
      expect(response).not.toHaveProperty('passwordHash');
    });

    it('deve lançar BadRequestException quando o e-mail já existir (checagem prévia)', async () => {
      prismaMock.user.findUnique.mockResolvedValue({ id: 'existing-user-id' });

      await expect(
        service.register({
          name: 'Duplicado',
          email: 'dup@example.com',
          password: 'password123',
        }),
      ).rejects.toThrow(
        new BadRequestException('Não foi possível concluir o cadastro'),
      );
    });

    it('deve lançar BadRequestException quando o Prisma retornar P2002', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      prismaMock.user.create.mockRejectedValue(
        new Prisma.PrismaClientKnownRequestError('Unique constraint', {
          code: 'P2002',
          clientVersion: '5.0.0',
        }),
      );

      await expect(
        service.register({
          name: 'Corrida',
          email: 'race@example.com',
          password: 'password123',
        }),
      ).rejects.toThrow(
        new BadRequestException('Não foi possível concluir o cadastro'),
      );
    });

    it('deve lançar BadRequestException quando o nome ficar vazio após sanitização', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);

      await expect(
        service.register({
          name: '<script></script>',
          email: 'xss@example.com',
          password: 'password123',
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('login', () => {
    it('deve retornar { accessToken } com payload { sub } em login bem-sucedido', async () => {
      const { res } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'user-id-login',
        passwordHash: 'hashed_pw',
      });
      mockedBcrypt.compare.mockResolvedValue(true);
      prismaMock.refreshToken.create.mockResolvedValue({ id: 'rt-login' });
      jwtServiceMock.signAsync.mockResolvedValue('jwt_access_token');

      const result = await service.login(
        { email: 'user@example.com', password: 'correctpassword' },
        res,
      );

      expect(jwtServiceMock.signAsync).toHaveBeenCalledWith({
        sub: 'user-id-login',
      });
      expect(result).toEqual({ accessToken: 'jwt_access_token' });
      expect(result).not.toHaveProperty('refreshToken');
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") quando a senha estiver errada', async () => {
      const { res } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'user-id',
        passwordHash: 'hashed_pw',
      });
      mockedBcrypt.compare.mockResolvedValue(false);

      await expect(
        service.login({ email: 'user@example.com', password: 'wrong' }, res),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") e chamar bcrypt.compare com hash falso quando usuário não existir', async () => {
      const { res } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue(null);
      mockedBcrypt.compare.mockResolvedValue(false);

      await expect(
        service.login(
          { email: 'nonexistent@example.com', password: 'anypassword' },
          res,
        ),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      // bcrypt.compare DEVE ser chamado mesmo quando o usuário não existe (timing attack)
      expect(mockedBcrypt.compare).toHaveBeenCalledTimes(1);
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") e chamar bcrypt.compare quando usuário não tiver passwordHash (conta Google)', async () => {
      const { res } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'google-user-id',
        passwordHash: null,
      });
      mockedBcrypt.compare.mockResolvedValue(false);

      await expect(
        service.login(
          { email: 'googleuser@example.com', password: 'anypassword' },
          res,
        ),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(mockedBcrypt.compare).toHaveBeenCalledTimes(1);
    });
  });

  describe('refresh', () => {
    it('deve lançar UnauthorizedException("Sessão inválida") quando não houver cookie', async () => {
      const { res } = createMockResponse();

      await expect(service.refresh(undefined, res)).rejects.toThrow(
        new UnauthorizedException('Sessão inválida'),
      );
    });

    it('deve limpar o cookie e lançar UnauthorizedException("Sessão inválida") quando o token não for encontrado', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.refreshToken.findUnique.mockResolvedValue(null);

      await expect(service.refresh('invalid_raw_token', res)).rejects.toThrow(
        new UnauthorizedException('Sessão inválida'),
      );

      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'refresh_token',
        expect.objectContaining({ path: '/auth', httpOnly: true }),
      );
    });

    it('deve limpar o cookie e lançar UnauthorizedException("Sessão inválida") quando o token estiver expirado', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.refreshToken.findUnique.mockResolvedValue({
        id: 'rt-id',
        userId: 'user-id',
        isRevoked: false,
        expiresAt: new Date(Date.now() - 1000), // expirado há 1 segundo
      });

      await expect(service.refresh('expired_token', res)).rejects.toThrow(
        new UnauthorizedException('Sessão inválida'),
      );

      expect(mockRes.clearCookie).toHaveBeenCalled();
    });

    it('deve revogar TODOS os tokens do usuário e lançar UnauthorizedException quando o token já estiver revogado (roubo)', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.refreshToken.findUnique.mockResolvedValue({
        id: 'rt-stolen',
        userId: 'user-id-stolen',
        isRevoked: true,
        expiresAt: new Date(Date.now() + 1_000_000),
      });
      prismaMock.refreshToken.updateMany.mockResolvedValue({ count: 3 });

      await expect(service.refresh('stolen_token', res)).rejects.toThrow(
        new UnauthorizedException('Sessão inválida'),
      );

      expect(prismaMock.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: 'user-id-stolen' },
        data: { isRevoked: true },
      });
      expect(mockRes.clearCookie).toHaveBeenCalled();
    });

    it('deve rotacionar o token válido, setar novo cookie e retornar { accessToken }', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.refreshToken.findUnique.mockResolvedValue({
        id: 'rt-valid-id',
        userId: 'user-id-valid',
        isRevoked: false,
        expiresAt: new Date(Date.now() + 1_000_000_000),
      });
      prismaMock.refreshToken.update.mockResolvedValue({});
      prismaMock.refreshToken.create.mockResolvedValue({});
      jwtServiceMock.signAsync.mockResolvedValue('novo_jwt_access_token');

      const result = await service.refresh('valid_raw_refresh_token', res);

      expect(prismaMock.$transaction).toHaveBeenCalled();
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'mocked_raw_refresh_token_base64url',
        expect.objectContaining({ httpOnly: true, path: '/auth' }),
      );
      expect(jwtServiceMock.signAsync).toHaveBeenCalledWith({
        sub: 'user-id-valid',
      });

      // Retorna apenas { accessToken }
      expect(result).toEqual({ accessToken: 'novo_jwt_access_token' });
      expect(result).not.toHaveProperty('refreshToken');
    });
  });

  describe('logout', () => {
    it('deve realizar logout com cookie, revogar o token no banco e limpar o cookie', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.refreshToken.updateMany.mockResolvedValue({ count: 1 });

      const rawToken = 'cookie_refresh_token_logout';
      const expectedHash =
        'e987422844fdaad2a4b8e1ad419076b9c14130ab6b2d660380f69a8376ca6e3d';

      await service.logout(rawToken, res);

      expect(prismaMock.refreshToken.updateMany).toHaveBeenCalledWith({
        where: {
          hashedToken: expectedHash,
          isRevoked: false,
        },
        data: { isRevoked: true },
      });

      expect(mockRes.clearCookie).toHaveBeenCalledWith('refresh_token', {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/auth',
      });
    });

    it('deve realizar logout sem cookie, não consultar banco e limpar o cookie mesmo assim', async () => {
      const { res, mockRes } = createMockResponse();

      await service.logout(undefined, res);

      expect(prismaMock.refreshToken.updateMany).not.toHaveBeenCalled();
      expect(mockRes.clearCookie).toHaveBeenCalledWith('refresh_token', {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/auth',
      });
    });
  });

  describe('googleLogin', () => {
    it('deve lançar UnauthorizedException("Credenciais inválidas") quando o idToken for inválido', async () => {
      const { res } = createMockResponse();
      mockVerifyIdToken.mockRejectedValue(new Error('Invalid token'));

      await expect(
        service.googleLogin({ idToken: 'invalid_token' }, res),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(prismaMock.user.findUnique).not.toHaveBeenCalled();
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") quando email_verified for false', async () => {
      const { res } = createMockResponse();
      mockVerifyIdToken.mockResolvedValue({
        getPayload: () => ({
          sub: 'google-sub-unverified',
          email: 'unverified@example.com',
          email_verified: false,
        }),
      });

      await expect(
        service.googleLogin({ idToken: 'unverified_token' }, res),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(prismaMock.user.findUnique).not.toHaveBeenCalled();
    });

    it('deve autenticar usuário existente por googleId sem alterar senha nem chamar transação', async () => {
      const { res, mockRes } = createMockResponse();
      mockVerifyIdToken.mockResolvedValue({
        getPayload: () => ({
          sub: 'google-sub-existing',
          email: 'existing.google@example.com',
          email_verified: true,
          name: 'Existing Google User',
        }),
      });

      prismaMock.user.findUnique.mockResolvedValueOnce({
        id: 'user-google-existing-id',
      });
      prismaMock.refreshToken.create.mockResolvedValue({ id: 'rt-id' });
      jwtServiceMock.signAsync.mockResolvedValue('jwt_google_existing_token');

      const result = await service.googleLogin(
        { idToken: 'valid_google_token' },
        res,
      );

      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({
        where: { googleId: 'google-sub-existing' },
        select: { id: true },
      });
      expect(prismaMock.user.update).not.toHaveBeenCalled();
      expect(prismaMock.user.create).not.toHaveBeenCalled();
      expect(prismaMock.$transaction).not.toHaveBeenCalled();

      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'mocked_raw_refresh_token_base64url',
        expect.objectContaining({
          httpOnly: true,
          path: '/auth',
        }),
      );

      expect(jwtServiceMock.signAsync).toHaveBeenCalledWith({
        sub: 'user-google-existing-id',
      });
      expect(result).toEqual({ accessToken: 'jwt_google_existing_token' });
    });

    it('deve vincular por email quando não achar por googleId, zerando senha e revogando tokens em transação', async () => {
      const { res, mockRes } = createMockResponse();
      mockVerifyIdToken.mockResolvedValue({
        getPayload: () => ({
          sub: 'google-sub-link',
          email: '  Link.Account@Example.COM  ',
          email_verified: true,
          name: 'Link User',
        }),
      });

      // 1st lookup by googleId -> null
      prismaMock.user.findUnique.mockResolvedValueOnce(null);
      // 2nd lookup by email -> user exists
      prismaMock.user.findUnique.mockResolvedValueOnce({
        id: 'user-email-match-id',
      });

      prismaMock.refreshToken.create.mockResolvedValue({ id: 'rt-id' });
      jwtServiceMock.signAsync.mockResolvedValue('jwt_link_token');

      const result = await service.googleLogin(
        { idToken: 'valid_google_token' },
        res,
      );

      expect(prismaMock.user.findUnique).toHaveBeenNthCalledWith(1, {
        where: { googleId: 'google-sub-link' },
        select: { id: true },
      });

      expect(prismaMock.user.findUnique).toHaveBeenNthCalledWith(2, {
        where: { email: 'link.account@example.com' },
        select: { id: true },
      });

      // Transação: atualiza usuário (grava googleId e passwordHash: null) e revoga todos os tokens
      expect(prismaMock.$transaction).toHaveBeenCalledWith([
        prismaMock.user.update({
          where: { id: 'user-email-match-id' },
          data: {
            googleId: 'google-sub-link',
            passwordHash: null,
          },
        }),
        prismaMock.refreshToken.updateMany({
          where: { userId: 'user-email-match-id' },
          data: { isRevoked: true },
        }),
      ]);

      expect(jwtServiceMock.signAsync).toHaveBeenCalledWith({
        sub: 'user-email-match-id',
      });
      expect(mockRes.cookie).toHaveBeenCalled();
      expect(result).toEqual({ accessToken: 'jwt_link_token' });
    });

    it('deve criar novo usuário com passwordHash null quando não achar por googleId nem por email', async () => {
      const { res, mockRes } = createMockResponse();
      mockVerifyIdToken.mockResolvedValue({
        getPayload: () => ({
          sub: 'google-sub-new',
          email: 'new.google@example.com',
          email_verified: true,
          name: '<b>Brand</b> &amp; New',
        }),
      });

      prismaMock.user.findUnique.mockResolvedValueOnce(null);
      prismaMock.user.findUnique.mockResolvedValueOnce(null);
      prismaMock.user.create.mockResolvedValue({
        id: 'new-google-user-id',
      });
      prismaMock.refreshToken.create.mockResolvedValue({ id: 'rt-id' });
      jwtServiceMock.signAsync.mockResolvedValue('jwt_new_google_token');

      const result = await service.googleLogin(
        { idToken: 'valid_google_token' },
        res,
      );

      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: {
          name: 'Brand & New',
          email: 'new.google@example.com',
          googleId: 'google-sub-new',
          passwordHash: null,
        },
        select: { id: true },
      });

      expect(jwtServiceMock.signAsync).toHaveBeenCalledWith({
        sub: 'new-google-user-id',
      });
      expect(mockRes.cookie).toHaveBeenCalled();
      expect(result).toEqual({ accessToken: 'jwt_new_google_token' });
    });

    it('deve usar a parte local do e-mail quando o nome sanitizado for vazio ou menor que 2 caracteres', async () => {
      const { res } = createMockResponse();
      mockVerifyIdToken.mockResolvedValue({
        getPayload: () => ({
          sub: 'google-sub-localname',
          email: 'alice.wonder@example.com',
          email_verified: true,
          name: '<script></script>',
        }),
      });

      prismaMock.user.findUnique.mockResolvedValueOnce(null);
      prismaMock.user.findUnique.mockResolvedValueOnce(null);
      prismaMock.user.create.mockResolvedValue({
        id: 'alice-user-id',
      });
      prismaMock.refreshToken.create.mockResolvedValue({ id: 'rt-id' });
      jwtServiceMock.signAsync.mockResolvedValue('jwt_alice_token');

      await service.googleLogin({ idToken: 'valid_google_token' }, res);

      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: {
          name: 'alice.wonder',
          email: 'alice.wonder@example.com',
          googleId: 'google-sub-localname',
          passwordHash: null,
        },
        select: { id: true },
      });
    });
  });

  describe('forgotPassword', () => {
    const STATIC_MESSAGE =
      'Se o e-mail estiver cadastrado, você receberá as instruções.';

    it('deve retornar a mesma mensagem estática quando o e-mail existir e enviar e-mail', async () => {
      prismaMock.user.findUnique.mockResolvedValue({ id: 'user-fp-id' });
      prismaMock.passwordReset.deleteMany.mockResolvedValue({ count: 0 });
      prismaMock.passwordReset.create.mockResolvedValue({
        id: 'reset-record-id',
      });
      mailServiceMock.sendPasswordReset.mockResolvedValue(undefined);

      const result = await service.forgotPassword({
        email: 'user@example.com',
      });

      expect(result).toEqual({ message: STATIC_MESSAGE });

      // E-mail DEVE ser disparado (fire-and-forget)
      // Aguardar microtasks para o catch não suprimir o assert
      await Promise.resolve();
      expect(mailServiceMock.sendPasswordReset).toHaveBeenCalledTimes(1);
      const [toArg, urlArg] = mailServiceMock.sendPasswordReset.mock
        .calls[0] as [string, string];
      expect(toArg).toBe('user@example.com');
      expect(urlArg).toContain('/reset-password?token=');
      expect(urlArg).toContain('reset-record-id.');
    });

    it('deve retornar a mesma mensagem estática quando o e-mail NÃO existir e NÃO enviar e-mail', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      // bcrypt.hash descartável é chamado para manter custo parecido
      mockedBcrypt.hash.mockResolvedValue('dummy_hash');

      const result = await service.forgotPassword({
        email: 'nonexistent@example.com',
      });

      expect(result).toEqual({ message: STATIC_MESSAGE });
      await Promise.resolve();
      expect(mailServiceMock.sendPasswordReset).not.toHaveBeenCalled();
      // bcrypt.hash descartável deve ter sido chamado (equalizar custo)
      expect(mockedBcrypt.hash).toHaveBeenCalledWith('dummy-secret', 12);
    });

    it('deve apagar resets anteriores antes de criar o novo (link de uso único)', async () => {
      prismaMock.user.findUnique.mockResolvedValue({ id: 'user-fp-id2' });
      prismaMock.passwordReset.deleteMany.mockResolvedValue({ count: 1 });
      prismaMock.passwordReset.create.mockResolvedValue({ id: 'new-reset-id' });
      mailServiceMock.sendPasswordReset.mockResolvedValue(undefined);

      await service.forgotPassword({ email: 'user2@example.com' });

      expect(prismaMock.passwordReset.deleteMany).toHaveBeenCalledWith({
        where: { userId: 'user-fp-id2' },
      });
      expect(prismaMock.passwordReset.create).toHaveBeenCalled();
    });

    it('deve salvar o hashedToken (bcrypt) e expiresAt (+15 min) no banco, nunca o secret puro', async () => {
      prismaMock.user.findUnique.mockResolvedValue({ id: 'user-fp-id3' });
      prismaMock.passwordReset.deleteMany.mockResolvedValue({ count: 0 });
      prismaMock.passwordReset.create.mockResolvedValue({
        id: 'reset-id-3',
      });
      mockedBcrypt.hash.mockResolvedValue('bcrypt_hashed_secret');
      mailServiceMock.sendPasswordReset.mockResolvedValue(undefined);

      const before = Date.now();
      await service.forgotPassword({ email: 'user3@example.com' });
      const after = Date.now();

      const createCall = prismaMock.passwordReset.create.mock
        .calls[0] as Array<{
        data: { userId: string; hashedToken: string; expiresAt: Date };
      }>;
      const data = createCall[0].data;

      expect(data.hashedToken).toBe('bcrypt_hashed_secret');
      expect(data.expiresAt).toBeInstanceOf(Date);
      // expiresAt deve ser ~15 minutos no futuro
      const diffMs = data.expiresAt.getTime() - before;
      expect(diffMs).toBeGreaterThanOrEqual(14 * 60 * 1000);
      expect(diffMs).toBeLessThanOrEqual(after - before + 16 * 60 * 1000);
    });
  });

  describe('resetPassword', () => {
    const RESET_ERROR = new BadRequestException('Link inválido ou expirado');

    it('deve alterar senha, apagar todos os resets e revogar refresh tokens em transação no sucesso', async () => {
      const futureDate = new Date(Date.now() + 10 * 60 * 1000);
      prismaMock.passwordReset.findUnique.mockResolvedValue({
        id: 'reset-ok-id',
        userId: 'user-reset-id',
        hashedToken: 'hashed_secret_in_db',
        expiresAt: futureDate,
      });
      mockedBcrypt.compare.mockResolvedValue(true);
      mockedBcrypt.hash.mockResolvedValue('new_hashed_password');

      const result = await service.resetPassword({
        token: 'reset-ok-id.valid_secret',
        newPassword: 'NewPass123!',
      });

      expect(result).toEqual({ message: 'Senha alterada com sucesso.' });

      // $transaction com as 3 operações
      expect(prismaMock.$transaction).toHaveBeenCalledWith([
        prismaMock.user.update({
          where: { id: 'user-reset-id' },
          data: { passwordHash: 'new_hashed_password' },
        }),
        prismaMock.passwordReset.deleteMany({
          where: { userId: 'user-reset-id' },
        }),
        prismaMock.refreshToken.updateMany({
          where: { userId: 'user-reset-id' },
          data: { isRevoked: true },
        }),
      ]);
    });

    it('deve lançar BadRequestException("Link inválido ou expirado") para formato de token inválido (sem ponto)', async () => {
      await expect(
        service.resetPassword({
          token: 'tokenSemPonto',
          newPassword: 'NewPass123!',
        }),
      ).rejects.toThrow(RESET_ERROR);

      expect(prismaMock.passwordReset.findUnique).not.toHaveBeenCalled();
    });

    it('deve lançar BadRequestException("Link inválido ou expirado") quando o registro não for encontrado', async () => {
      prismaMock.passwordReset.findUnique.mockResolvedValue(null);

      await expect(
        service.resetPassword({
          token: 'nonexistent-id.some_secret',
          newPassword: 'NewPass123!',
        }),
      ).rejects.toThrow(RESET_ERROR);
    });

    it('deve lançar BadRequestException("Link inválido ou expirado") quando o token estiver expirado', async () => {
      prismaMock.passwordReset.findUnique.mockResolvedValue({
        id: 'expired-reset-id',
        userId: 'user-id',
        hashedToken: 'hashed_secret',
        expiresAt: new Date(Date.now() - 1000), // expirado
      });

      await expect(
        service.resetPassword({
          token: 'expired-reset-id.some_secret',
          newPassword: 'NewPass123!',
        }),
      ).rejects.toThrow(RESET_ERROR);
    });

    it('deve lançar BadRequestException("Link inválido ou expirado") quando o secret for inválido (bcrypt.compare falso)', async () => {
      prismaMock.passwordReset.findUnique.mockResolvedValue({
        id: 'valid-id',
        userId: 'user-id',
        hashedToken: 'hashed_secret',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      });
      mockedBcrypt.compare.mockResolvedValue(false);

      await expect(
        service.resetPassword({
          token: 'valid-id.wrong_secret',
          newPassword: 'NewPass123!',
        }),
      ).rejects.toThrow(RESET_ERROR);
    });

    it('deve falhar na segunda tentativa com o mesmo token (token já consumido)', async () => {
      // Primeira chamada bem-sucedida
      const futureDate = new Date(Date.now() + 10 * 60 * 1000);
      prismaMock.passwordReset.findUnique.mockResolvedValueOnce({
        id: 'one-time-id',
        userId: 'user-one-time',
        hashedToken: 'hashed_secret',
        expiresAt: futureDate,
      });
      mockedBcrypt.compare.mockResolvedValue(true);
      mockedBcrypt.hash.mockResolvedValue('new_hash');

      await service.resetPassword({
        token: 'one-time-id.valid_secret',
        newPassword: 'NewPass123!',
      });

      // Segunda tentativa — registro não existe mais (deleteMany foi chamado no $transaction)
      prismaMock.passwordReset.findUnique.mockResolvedValueOnce(null);

      await expect(
        service.resetPassword({
          token: 'one-time-id.valid_secret',
          newPassword: 'AnotherPass456!',
        }),
      ).rejects.toThrow(RESET_ERROR);
    });
  });
});
