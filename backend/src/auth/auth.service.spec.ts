import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import type { Response } from 'express';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { AuthService, RegisterResponse } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';

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
    $transaction: jest.fn(),
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

type MockPrismaService = {
  user: MockPrismaUser;
  refreshToken: MockPrismaRefreshToken;
  $transaction: jest.Mock;
};

type MockJwtService = {
  signAsync: jest.Mock;
  verifyAsync: jest.Mock;
};

type MockConfigService = {
  get: jest.Mock;
};

type MockResponse = {
  cookie: jest.Mock;
  clearCookie: jest.Mock;
};

describe('AuthService', () => {
  let service: AuthService;
  let prismaMock: MockPrismaService;
  let jwtServiceMock: MockJwtService;
  let configServiceMock: MockConfigService;

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
          return defaultValue;
        }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prismaInstance },
        { provide: JwtService, useValue: jwtInstance },
        { provide: ConfigService, useValue: configInstance },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prismaMock = prismaInstance;
    jwtServiceMock = jwtInstance;
    configServiceMock = configInstance;
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

    it('deve sanitizar tags HTML do nome ("<b>Ana</b>" vira "Ana")', async () => {
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

      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: {
          name: 'Ana',
          email: 'ana@example.com',
          passwordHash: 'mocked_hashed_password',
        },
        select: {
          id: true,
          name: true,
          email: true,
        },
      });
    });

    it('deve preservar o caractere & no nome ("A & B" continua "A & B")', async () => {
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

      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: {
          name: 'A & B',
          email: 'ab@example.com',
          passwordHash: 'mocked_hashed_password',
        },
        select: {
          id: true,
          name: true,
          email: true,
        },
      });
    });

    it('deve retornar apenas { id, name, email } no cadastro', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      prismaMock.user.create.mockResolvedValue({
        id: 'user-id-4',
        name: 'Bruno',
        email: 'bruno@example.com',
      });

      const result: RegisterResponse = await service.register({
        name: 'Bruno',
        email: 'bruno@example.com',
        password: 'password123',
      });

      expect(result).toEqual({
        id: 'user-id-4',
        name: 'Bruno',
        email: 'bruno@example.com',
      });
      expect(result).not.toHaveProperty('passwordHash');
    });

    it('deve lançar BadRequestException("Não foi possível concluir o cadastro") quando email já existir', async () => {
      prismaMock.user.findUnique.mockResolvedValue({ id: 'existing-id' });

      await expect(
        service.register({
          name: 'Usuario Existente',
          email: 'existente@example.com',
          password: 'password123',
        }),
      ).rejects.toThrow(
        new BadRequestException('Não foi possível concluir o cadastro'),
      );

      expect(prismaMock.user.create).not.toHaveBeenCalled();
    });

    it('deve lançar BadRequestException("Não foi possível concluir o cadastro") em caso de erro P2002 do Prisma', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      const prismaError = new Prisma.PrismaClientKnownRequestError(
        'Unique constraint violation',
        {
          code: 'P2002',
          clientVersion: '6.0.0',
        },
      );
      prismaMock.user.create.mockRejectedValue(prismaError);

      await expect(
        service.register({
          name: 'Usuario Concorrente',
          email: 'concorrente@example.com',
          password: 'password123',
        }),
      ).rejects.toThrow(
        new BadRequestException('Não foi possível concluir o cadastro'),
      );
    });

    it('deve lançar BadRequestException quando o nome for vazio após sanitização', async () => {
      await expect(
        service.register({
          name: '<b></b>',
          email: 'teste@example.com',
          password: 'password123',
        }),
      ).rejects.toThrow(
        new BadRequestException('O nome deve ter entre 2 e 80 caracteres'),
      );

      expect(prismaMock.user.findUnique).not.toHaveBeenCalled();
      expect(prismaMock.user.create).not.toHaveBeenCalled();
    });
  });

  describe('login', () => {
    it('deve realizar login com sucesso, assinar JWT apenas com sub, salvar hash do refresh token e setar cookie com flags corretas', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'user-id-5',
        passwordHash: 'real_stored_hash',
      });
      prismaMock.refreshToken.create.mockResolvedValue({
        id: 'refresh-token-id',
      });
      mockedBcrypt.compare.mockResolvedValue(true as never);
      jwtServiceMock.signAsync.mockResolvedValue('jwt_access_token_mock');

      const result = await service.login(
        {
          email: '  Login.User@Example.COM  ',
          password: 'correct_password',
        },
        res,
      );

      expect(prismaMock.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'login.user@example.com' },
        select: {
          id: true,
          passwordHash: true,
        },
      });
      expect(mockedBcrypt.compare).toHaveBeenCalledWith(
        'correct_password',
        'real_stored_hash',
      );
      expect(jwtServiceMock.signAsync).toHaveBeenCalledWith({
        sub: 'user-id-5',
      });

      // Salva apenas o hash SHA-256 no banco
      const createCallData = (
        prismaMock.refreshToken.create.mock.calls[0] as [
          { data: { userId: string; hashedToken: string; expiresAt: Date } },
        ]
      )[0].data;
      expect(createCallData.userId).toBe('user-id-5');
      expect(createCallData.hashedToken).toBe(
        '9d028ebf85ceafd9886a3dc94d101ccca0682fe89dc8f220ce4a7adf1375a70a',
      );
      expect(createCallData.expiresAt).toBeInstanceOf(Date);

      // Cookie com as flags corretas (httpOnly, path '/auth', sameSite 'lax', maxAge 30 dias)
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'mocked_raw_refresh_token_base64url',
        {
          httpOnly: true,
          secure: false,
          sameSite: 'lax',
          path: '/auth',
          maxAge: 30 * 24 * 60 * 60 * 1000,
        },
      );

      // O refresh token nunca vai no corpo da resposta
      expect(result).toEqual({ accessToken: 'jwt_access_token_mock' });
      expect(result).not.toHaveProperty('refreshToken');
    });

    it('deve setar cookie com flag secure quando em ambiente de produção', async () => {
      configServiceMock.get.mockImplementation(
        (key: string, defaultValue?: string) => {
          if (key === 'NODE_ENV') return 'production';
          if (key === 'REFRESH_TOKEN_TTL_DAYS') return '30';
          return defaultValue;
        },
      );

      const { res, mockRes } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'user-id-prod',
        passwordHash: 'real_stored_hash',
      });
      prismaMock.refreshToken.create.mockResolvedValue({ id: 'rt-id' });
      mockedBcrypt.compare.mockResolvedValue(true as never);
      jwtServiceMock.signAsync.mockResolvedValue('jwt_prod_token');

      await service.login(
        {
          email: 'prod@example.com',
          password: 'correct_password',
        },
        res,
      );

      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'mocked_raw_refresh_token_base64url',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          path: '/auth',
        }),
      );
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") quando a senha estiver errada', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'user-id-6',
        passwordHash: 'real_stored_hash',
      });
      mockedBcrypt.compare.mockResolvedValue(false as never);

      await expect(
        service.login(
          {
            email: 'user@example.com',
            password: 'wrong_password',
          },
          res,
        ),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(jwtServiceMock.signAsync).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
      expect(prismaMock.refreshToken.create).not.toHaveBeenCalled();
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") e chamar bcrypt.compare quando o usuário não existir', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue(null);
      mockedBcrypt.compare.mockResolvedValue(false as never);

      await expect(
        service.login(
          {
            email: 'nonexistent@example.com',
            password: 'some_password',
          },
          res,
        ),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(mockedBcrypt.compare).toHaveBeenCalledWith(
        'some_password',
        'mocked_dummy_bcrypt_hash',
      );
      expect(jwtServiceMock.signAsync).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
      expect(prismaMock.refreshToken.create).not.toHaveBeenCalled();
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") e chamar bcrypt.compare quando o usuário não possuir passwordHash', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'google-user-id',
        passwordHash: null,
      });
      mockedBcrypt.compare.mockResolvedValue(false as never);

      await expect(
        service.login(
          {
            email: 'googleuser@example.com',
            password: 'some_password',
          },
          res,
        ),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(mockedBcrypt.compare).toHaveBeenCalledWith(
        'some_password',
        'mocked_dummy_bcrypt_hash',
      );
      expect(jwtServiceMock.signAsync).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
      expect(prismaMock.refreshToken.create).not.toHaveBeenCalled();
    });
  });

  describe('refresh', () => {
    it('deve lançar UnauthorizedException("Sessão inválida") quando não houver cookie', async () => {
      const { res, mockRes } = createMockResponse();

      await expect(service.refresh(undefined, res)).rejects.toThrow(
        new UnauthorizedException('Sessão inválida'),
      );

      expect(prismaMock.refreshToken.findUnique).not.toHaveBeenCalled();
      expect(mockRes.cookie).not.toHaveBeenCalled();
      expect(mockRes.clearCookie).not.toHaveBeenCalled();
    });

    it('deve limpar o cookie e lançar UnauthorizedException("Sessão inválida") quando o token não for encontrado no banco', async () => {
      const { res, mockRes } = createMockResponse();
      prismaMock.refreshToken.findUnique.mockResolvedValue(null);

      const rawToken = 'token_inexistente_123';
      const expectedHashedToken =
        '7a4f9a33150a9b8df0bad5edafe279066af1a1b5121098637932b2048a3ff749';

      await expect(service.refresh(rawToken, res)).rejects.toThrow(
        new UnauthorizedException('Sessão inválida'),
      );

      expect(prismaMock.refreshToken.findUnique).toHaveBeenCalledWith({
        where: { hashedToken: expectedHashedToken },
      });
      expect(mockRes.clearCookie).toHaveBeenCalledWith('refresh_token', {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/auth',
      });
      expect(mockRes.cookie).not.toHaveBeenCalled();
    });

    it('deve limpar o cookie e lançar UnauthorizedException("Sessão inválida") quando o token estiver expirado', async () => {
      const { res, mockRes } = createMockResponse();
      const pastDate = new Date(Date.now() - 1000 * 60 * 60);

      prismaMock.refreshToken.findUnique.mockResolvedValue({
        id: 'token-expirado-id',
        userId: 'user-id-expirado',
        isRevoked: false,
        expiresAt: pastDate,
      });

      await expect(service.refresh('token_expirado_raw', res)).rejects.toThrow(
        new UnauthorizedException('Sessão inválida'),
      );

      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'refresh_token',
        expect.objectContaining({
          httpOnly: true,
          path: '/auth',
        }),
      );
      expect(mockRes.cookie).not.toHaveBeenCalled();
      expect(prismaMock.$transaction).not.toHaveBeenCalled();
    });

    it('deve revogar todos os refresh tokens do usuário, limpar o cookie e lançar UnauthorizedException quando o token já estiver revogado (reuso detectado)', async () => {
      const { res, mockRes } = createMockResponse();
      const futureDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 10);

      prismaMock.refreshToken.findUnique.mockResolvedValue({
        id: 'token-revogado-id',
        userId: 'user-comprometido-id',
        isRevoked: true,
        expiresAt: futureDate,
      });
      prismaMock.refreshToken.updateMany.mockResolvedValue({ count: 3 });

      await expect(service.refresh('token_reusado_raw', res)).rejects.toThrow(
        new UnauthorizedException('Sessão inválida'),
      );

      // Revoga TODOS os tokens daquele usuário
      expect(prismaMock.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: 'user-comprometido-id' },
        data: { isRevoked: true },
      });

      expect(mockRes.clearCookie).toHaveBeenCalledWith(
        'refresh_token',
        expect.objectContaining({
          httpOnly: true,
          path: '/auth',
        }),
      );
      expect(mockRes.cookie).not.toHaveBeenCalled();
      expect(prismaMock.$transaction).not.toHaveBeenCalled();
    });

    it('deve rotacionar o refresh token em transação, atualizar cookie com flags corretas e retornar novo accessToken', async () => {
      const { res, mockRes } = createMockResponse();
      const futureDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 10);

      prismaMock.refreshToken.findUnique.mockResolvedValue({
        id: 'token-valido-id',
        userId: 'user-legitimo-id',
        isRevoked: false,
        expiresAt: futureDate,
      });
      prismaMock.refreshToken.update.mockResolvedValue({
        id: 'token-valido-id',
        isRevoked: true,
      });
      prismaMock.refreshToken.create.mockResolvedValue({
        id: 'novo-token-id',
      });
      jwtServiceMock.signAsync.mockResolvedValue('novo_jwt_access_token');

      const result = await service.refresh('token_valido_raw', res);

      // Transação revogando o atual e criando o novo
      expect(prismaMock.$transaction).toHaveBeenCalled();
      expect(prismaMock.refreshToken.update).toHaveBeenCalledWith({
        where: { id: 'token-valido-id' },
        data: { isRevoked: true },
      });
      const rotateCreateData = (
        prismaMock.refreshToken.create.mock.calls[0] as [
          { data: { userId: string; hashedToken: string; expiresAt: Date } },
        ]
      )[0].data;
      expect(rotateCreateData.userId).toBe('user-legitimo-id');
      expect(rotateCreateData.hashedToken).toBe(
        '9d028ebf85ceafd9886a3dc94d101ccca0682fe89dc8f220ce4a7adf1375a70a',
      );
      expect(rotateCreateData.expiresAt).toBeInstanceOf(Date);

      // Cookie atualizado com flags corretas (httpOnly, path '/auth', maxAge)
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'mocked_raw_refresh_token_base64url',
        {
          httpOnly: true,
          secure: false,
          sameSite: 'lax',
          path: '/auth',
          maxAge: 30 * 24 * 60 * 60 * 1000,
        },
      );

      // Assina payload apenas com { sub: userId }
      expect(jwtServiceMock.signAsync).toHaveBeenCalledWith({
        sub: 'user-legitimo-id',
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
});
