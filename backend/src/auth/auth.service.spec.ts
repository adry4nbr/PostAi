import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import type { Response } from 'express';
import { AuthService, RegisterResponse } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';

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
});
