import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
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

jest.mock('../prisma/prisma.service', () => ({
  PrismaService: jest.fn().mockImplementation(() => ({
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
    },
  })),
}));

const mockedBcrypt = jest.mocked(bcrypt);

type MockPrismaUser = {
  findUnique: jest.Mock;
  create: jest.Mock;
};

type MockPrismaService = {
  user: MockPrismaUser;
};

type MockJwtService = {
  signAsync: jest.Mock;
  verifyAsync: jest.Mock;
};

describe('AuthService', () => {
  let service: AuthService;
  let prismaMock: MockPrismaService;
  let jwtServiceMock: MockJwtService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const prismaInstance: MockPrismaService = {
      user: {
        findUnique: jest.fn(),
        create: jest.fn(),
      },
    };

    const jwtInstance: MockJwtService = {
      signAsync: jest.fn(),
      verifyAsync: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prismaInstance },
        { provide: JwtService, useValue: jwtInstance },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prismaMock = prismaInstance;
    jwtServiceMock = jwtInstance;
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
    it('deve realizar login com sucesso, assinar JWT apenas com sub e retornar accessToken', async () => {
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'user-id-5',
        passwordHash: 'real_stored_hash',
      });
      mockedBcrypt.compare.mockResolvedValue(true as never);
      jwtServiceMock.signAsync.mockResolvedValue('jwt_access_token_mock');

      const result = await service.login({
        email: '  Login.User@Example.COM  ',
        password: 'correct_password',
      });

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
      expect(result).toEqual({ accessToken: 'jwt_access_token_mock' });
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") quando a senha estiver errada', async () => {
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'user-id-6',
        passwordHash: 'real_stored_hash',
      });
      mockedBcrypt.compare.mockResolvedValue(false as never);

      await expect(
        service.login({
          email: 'user@example.com',
          password: 'wrong_password',
        }),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(jwtServiceMock.signAsync).not.toHaveBeenCalled();
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") e chamar bcrypt.compare quando o usuário não existir', async () => {
      prismaMock.user.findUnique.mockResolvedValue(null);
      mockedBcrypt.compare.mockResolvedValue(false as never);

      await expect(
        service.login({
          email: 'nonexistent@example.com',
          password: 'some_password',
        }),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(mockedBcrypt.compare).toHaveBeenCalledWith(
        'some_password',
        'mocked_dummy_bcrypt_hash',
      );
      expect(jwtServiceMock.signAsync).not.toHaveBeenCalled();
    });

    it('deve lançar UnauthorizedException("Credenciais inválidas") e chamar bcrypt.compare quando o usuário não possuir passwordHash', async () => {
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'google-user-id',
        passwordHash: null,
      });
      mockedBcrypt.compare.mockResolvedValue(false as never);

      await expect(
        service.login({
          email: 'googleuser@example.com',
          password: 'some_password',
        }),
      ).rejects.toThrow(new UnauthorizedException('Credenciais inválidas'));

      expect(mockedBcrypt.compare).toHaveBeenCalledWith(
        'some_password',
        'mocked_dummy_bcrypt_hash',
      );
      expect(jwtServiceMock.signAsync).not.toHaveBeenCalled();
    });
  });
});
