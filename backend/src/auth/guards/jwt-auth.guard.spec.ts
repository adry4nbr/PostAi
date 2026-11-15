import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtAuthGuard, AuthenticatedRequest } from './jwt-auth.guard';

jest.mock('@nestjs/jwt', () => ({
  JwtService: jest.fn().mockImplementation(() => ({
    verifyAsync: jest.fn(),
  })),
}));

type MockJwtService = {
  verifyAsync: jest.Mock;
};

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let jwtServiceMock: MockJwtService;

  beforeEach(() => {
    jwtServiceMock = {
      verifyAsync: jest.fn(),
    };
    guard = new JwtAuthGuard(jwtServiceMock as unknown as JwtService);
  });

  const createMockContext = (
    authorizationHeader?: string,
  ): {
    context: ExecutionContext;
    request: AuthenticatedRequest;
  } => {
    const request = {
      headers: {
        authorization: authorizationHeader,
      },
      user: undefined,
    } as unknown as AuthenticatedRequest;

    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
      }),
    } as unknown as ExecutionContext;

    return { context, request };
  };

  it('deve lançar UnauthorizedException quando não houver header de autorização', async () => {
    const { context } = createMockContext(undefined);

    await expect(guard.canActivate(context)).rejects.toThrow(
      new UnauthorizedException('Token de autenticação não fornecido'),
    );
  });

  it('deve lançar UnauthorizedException quando o esquema do token for diferente de Bearer', async () => {
    const { context } = createMockContext('Basic 123456');

    await expect(guard.canActivate(context)).rejects.toThrow(
      new UnauthorizedException('Token de autenticação não fornecido'),
    );
  });

  it('deve lançar UnauthorizedException quando o token for inválido', async () => {
    const { context } = createMockContext('Bearer invalid_token');
    jwtServiceMock.verifyAsync.mockRejectedValue(new Error('Invalid token'));

    await expect(guard.canActivate(context)).rejects.toThrow(
      new UnauthorizedException('Token inválido ou expirado'),
    );
  });

  it('deve lançar UnauthorizedException quando o payload não contiver a propriedade sub como string', async () => {
    const { context: contextWithoutSub } = createMockContext(
      'Bearer token_without_sub',
    );
    jwtServiceMock.verifyAsync.mockResolvedValue({});

    await expect(guard.canActivate(contextWithoutSub)).rejects.toThrow(
      new UnauthorizedException('Token inválido ou expirado'),
    );

    const { context: contextWithNumericSub } = createMockContext(
      'Bearer token_with_numeric_sub',
    );
    jwtServiceMock.verifyAsync.mockResolvedValue({ sub: 12345 });

    await expect(guard.canActivate(contextWithNumericSub)).rejects.toThrow(
      new UnauthorizedException('Token inválido ou expirado'),
    );
  });

  it('deve retornar true, preencher request.user com { id } e chamar verifyAsync com { algorithms: ["HS256"] } quando o token for válido', async () => {
    const { context, request } = createMockContext('Bearer valid_token');
    jwtServiceMock.verifyAsync.mockResolvedValue({ sub: 'user-id-123' });

    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(request.user).toEqual({ id: 'user-id-123' });
    expect(jwtServiceMock.verifyAsync).toHaveBeenCalledWith('valid_token', {
      algorithms: ['HS256'],
    });
  });
});
