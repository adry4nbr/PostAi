import { IsByteLength, IsString, MaxLength, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @IsString({ message: 'Token inválido' })
  @MaxLength(200, { message: 'Token inválido' })
  token!: string;

  // Mesmas validações do RegisterDto: mínimo 8 chars, máximo 72 bytes (limite bcrypt).
  @IsString({ message: 'A senha deve ser uma string' })
  @MinLength(8, { message: 'A senha deve ter no mínimo 8 caracteres' })
  @IsByteLength(1, 72, {
    message:
      'A senha é muito longa. Use uma senha menor (acentos e emojis contam mais).',
  })
  newPassword!: string;
}
