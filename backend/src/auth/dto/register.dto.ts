import {
  IsByteLength,
  IsEmail,
  IsString,
  Length,
  MinLength,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class RegisterDto {
  @IsString({ message: 'O nome deve ser uma string' })
  @Length(2, 80, { message: 'O nome deve ter entre 2 e 80 caracteres' })
  name!: string;

  @IsEmail({}, { message: 'Formato de email inválido' })
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  email!: string;

  @IsString({ message: 'A senha deve ser uma string' })
  @MinLength(8, { message: 'A senha deve ter no mínimo 8 caracteres' })
  @IsByteLength(1, 72, {
    message:
      'A senha é muito longa. Use uma senha menor (acentos e emojis contam mais).',
  })
  password!: string;
}
