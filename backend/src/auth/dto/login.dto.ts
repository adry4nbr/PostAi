import { IsEmail, IsString, MaxLength } from 'class-validator';
import { Transform } from 'class-transformer';

export class LoginDto {
  @IsEmail({}, { message: 'Formato de email inválido' })
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  email!: string;

  @IsString({ message: 'A senha deve ser uma string' })
  @MaxLength(128, { message: 'A senha deve ter no máximo 128 caracteres' })
  password!: string;
}
