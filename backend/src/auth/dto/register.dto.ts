import { IsEmail, IsString, Length } from 'class-validator';
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
  @Length(8, 72, { message: 'A senha deve ter entre 8 e 72 caracteres' })
  password!: string;
}
