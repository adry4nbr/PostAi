import { IsString, MaxLength } from 'class-validator';

export class GoogleLoginDto {
  @IsString({ message: 'idToken deve ser uma string' })
  @MaxLength(4096, { message: 'idToken muito longo' })
  idToken!: string;
}
