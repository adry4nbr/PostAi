import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';

@Injectable()
export class MailService {
  private readonly transporter: Transporter;
  private readonly mailFrom: string;
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly configService: ConfigService) {
    this.mailFrom = this.configService.getOrThrow<string>('MAIL_FROM');
    const port = Number(this.configService.getOrThrow<string>('SMTP_PORT'));

    // Transporter configurado via variáveis de ambiente, nunca hardcoded.
    this.transporter = nodemailer.createTransport({
      host: this.configService.getOrThrow<string>('SMTP_HOST'),
      port,
      secure: port === 465, // 465 = TLS direto
      requireTLS: port !== 465, // demais portas exigem STARTTLS
      auth: {
        user: this.configService.getOrThrow<string>('SMTP_USER'),
        pass: this.configService.getOrThrow<string>('SMTP_PASS'),
      },
    });
  }

  /**
   * Envia e-mail de recuperação de senha em texto puro.
   * Nunca registra o link ou o token nos logs.
   */
  async sendPasswordReset(to: string, resetUrl: string): Promise<void> {
    await this.transporter.sendMail({
      from: this.mailFrom,
      to,
      subject: 'Recuperação de senha — PostAi',
      text: [
        'Você solicitou a recuperação de senha do PostAi.',
        '',
        'Clique no link abaixo para criar uma nova senha (válido por 15 minutos):',
        resetUrl,
        '',
        'Se você não solicitou isso, ignore este e-mail.',
        'Sua senha permanece a mesma.',
      ].join('\n'),
    });

    this.logger.log(`E-mail de recuperação enviado`);
  }
}
