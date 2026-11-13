# 🚀 PostAi (Nome Provisório)

Plataforma centralizada para orquestração e publicação de conteúdo simultaneamente no Instagram, Facebook, TikTok e YouTube(Por hora). Foco em agilidade: envie uma vez, a plataforma distribui e mantém apenas o status da sua última postagem.

## 🛠️ 1. Stack Tecnológica

- **Front-end:** Next.js (React) com Tailwind CSS.

- **Back-end:** NestJS (TypeScript).

- **ORM:** Prisma (Proteção nativa contra SQL Injection).

- **Mensageria:** Redis com BullMQ.

- **Banco de Dados:** PostgreSQL (Docker local) / Supabase (Produção).

## 🛡️ 2. Requisitos de Segurança & Autenticação

O sistema implementa uma camada de segurança rigorosa baseada em práticas de mercado:

- **Login/Cadastro:** E-mail e senha emitindo JWT. Senhas cacheadas com `bcrypt`.

- **Social Login:** Google OAuth2 (Google Identity Services) com validação de ID token no back-end.

- **Refresh Token com Rotação:** Uso único, guardado como hash (SHA-256) com busca indexada no banco.

- **Recuperação de Senha:** Link de uso único por e-mail, expiração em 15 minutos, token via `bcrypt`.

- **Prevenção a Ataques:**

- **XSS:** Sanitização rigorosa de inputs (ex: `sanitize-html`) no registro e login social.

- **Força Bruta:** Rate limiting por IP real (5 tentativas/minuto) nas rotas `/login` e `/forgot-password`, configurado para `trust proxy`.

- **Enumeração:** Respostas genéricas em rotas de recuperação de senha.

- **CORS:** Restrito à variável de ambiente `FRONTEND_URL`.

- **Segredos:** 100% gerenciados por variáveis de ambiente.

## 🎯 3. Requisitos Funcionais (MVP)

- **RF01:** Autenticação completa (Interna e Google) do usuário na plataforma.

- **RF02:** Vinculação via OAuth2 de contas do Facebook, Instagram (Profissional) e TikTok, com renovação automática de tokens.

- **RF03:** Upload de mídia (identificando formato MIME para bloqueio de redes incompatíveis) e inclusão de legenda unificada.

- **RF04:** Envio do conteúdo em background via filas (Redis/BullMQ).

- **RF05:** O sistema armazena e exibe **apenas o status da última postagem** enviada (substituindo ou deletando registros anteriores para economizar storage).

## 🚏 4. Mapeamento de Rotas (API REST)

**Domínio: Autenticação (Segurança Máxima)**

- `POST /auth/register` - Cria conta (com sanitização XSS).

- `POST /auth/login` - Retorna JWT (Rate limited).

- `POST /auth/refresh` - Rotação do refresh token.

- `POST /auth/google` - Valida o ID Token do Google.

- `POST /auth/forgot-password` - Dispara e-mail genérico (Rate limited).

- `POST /auth/reset-password` - Valida token `bcrypt` de 15 min e altera senha.

**Domínio: Conexões Sociais (OAuth2)**

- `GET /connections` - Lista redes vinculadas.

- `GET /oauth/:provider/callback` - Salva tokens da rede social.

**Domínio: Postagem (Única)**

- `POST /posts` - Salva o arquivo temporariamente, agenda o disparo no BullMQ e apaga do banco a postagem anterior do usuário.

- `GET /posts/latest` - Retorna apenas a última publicação tentada e o log de status em cada rede (Pendente, Sucesso, Falha).

## 🗄️ 5. Modelagem do Banco de Dados

**Tabela: `users**`

- `id` (UUID, PK)

- `name` (Varchar, sanitizado)

- `email` (Varchar, Unique)

- `password_hash` (Varchar, Nullable para quem usa só Google)

- `google_id` (Varchar, Nullable, Unique)

- `plan` (Enum: 'FREE', 'PRO') - com valor padrão 'FREE'.

**Tabelas de Segurança Auth:**

- `refresh_tokens` (id, user_id, hashed_token, expires_at, is_revoked)

- `password_resets` (id, user_id, hashed_token, expires_at)

**Tabela: `oauth_connections**`

- `id` (UUID, PK)

- `user_id` (UUID, FK)

- `provider` ('facebook', 'instagram', 'tiktok')

- `external_account_id` (Varchar)

- `access_token` (Text)

- `refresh_token` (Text)

- `expires_at` (Timestamp)

**Tabela: `latest_post**` (Substitui a tabela de histórico)

- `id` (UUID, PK)

- `user_id` (UUID, FK, Unique) - _Garante que exista apenas 1 post por usuário no banco._

- `content_text` (Text)

- `media_url` (Varchar)

**Tabela: `latest_post_deliveries**`

- `id` (UUID, PK)

- `latest_post_id` (UUID, FK)

- `provider` ('facebook', 'instagram', 'tiktok')

- `status` ('pending', 'processing', 'success', 'failed')

- `error_message` (Text)

---
