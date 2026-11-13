# AGENTS.md — PostAi (MVP)

Fonte única de regras para qualquer IA/assistente neste repositório (Cursor, Copilot, Antigravity, Gemini CLI, Claude).
Idioma de conversa e comentários: **português (BR)**. Identificadores de código: **inglês**.

## 1. Visão geral

SaaS freemium de orquestração de redes sociais. O usuário envia uma mídia (foto/vídeo), escreve uma legenda e publica ao mesmo tempo em **Instagram (Profissional), Facebook, TikTok e YouTube**.
Foco: agilidade e economia de armazenamento. O sistema guarda **apenas a última postagem** de cada usuário.

## 2. Estrutura do repositório

```
/backend    NestJS + Prisma (API REST, workers BullMQ)
/frontend   Next.js (App Router) + Tailwind
docker-compose.yml   Postgres (porta 5433) + Redis (6379) locais
```

- `frontend/AGENTS.md` é gerado pelo Next.js: **leia-o e a documentação em `node_modules/next/dist/docs/` antes de escrever código no frontend** (esta versão tem breaking changes).

## 3. Stack (restrita — não adicionar tecnologias sem pedir)

- **Frontend:** Next.js (App Router), React, Tailwind CSS, TypeScript strict.
- **Backend:** NestJS, TypeScript.
- **Banco/ORM:** PostgreSQL + Prisma (v6).
- **Filas:** Redis + BullMQ.
- **Storage:** Supabase Storage (ou S3).

## 4. Segurança (obrigatório no backend)

1. **Auth:** JWT para sessões. Senhas e tokens de recuperação com `bcrypt`.
2. **Refresh token:** rotação a cada uso (uso único), salvo como hash `SHA-256` (busca indexada).
3. **Google OAuth:** validar o ID token no backend.
4. **XSS:** `sanitize-html` em todo input de texto (registro, nomes vindos do Google).
5. **Brute force:** rate limit por IP real (`trust proxy`) em `/auth/login` e `/auth/forgot-password`: máx. 5 tentativas/min.
6. **Enumeração:** rotas de recuperação de senha retornam sempre a mesma mensagem genérica estática.
7. **Reset de senha:** link de uso único, expira em 15 min.
8. **Segredos:** nunca hardcoded. Usar `ConfigService` e variáveis de ambiente. Nunca commitar `.env`.
9. **CORS:** restrito a `FRONTEND_URL`.
10. Tokens OAuth das redes (`access_token`, `refresh_token`) nunca vão para logs nem para respostas da API.

## 5. Regras de negócio e arquitetura

1. **Mídia:** o frontend detecta o MIME type. Se for imagem, bloquear destinos que exigem vídeo.
2. **Assíncrono:** `POST /posts` **não** chama APIs das redes. Ele salva o arquivo temporariamente, enfileira o job no BullMQ e retorna sucesso. O **worker** faz o envio.
3. **Armazenamento único:**
   - `LatestPost.user_id` é `UNIQUE`.
   - Nova postagem = `upsert` do Prisma.
   - Antes de salvar a nova, **deletar a mídia antiga** no bucket.
4. **Planos:** todo usuário nasce `plan: FREE`. A coluna existe; a trava de 12h **não** é implementada agora.
5. **Tokens das redes:** renovação automática antes de expirar.

## 6. Modelagem (referência para o `schema.prisma`)

- `User`: id (uuid), name, email (unique), password_hash (opcional), google_id (opcional, unique), plan (default FREE)
- `RefreshToken`: id, user_id, hashed_token (indexado), expires_at, is_revoked
- `PasswordReset`: id, user_id, hashed_token, expires_at
- `OAuthConnection`: id, user_id, provider (facebook | instagram | tiktok | youtube), external_account_id, access_token, refresh_token, expires_at
- `LatestPost`: id, user_id (UNIQUE), content_text, media_url
- `LatestPostDelivery`: id, latest_post_id, provider, status (pending | processing | success | failed), error_message

## 7. Rotas (API REST)

- Auth: `POST /auth/register | login | refresh | google | forgot-password | reset-password`
- Conexões: `GET /connections`, `GET /oauth/:provider/callback`
- Posts: `POST /posts`, `GET /posts/latest`

## 8. Convenções de código

- TypeScript strict, código limpo, modular e tipado. Sem `any` desnecessário.
- NestJS: Controllers, Services e Modules separados; Guards para auth; Interceptors quando fizer sentido; DTOs validados.
- Prisma é a única forma de acessar o banco (sem SQL cru concatenado).
- Commits em português, no padrão Conventional Commits (`feat:`, `fix:`, `chore:`).

## 9. Como o assistente deve se comportar

- Mostrar **apenas os arquivos criados/modificados**.
- **Não inventar requisitos** além do MVP descrito aqui.
- Em caso de ambiguidade, **perguntar antes** de gerar blocos grandes de código.
- Mudanças de segurança, auth e banco: explicar o motivo em poucas linhas.
- Respostas curtas e diretas.
