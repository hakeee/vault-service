import type { FastifyError, FastifyReply, FastifyRequest } from "fastify";
import { ZodError } from "zod";

/**
 * Error handler for the auth and vault routes. Bad input is the caller's
 * mistake: a 400 with the first problem. Other client errors Fastify raises
 * itself (malformed JSON, body too large) keep their status. Anything else
 * is ours: logged, and answered with a bare "internal error" so a message
 * from a library or the database never reaches the browser.
 */
export function routeErrorHandler(error: FastifyError | Error, request: FastifyRequest, reply: FastifyReply) {
  if (error instanceof ZodError) return reply.code(400).send({ error: error.issues[0]?.message ?? "invalid input" });
  const status = (error as FastifyError).statusCode;
  if (status !== undefined && status >= 400 && status < 500) return reply.code(status).send({ error: error.message });
  request.log.error(error);
  return reply.code(500).send({ error: "internal error" });
}
