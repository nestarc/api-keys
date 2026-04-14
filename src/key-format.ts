import { randomBytes } from 'node:crypto';
import { ApiKeyError, ApiKeyErrorCode } from './errors';
import type { Environment } from './types';

const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const PREFIX_LENGTH = 12;
const SECRET_LENGTH = 32;
const ENVIRONMENTS: Environment[] = ['live', 'test'];

function randomBase62(length: number): string {
  const bytes = randomBytes(length);
  let output = '';

  for (let index = 0; index < length; index += 1) {
    output += BASE62[bytes[index] % BASE62.length];
  }

  return output;
}

export interface GeneratedKey {
  raw: string;
  namespace: string;
  environment: Environment;
  prefix: string;
  secret: string;
}

export function generateKey(options: {
  namespace: string;
  environment: Environment;
}): GeneratedKey {
  const prefix = randomBase62(PREFIX_LENGTH);
  const secret = randomBase62(SECRET_LENGTH);
  const raw = `${options.namespace}_${options.environment}_${prefix}_${secret}`;

  return {
    raw,
    namespace: options.namespace,
    environment: options.environment,
    prefix,
    secret,
  };
}

export interface ParsedKey {
  namespace: string;
  environment: Environment;
  prefix: string;
  secret: string;
}

export function parseKey(raw: string): ParsedKey {
  const parts = raw.split('_');
  if (parts.length !== 4) {
    throw new ApiKeyError(ApiKeyErrorCode.Malformed, 'expected 4 segments');
  }

  const [namespace, environment, prefix, secret] = parts;

  if (!ENVIRONMENTS.includes(environment as Environment)) {
    throw new ApiKeyError(ApiKeyErrorCode.Malformed, `unknown environment: ${environment}`);
  }

  if (prefix.length !== PREFIX_LENGTH || secret.length !== SECRET_LENGTH) {
    throw new ApiKeyError(ApiKeyErrorCode.Malformed, 'wrong segment length');
  }

  return {
    namespace,
    environment: environment as Environment,
    prefix,
    secret,
  };
}

export const API_KEY_REDACT_REGEX =
  /[A-Za-z0-9]+_(live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}/g;
