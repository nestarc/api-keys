import { SetMetadata } from '@nestjs/common';
import type { Environment } from '../types';

export const ENVIRONMENT_METADATA = 'nestarc:api-keys:environment';

export const RequireEnvironment = (environment: Environment) =>
  SetMetadata(ENVIRONMENT_METADATA, environment);
