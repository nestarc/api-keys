import { SetMetadata } from '@nestjs/common';
import type { CustomDecorator } from '@nestjs/common' with {
  'resolution-mode': 'import',
};
import type { Environment } from '../types';

export const ENVIRONMENT_METADATA = 'nestarc:api-keys:environment';

export const RequireEnvironment = (environment: Environment): CustomDecorator<string> =>
  SetMetadata(ENVIRONMENT_METADATA, environment);
