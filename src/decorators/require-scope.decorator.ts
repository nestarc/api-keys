import { SetMetadata } from '@nestjs/common';
import type { CustomDecorator } from '@nestjs/common' with {
  'resolution-mode': 'import',
};
import type { ScopeLevel } from '../types';

export const SCOPE_METADATA = 'nestarc:api-keys:scope';

export interface RequiredScope {
  resource: string;
  level: ScopeLevel;
}

export const RequireScope = (resource: string, level: ScopeLevel): CustomDecorator<string> =>
  SetMetadata(SCOPE_METADATA, { resource, level } satisfies RequiredScope);
