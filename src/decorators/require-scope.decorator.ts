import { SetMetadata } from '@nestjs/common';
import type { ScopeLevel } from '../types';

export const SCOPE_METADATA = 'nestarc:api-keys:scope';

export interface RequiredScope {
  resource: string;
  level: ScopeLevel;
}

export const RequireScope = (resource: string, level: ScopeLevel) =>
  SetMetadata(SCOPE_METADATA, { resource, level } satisfies RequiredScope);
