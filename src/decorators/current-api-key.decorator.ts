import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { getApiKeyContext } from '../context';

export const CurrentApiKey = createParamDecorator(
  (_data: unknown, context: ExecutionContext) =>
    getApiKeyContext(context.switchToHttp().getRequest()),
);
