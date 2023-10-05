import {
  KredsAuthenticationOutcome,
  KredsDestroyFunction,
  KredsStrategy,
  KredsStrategyOptions,
  KredsVerifyUserFunction,KredsContext
} from '@kreds/types';

interface BearerStrategyOptions<TUser> extends KredsStrategyOptions<TUser> {
  authorizationType: string;
  verify: KredsVerifyUserFunction<TUser, string>;
  destroy?: KredsDestroyFunction<string>;
}

export class BearerStrategy<TUser> implements KredsStrategy<TUser> {
  name = 'bearer';

  constructor(private options: BearerStrategyOptions<TUser>) {
    if (!options.destroy) {
      this.unauthenticate = undefined;
    }
  }

  async authenticate(
    context: KredsContext
  ): Promise<KredsAuthenticationOutcome<TUser> | undefined> {
    let token: string | undefined;

    if (typeof context.payload === 'string') {
      token = context.payload;
    } else if (context.transport === 'http') {
      const authorization = context.adapter.getAuthorization();
      if (
        !authorization ||
        !authorization.credentials ||
        authorization.type !== this.options.authorizationType
      ) {
        return undefined;
      }

      token = authorization.credentials;
    } else {
      return undefined;
    }

    try {
      return await this.options.verify(context, token);
    } catch {
      return undefined;
    }
  }

  async unauthenticate?(context: KredsContext): Promise<void> {
    await this.options.destroy!(context, context.payload as string);
  }
}
