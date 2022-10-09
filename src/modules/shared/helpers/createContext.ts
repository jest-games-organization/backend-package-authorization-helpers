import { VerifyOptions } from 'jsonwebtoken';
import { JwksClient } from 'jwks-rsa';
import { Context } from '../types/Context';
import { DecodedJwt } from '../types/DecodedJwt';
import { ExpressContext } from '../types/ExpressContext';
import { decodeJwt } from './decodeJwt';

/**
 * Create the context.
 * @param expressContext The Express context.
 * @param config The configuration.
 * @returns The context.
 */
export const createContext = async <T extends { [key: string]: unknown }>(
  expressContext: ExpressContext,
  config: {
    jwksClient: JwksClient;
    verifyOptions: VerifyOptions;
    createData: (expressContext: ExpressContext, decodedJwt: DecodedJwt) => Promise<T>;
  },
): Promise<Context<T>> => {
  // Create the base context
  const baseContext: Context<T> = { ...expressContext, data: null };

  // Get the authorization header from the request
  const authorizationHeader = expressContext.req.headers.authorization;

  // If there is no authorization header, return the base context
  if (!authorizationHeader) return baseContext;

  // Get the JWT (JSON Web Token) from the authorization header
  const [authorizationScheme, jwt] = authorizationHeader.split(' ');

  // If the authorization scheme is not Bearer, return the base context
  if (authorizationScheme !== 'Bearer') return baseContext;

  // Get the decoded JWT
  const decodedJwt = await decodeJwt(jwt, config);

  // If the decoded JWT is undefined, return the base context
  if (!decodedJwt) return baseContext;

  // Create the data from the payload
  const data = await config.createData(expressContext, decodedJwt);

  // Return the authorized context
  return { ...baseContext, data };
};
