import { DecodedJwt } from '@jest-games-organization/backend-package-authorization-types';
import * as jwtPackage from 'jsonwebtoken';
import { SigningKeyCallback, VerifyOptions } from 'jsonwebtoken';
import { JwksClient } from 'jwks-rsa';

/**
 * Decode the JWT (JSON Web Token).
 * @param jwt The JWT to decode.
 * @param config The configuration.
 * @returns The decoded JWT.
 */
export const decodeJwt = async (
  jwt: string,
  config: { jwksClient: JwksClient; verifyOptions: VerifyOptions },
): Promise<DecodedJwt | undefined> => {
  // Get the public key from the JWKS (JSON Web Key Set) client
  const getKey = (jwtHeader: DecodedJwt['header'], callback: SigningKeyCallback) => {
    config.jwksClient.getSigningKey(jwtHeader.kid, (_, key) => {
      callback(null, key?.getPublicKey());
    });
  };
  // Verify the JWT (JSON Web Token) and get the payload
  return new Promise((resolve) =>
    jwtPackage.verify(jwt, getKey, { ...config.verifyOptions, complete: true }, (_, decoded) => {
      resolve(decoded as DecodedJwt);
    }),
  );
};
