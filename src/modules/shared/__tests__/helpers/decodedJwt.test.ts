import { JwksClient } from 'jwks-rsa';
import { Algorithm } from 'jsonwebtoken';
import createJWKSMock, { JWKSMock } from 'mock-jwks';
import { decodeJwt } from '../../helpers/decodeJwt';

describe('GIVEN the decodeJwt method', () => {
  let audience: string;
  let algorithms: Algorithm[];

  beforeEach(() => {
    audience = 'mockAudience';
    algorithms = ['RS256'];
  });

  describe('WHEN the JWKS client does not return a signing key', () => {
    let issuer: string;
    let jwks: JWKSMock;
    let jwksClient: JwksClient;

    beforeEach(() => {
      issuer = 'https://mockIssuer.com';
      jwks = createJWKSMock(issuer);
      jwks.start();
      jwksClient = new JwksClient({ jwksUri: `${issuer}-other/.well-known/jwks.json` });
    });

    afterEach(() => {
      jwks.stop();
    });

    test('THEN it should return undefined', async () => {
      const jwt = jwks.token({ aud: audience, iss: issuer });
      const response = await decodeJwt(jwt, { jwksClient, verifyOptions: { algorithms } });
      expect(response).toBeUndefined();
    });
  });

  describe('WHEN the JWKS client does return a signing key', () => {
    let issuer: string;
    let jwks: JWKSMock;
    let jwksClient: JwksClient;

    beforeEach(() => {
      issuer = 'https://mockIssuer.com';
      jwks = createJWKSMock(issuer);
      jwks.start();
      jwksClient = new JwksClient({ jwksUri: `${issuer}/.well-known/jwks.json` });
    });

    afterEach(() => {
      jwks.stop();
    });

    describe('WHEN the JWT is invalid', () => {
      describe('WHEN the jwt is not provided', () => {
        test('THEN it should return undefined', async () => {
          const jwt = '';
          const verifyOptions = { audience, issuer, algorithms };
          const response = await decodeJwt(jwt, { jwksClient, verifyOptions });
          expect(response).toBeUndefined();
        });
      });

      describe('WHEN the jwt audience is incorrect', () => {
        test('THEN it should return undefined', async () => {
          const incorectAudience = 'incorrectAudience';
          const jwt = jwks.token({ aud: incorectAudience, iss: issuer });
          const verifyOptions = { audience, issuer, algorithms };
          const response = await decodeJwt(jwt, { jwksClient, verifyOptions });
          expect(response).toBeUndefined();
        });
      });

      describe('WHEN the jwt issuer is incorrect', () => {
        test('THEN it should return undefined', async () => {
          const incorectIssuer = 'incorrectIssuer';
          const jwt = jwks.token({ aud: audience, iss: incorectIssuer });
          const verifyOptions = { audience, issuer, algorithms };
          const response = await decodeJwt(jwt, { jwksClient, verifyOptions });
          expect(response).toBeUndefined();
        });
      });
    });

    describe('WHEN the JWT is valid', () => {
      test('THEN it should return the JWT payload', async () => {
        const jwt = jwks.token({ aud: audience, iss: issuer });
        const verifyOptions = { audience, issuer, algorithms };
        const response = await decodeJwt(jwt, { jwksClient, verifyOptions });
        expect(response?.payload).toEqual({ aud: audience, iss: issuer });
      });
    });
  });
});
