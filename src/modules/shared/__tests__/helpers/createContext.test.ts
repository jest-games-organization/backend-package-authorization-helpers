import { ExpressContext } from '../../types/ExpressContext';
import { Algorithm, VerifyOptions } from 'jsonwebtoken';
import createJWKSMock, { JWKSMock } from 'mock-jwks';
import { JwksClient } from 'jwks-rsa';
import { createContext } from '../../helpers/createContext';

describe('GIVEN the createContext method', () => {
  let audience: string;
  let issuer: string;
  let algorithms: Algorithm[];
  let jwks: JWKSMock;
  let jwksClient: JwksClient;
  let verifyOptions: VerifyOptions;

  beforeEach(() => {
    audience = 'mockAudience';
    issuer = 'https://jest-games.us.auth0.com';
    algorithms = ['RS256'];
    jwks = createJWKSMock(issuer);
    jwks.start();
    jwksClient = new JwksClient({ jwksUri: `${issuer}/.well-known/jwks.json` });
    verifyOptions = { audience, issuer, algorithms };
  });

  afterEach(() => {
    jwks.stop();
  });

  describe('WHEN the request does not contain an authorization header', () => {
    test('THEN it should return the context', async () => {
      const expressContext = { req: { headers: {} }, res: {} } as ExpressContext;
      const createData = jest.fn();
      const response = await createContext(expressContext, { jwksClient, verifyOptions, createData });
      expect(response).toEqual({ req: { headers: {} }, res: {}, data: null });
    });
  });

  describe('WHEN the request does contain an authorization header', () => {
    describe('WHEN the authorization header is not a bearer token', () => {
      test('THEN it should return the context', async () => {
        const expressContext = {
          req: { headers: { authorization: 'mockAuthorizationHeader' } },
          res: {},
        } as ExpressContext;
        const createData = jest.fn();
        const response = await createContext(expressContext, { jwksClient, verifyOptions, createData });
        expect(response).toEqual({
          req: { headers: { authorization: 'mockAuthorizationHeader' } },
          res: {},
          data: null,
        });
      });
    });

    describe('WHEN the authorization header is a bearer token', () => {
      describe('WHEN the bearer token is invalid', () => {
        test('THEN it should return the context', async () => {
          const incorectAudience = 'incorrectAudience';
          const jwt = jwks.token({ aud: incorectAudience, iss: issuer });
          const expressContext = {
            req: { headers: { authorization: `Bearer ${jwt}` } },
            res: {},
          } as ExpressContext;
          const createData = jest.fn();
          const response = await createContext(expressContext, { jwksClient, verifyOptions, createData });
          expect(response).toEqual({
            req: { headers: { authorization: `Bearer ${jwt}` } },
            res: {},
            data: null,
          });
        });
      });

      describe('WHEN the bearer token is valid', () => {
        test('THEN it should return the context', async () => {
          const subject = 'mockSubject';
          const jwt = jwks.token({ aud: audience, iss: issuer, sub: subject });
          const expressContext = {
            req: { headers: { authorization: `Bearer ${jwt}` } },
            res: {},
          } as ExpressContext;
          const createData = jest.fn().mockImplementation(async (_, decodedJwt) => ({
            user: { id: decodedJwt.payload.sub },
          }));
          const response = await createContext(expressContext, { jwksClient, verifyOptions, createData });
          expect(response).toEqual({
            req: { headers: { authorization: `Bearer ${jwt}` } },
            res: {},
            data: { user: { id: subject } },
          });
        });
      });
    });
  });
});
