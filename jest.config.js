module.exports = {
  clearMocks: true,
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.json' }] },
  modulePathIgnorePatterns: ['<rootDir>/node_modules/', '<rootDir>/test/', '<rootDir>/dist/'],
};
