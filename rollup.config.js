import resolve from '@rollup/plugin-node-resolve';
import pkg from './package.json';
import babel from '@rollup/plugin-babel';
import dts from 'rollup-plugin-dts';

const extensions = ['.js', '.ts'];

export default [
  {
    input: './src/index.ts',
    output: [
      { file: pkg.main, format: 'cjs' },
      { file: pkg.module, format: 'es' },
    ],
    plugins: [resolve({ extensions }), babel({ exclude: 'node_modules/**', extensions, babelHelpers: 'bundled' })],
    onwarn: (warning) => {
      if (warning.code === 'THIS_IS_UNDEFINED') return;
      console.warn(warning.message);
    },
  },
  {
    input: './dist/types/index.d.ts',
    output: [{ file: pkg.types, format: 'es' }],
    plugins: [dts()],
  },
];
