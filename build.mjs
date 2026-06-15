import { build } from 'esbuild';

await build({
  entryPoints: ['webapp/app.js'],
  bundle: true,
  format: 'esm',
  target: 'es2020',
  outfile: 'webapp/dist/bundle.js',
  minify: false,
  sourcemap: true,
});

console.log('[build] webapp/dist/bundle.js yaradıldı');
