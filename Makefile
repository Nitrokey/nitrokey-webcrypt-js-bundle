all:
	rm -rf ./dist/* -v
	./node_modules/.bin/esbuild index.ts --bundle --sourcemap --target=chrome99  --outfile=dist/webcrypt.min.js
	./node_modules/.bin/esbuild index.ts --bundle --sourcemap --target=chrome99  --outfile=dist/webcrypt.min.mjs --format=esm
	./node_modules/.bin/esbuild index.ts --bundle --platform=node --external:./node_modules/* --outfile=dist/node/webcrypt.min.js
	./node_modules/.bin/esbuild index.ts --bundle --platform=node --external:./node_modules/* --outfile=dist/node/webcrypt.min.mjs --format=esm
