const arg = require('arg');
const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const args = arg({
    '--watch': Boolean,
    '--serve': Boolean
});

async function build(entryPoints) {
    const ctx = await esbuild.context({
        entryPoints: entryPoints,
        outdir: 'www/html/assets',
        bundle: true,
        allowOverwrite: true,
        platform: 'browser',
        sourcemap: 'external',
        external: ['*.png'],
        banner: {
            css: '/* DO NOT EDIT - automatically generated */', 
            js: '/* DO NOT EDIT - automatically generated */'
        }, 
        minify: !args['--watch'],
        define: { 
            'process.env.NODE_ENV': args['--watch'] ? `'development'` : `'production'`
        },
    });
    
    if (args['--watch']) {
        console.log(`Watching ${package}...`);

        ctx.watch().catch(() => {
            process.exit(1);
        });
    } else {
        await ctx.rebuild().catch(() => {
            process.exit(1);
        });
        await ctx.dispose();
    }
}

/* ----------------------- Main ----------------------- */
if (args['--serve']) args['--watch'] = true;

const entryPoints = fs.readdirSync('assets').filter((package) => {
    const type = path.extname(package);
    return ((type == '.js') || (type == '.css'))
}).map((package) => {
    const type = path.extname(package);
    const base = path.basename(package, type);
    return {
        in: `assets/${package}/main${type}`,
        out: base
    }
});
build(entryPoints);

if (args['--serve']) {
    const server = require("@compodoc/live-server");
    params = {
        port: 4000,
        host: "0.0.0.0",
        root: "tests/frontend",
        open: false, // When false, it won't load your browser by default.
        mount: [
            ["/html", "./www/html"]
        ],
        logLevel: 2, // 0 = errors only, 1 = some, 2 = lots
    };
    console.log(`Serving on http://${params.host}:${params.port}/`)
    server.start(params);
}
