const arg = require('arg');
const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const args = arg({
    '--watch': Boolean,
    '--serve': Boolean
});

async function buildScript(package) {
    const ctx = await esbuild.context({
        entryPoints: [`assets/${package}/main.js`],
        outfile: `www/html/assets/${package}`,
        bundle: true,
        allowOverwrite: true,
        platform: 'browser',
        sourcemap: 'external',
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

async function buildStylesheet(package) {
    const ctx = await esbuild.context({
        entryPoints: [`assets/${package}/main.css`],
        outfile: `www/html/assets/${package}`,
        bundle: true,
        allowOverwrite: true,
        platform: 'browser',
        sourcemap: 'external',
        external: ['*.png'],
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

fs.readdirSync('assets').forEach(function(package) {
    const type = path.extname(package);
    if (type == '.js') {
        buildScript(package);
    } else if (type == '.css') {
        buildStylesheet(package);
    }
});

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
