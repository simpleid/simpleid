const arg = require('arg');
const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const sassPlugin = require('esbuild-sass-plugin').sassPlugin;
const postcss = require('postcss');
const mergeRules = require('postcss-merge-rules');
const autoprefixer = require('autoprefixer');

const extensions = {
    '.js': [ '.js' ],
    '.css': [ '.css', '.scss' ]
};

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
        plugins: [
            sassPlugin({
                async transform(src, resolveDir) {
                    const {css} = await postcss([mergeRules, autoprefixer]).process(src, { from: undefined });
                    return css;
                }
            })
        ]
    });
    
    if (args['--watch']) {
        console.log(`Watching...`);

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
    const input = extensions[type].reduce((prev, current) => {
        if (prev != null) return prev;
        try {
            fs.accessSync(`assets/${package}/main${current}`);
            return `assets/${package}/main${current}`;
        } catch (err) {
            // Not found, return previous value
            return prev;
        }
    }, null);

    return {
        in: input,
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
