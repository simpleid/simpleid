const arg = require('arg');
const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const args = arg({
    '--watch': Boolean
});

async function buildScript(package) {
    const ctx = await esbuild.context({
        entryPoints: [`assets/${package}/main.js`],
        outfile: `www/html/assets/${package}`,
        bundle: true,
        allowOverwrite: true,
        platform: 'browser',
        sourcemap: 'external',
        minify: !args.watch,
        define: { 
            'process.env.NODE_ENV': args.watch ? `'development'` : `'production'`
        },
    });
    
    if (args.watch) {
        console.log('Watching...');

        await ctx.watch().catch(() => {
            process.exit(1);
        });
    } else {
        await ctx.rebuild().catch(() => {
            process.exit(1);
        });
    }

    await ctx.dispose();
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
        minify: !args.watch,
        define: { 
            'process.env.NODE_ENV': args.watch ? `'development'` : `'production'`
        },
    });
    
    if (args.watch) {
        console.log('Watching...');

        await ctx.watch().catch(() => {
            process.exit(1);
        });
    } else {
        await ctx.rebuild().catch(() => {
            process.exit(1);
        });
    }

    await ctx.dispose();
}

fs.readdirSync('assets').forEach(function(package) {
    const type = path.extname(package);
    if (type == '.js') {
        buildScript(package);
    } else if (type == '.css') {
        buildStylesheet(package);
    }
});
