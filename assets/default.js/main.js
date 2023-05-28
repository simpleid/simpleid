const Alpine = require('alpinejs');

window.Alpine = Alpine;
queueMicrotask(() => {
    window.Alpine.start();
})