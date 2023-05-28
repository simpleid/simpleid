const Alpine = require('alpinejs');

window.Alpine = Alpine;
queueMicrotask(() => {
    Alpine.start()
})