import Alpine from 'alpinejs';

window.Alpine = Alpine;
queueMicrotask(() => {
    Alpine.start();
})