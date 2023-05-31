import QRCode from 'qrcode-svg'

document.addEventListener('alpine:initializing', () => {
    let Alpine = window.Alpine;

    Alpine.directive('qrcode', (el, { modifiers, expression }, { evaluateLater, effect }) => {
        let getContent = evaluateLater(expression);

        effect(() => {
            getContent(expr => {
                const qrcode = new QRCode(expr);
                el.innerHTML = qrcode.svg();
            })
        });
    });
});