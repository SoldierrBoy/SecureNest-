(() => {
    'use strict';
    const input = document.querySelector('[data-password-input]');
    const meter = document.querySelector('[data-password-meter]');
    if (input && meter) {
        const rules = document.querySelector('[data-password-rules]');
        const checks = {
            length: v => v.length >= 8,
            case: v => /[a-z]/.test(v) && /[A-Z]/.test(v),
            digit: v => /\d/.test(v),
            symbol: v => /[^A-Za-z0-9]/.test(v)
        };
        input.addEventListener('input', () => {
            const value = input.value;
            const validCount = Object.entries(checks).reduce((score, [key, check]) => {
                const passed = check(value);
                rules?.querySelector(`[data-rule="${key}"]`)?.classList.toggle('passed', passed);
                return score + Number(passed);
            }, 0);
            meter.style.width = `${validCount * 25}%`;
            meter.style.background = validCount === 4 ? '#91f8d7' : validCount >= 2 ? '#f5c76b' : '#ff9cae';
        });
    }
    document.querySelector('[data-captcha-refresh]')?.addEventListener('click', () => {
        const image = document.querySelector('#captcha-image');
        if (image) image.src = `/captcha/image?r=${Date.now()}`;
    });
    document.querySelectorAll('[data-copy-text]').forEach(button => {
        button.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(button.dataset.copyText.replace(/\s+/g, ''));
                button.textContent = 'Скопійовано ✓';
            } catch { button.textContent = 'Не вдалося скопіювати'; }
        });
    });
    document.querySelectorAll('[data-confirm]').forEach(button => {
        button.addEventListener('click', event => {
            if (!window.confirm(button.dataset.confirm || 'Підтвердити?')) event.preventDefault();
        });
    });
})();
