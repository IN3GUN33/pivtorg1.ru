// Инициализация элементов при загрузке
document.addEventListener('DOMContentLoaded', function() {
    // Анимация элементов
    animateElements();
    
    // Обработка всплывающих сообщений
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        });
    };

    // Обработка форм
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', handleFormSubmit);
    });
});

function animateElements() {
    const elements = document.querySelectorAll('.animate-on-load');
    elements.forEach((el, index) => {
        setTimeout(() => {
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
        }, index * 100);
    });
}

function handleFormSubmit(e) {
    const form = e.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<div class="spinner-border spinner-border-sm"></div>';
}
