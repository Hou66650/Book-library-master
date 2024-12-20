// script.js
(function() {
    const slides = document.querySelectorAll('.slide');
    const radioButtons = document.querySelectorAll('input[name="radio-btn"]');
    let currentSlide = 0;
    const totalSlides = slides.length;
    const slideInterval = 1000; // 换片间隔时间，单位毫秒

    function nextSlide() {
        radioButtons[currentSlide].checked = false;
        currentSlide = (currentSlide + 1) % totalSlides;
        radioButtons[currentSlide].checked = true;
    }

    setInterval(nextSlide, slideInterval);
})();