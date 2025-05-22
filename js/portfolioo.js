window.addEventListener('DOMContentLoaded', () => {
  const slides = document.getElementById('slides');
  if (!slides) return;

  const totalSlides = slides.children.length;
  let index = 0;

  function showSlide(idx) {
    slides.style.transform = `translateX(-${idx * 100}%)`;
  }

  window.nextSlide = function () {
    index = (index + 1) % totalSlides;
    showSlide(index);
  };

  window.prevSlide = function () {
    index = (index - 1 + totalSlides) % totalSlides;
    showSlide(index);
  };

  // Optional: Initialize first slide
  showSlide(index);
});
