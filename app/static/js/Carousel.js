let currentIndex = 0;
const images = document.querySelectorAll('.carousel-images img');
const totalImages = images.length;

function showNextImage() {
  images[currentIndex].style.display = 'none';
  currentIndex = (currentIndex + 1) % totalImages;
  images[currentIndex].style.display = 'block';
}

setInterval(showNextImage, 3000); // Change image every 3 seconds
