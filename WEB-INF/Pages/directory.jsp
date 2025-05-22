<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Venus Models Agency</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="${pageContext.request.contextPath}/css/directory.css">
</head>
<body>

    <header>
        <div class="top-bar">
          <h1>Venus</h1>
        </div>
        
        <nav class="navbar">
          <div class="search-bar">
            <input type="text" placeholder="Search...">
          </div>
          <div class="nav-links">
  <a href="${pageContext.request.contextPath}/index">Home</a>
  <a href="${pageContext.request.contextPath}/directory">Directory</a>
  <a href="#">Get Scouted</a>
  <a href="${pageContext.request.contextPath}/login">Login</a>
</div>

        </nav>
      </header>

  <div class="filter">
    <select>
      <option>Gender</option>
      <option>Female</option>
      <option>Male</option>
      <option>Other</option>
    </select>
  </div>

  <main class="gallery">
    <div class="model-card">
        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.22.27.png" alt="Model 1">
        <div class="model-name">Terra Kinnimonth </div>
      </div>
      
    <div class="model-card">
      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.17.12.png" alt="Model 2">
      <div class="model-name">Hailey Freeman</div>
    </div>
    <div class="model-card">
      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.21.49.png" alt="Model 3">
      <div class="model-name">Soy Kim</div>
    </div>
    <div class="model-card">
      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.21.07 copy.png" alt="Model 4">
      <div class="model-name">Dave Kabamba</div>
    </div>
    <div class="model-card">
      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.14.15.png" alt="Model 5">
      <div class="model-name">Lara Jade</div>
    </div>
    <div class="model-card">
      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.15.06.png" alt="Model 6">
      <div class="model-name">Liu Wen</div>
    </div>
    <div class="model-card">
      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.38.16.png" alt="Model 7">
      <div class="model-name">Julia Hafstrom</div>
    </div>
    <div class="model-card">
      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.37.33.png" alt="Model 8">
      <div class="model-name">Ida Auke</div>
    </div>
    <div class="model-card">
        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.37.00.png" alt="Model 9">
        <div class="model-name">Gustave Lorrè</div>
    </div>
    <div class="model-card">
        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.36.17.png" alt="Model 10">
        <div class="model-name">Alexander Holdbrook</div>
    </div>
    <div class="model-card">
        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 19.03.55.png" alt="Model 11">
        <div class="model-name">Orlagh Mortan</div>
    </div>
        <div class="model-card">
            <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 19.02.48.png" alt="Model 12">
            <div class="model-name">Jeneil</div>
    </div>
  </main>

 <footer>
    <div class="footer-content">
      <div class="socials">
       <a href="https://www.instagram.com/islingtoncollege?utm_source=ig_web_button_share_sheet&igsh=ZDNlZDc0MzIxNw==" target="_blank">
  <img src="${pageContext.request.contextPath}/images/Instagram Black And White Logo Vector Png.jpg" alt="Instagram">
</a>

        <a href="https://www.tiktok.com/@islingtoncollege?_t=ZS-8wWzfmXmpWu&_r=1" target="_blank">
        
            <img src="${pageContext.request.contextPath}/images/tikfo.jpg" alt="TikTok">
          </a>
      </div>
  
      <div class="map">
        <iframe 
          src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3153.1189602153655!2d-122.41941508468143!3d37.77492977975956!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x80858064c1b9f7b7%3A0x8b0a8a85b8a4eec1!2sSan%20Francisco%2C%20CA!5e0!3m2!1sen!2sus!4v1616180798880!5m2!1sen!2sus" 
          width="700" 
          height="200" 
          style="border:0;" 
          allowfullscreen="" 
          loading="lazy">
        </iframe>
      </div>
    </div>
  
    <p>© 2025 Venus Company. All rights reserved.</p>
  </footer>
  

</body>
</html>
    