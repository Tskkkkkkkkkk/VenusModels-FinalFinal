<%= java.time.LocalDate.now() %>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Venus Models</title>
 <link rel="stylesheet" href="${pageContext.request.contextPath}/css/portfoliio.css">
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

      <div class="page-background">
  <div class="container">
    <div class="left-side">
      <h2>Julia Hafstrom</h2>
      <p>Height: 170</p>
      <div class="buttons">
  <form action="${pageContext.request.contextPath}/book" method="post">
    <input type="hidden" name="name" value="Julia Hafstrom" />
    <input type="hidden" name="date" value="<%= java.time.LocalDate.now() %>" />
    <input type="hidden" name="time" value="<%= java.time.LocalTime.now().withSecond(0).withNano(0) %>" />
    <button class="book-button" type="submit">BOOK HER</button>
  </form>

  <button class="download-button">DOWNLOAD PORTFOLIO</button>
</div>

    </div>

    <div class="right-side">
      <div class="slide-container" id="slides">
        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-05-20 at 12.40.30.png" alt="Model 1">
        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-05-20 at 12.40.52.png" alt="Model 2">
        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-05-20 at 12.39.58.png" alt="Model 3">
      </div>
      <div class="navigation">
        <button class="nav-button" onclick="prevSlide()">&#10094;</button>
        <button class="nav-button" onclick="nextSlide()">&#10095;</button>
      </div>
    </div>
  </div>
</div>
<script src="${pageContext.request.contextPath}/js/portfolioo.js"></script>
</body>
</html>
