<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Venus Models Agency</title>
  <link rel="stylesheet" href="${pageContext.request.contextPath}/css/style.css"/>
<script src="script.js"></script>
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
  <a href= "${pageContext.request.contextPath}/index">Home</a>
  <a href= "${pageContext.request.contextPath}/directory">Directory</a>
  <a href="#">Get Scouted</a>
  <a href="${pageContext.request.contextPath}/login">Login</a>
</div>
      
    </nav>
  </header>

  <main>
   
    <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 14.38.41.png" class="Maincover">
    <div class="grid-wrapper">
      <div class="left">
        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 16.25.07.png" alt="Big Image">
      </div>
      
      <div class="right">
        <div class="top-small">
          <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 16.28.09.png" alt="Small Top Left">
          <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 16.05.41.png" alt="Small Top Right">
        </div>
        <div class="bottom-wide">
          <img src="${pageContext.request.contextPath}/images/Valentino Spring_Summer 1998 Advertising Campaign Model_ Danielle Zinaich Photographer_ Michael Thompson.jpg" alt="Wide Top">
          <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 16.19.13.png" alt="Wide Bottom">
        </div>
      </div>
    </div>
  </main>


  

</body>
</html>
    