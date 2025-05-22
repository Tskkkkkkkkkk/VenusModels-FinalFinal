<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Add New Model</title>
  <link rel="stylesheet" href="${pageContext.request.contextPath}/css/addmodel.css" />
</head>
<body>

<main class="main">
  <div class="box">
    <div class="login-section">
      <div class="login-form">
        <div class="header-with-icons">
          <h2>Add New Model</h2>
          <div class="social-icons">
            <img src="${pageContext.request.contextPath}/images/ficon.png" alt="Facebook" />
            <img src="${pageContext.request.contextPath}/images/iicon.png" alt="Instagram" />
          </div>
        </div>

        <!-- Success Message -->
        <c:if test="${not empty message}">
          <p style="color: green;">${message}</p>
        </c:if>

        <!-- Error Message -->
        <c:if test="${not empty error}">
          <p style="color: red;">${error}</p>
        </c:if>

        <!-- Add Model Form -->
<form action="${pageContext.request.contextPath}/addmodel" method="post">
  <input type="hidden" name="action" value="add" />

          <div class="form-row">
            <div class="form-group">
              <label for="modelID">Model ID</label>
              <input type="text" id="modelID" name="modelID" required />
            </div>
            <div class="form-group">
              <label for="modelName">Model Name</label>
              <input type="text" id="modelName" name="modelName" required />
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="modelContact">Model Contact</label>
              <input type="text" id="modelContact" name="modelContact" required />
            </div>
            <div class="form-group">
              <label for="height">Height (cm)</label>
              <input type="text" id="height" name="height" required />
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="weight">Weight</label>
              <input type="text" id="weight" name="weight" required />
            </div>
            <div class="form-group">
              <label for="eyeColor">Eye Color</label>
              <input type="text" id="eyeColor" name="eyeColor" required />
            </div>
          </div>

          <button type="submit">Add Model</button>
        </form>

       </div>
      </div>

    <div class="image-section">
      <div class="overlay">
        <h2>Manage Models</h2>
        <p>Want to view all models?</p>
        <button onclick="window.location.href='${pageContext.request.contextPath}/admin'" class="signup-btn">Dashboard</button>
      </div>
    </div>
  </div>
</main>

<footer>
  <div class="footer-container">
    <div class="footer-top">
      <div class="footer-socials">
        <a href="https://instagram.com" target="_blank">
          <img src="${pageContext.request.contextPath}/images/info.jpg" alt="Instagram">
        </a>
        <a href="https://tiktok.com" target="_blank">
          <img src="${pageContext.request.contextPath}/images/tikfo.jpg" alt="TikTok">
        </a>
      </div>
      <div class="footer-map">
        <iframe 
          src="https://www.google.com/maps/embed?pb=..." 
          width="500" 
          height="200" 
          style="border:0;" 
          allowfullscreen="" 
          loading="lazy">
        </iframe>
      </div>
    </div>
    <p class="footer-copy">© 2025 Venus Company. All rights reserved.</p>
  </div>
</footer>

</body>
</html>

