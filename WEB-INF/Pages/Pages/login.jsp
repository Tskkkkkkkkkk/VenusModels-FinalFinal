<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Venus Login Page</title>
  <link rel="stylesheet" href="${pageContext.request.contextPath}/css/loginpages.css"/>
</head>
<body>
  <header>
    <div class="nav-container">
      <div class="nav-left"></div>
      <h1 class="logo">Venus</h1>
      <nav class="nav-right">
        <div class="nav-links">
  <a href="${pageContext.request.contextPath}/index">Home</a>
  <a href="${pageContext.request.contextPath}/directory">Directory</a>
  <a href="#">Get Scouted</a>
  <a href="${pageContext.request.contextPath}/login">Login</a>
</div>
        
      </nav>
    </div>
  </header>

  <main class="main">
    <div class="box">
      <div class="login-section">
        <div class="login-form">
          <div class="header-with-icons">
            <h2>Log In</h2>
            <div class="social-icons">
              <img src="${pageContext.request.contextPath}/images/ficon.png" alt="Facebook" />
              <img src="${pageContext.request.contextPath}/images/iicon.png" alt="Instagram" />
            </div>
          </div>
          <form action="${pageContext.request.contextPath}/login" method="post">
            <div class="form-group">
              <label for="username">Username</label>
              <input type="text" id="username" name="username"/>
            </div>
            <div class="form-group">
              <label for="password">Password</label>
              <input type="password" id="password" name="password"/>
            </div>
            <div class="forgot-password">
              <a href="#">Forgot Password?</a>
            </div>
            <button type="submit">Log In</button>
            <div class="checkbox">
              <input type="checkbox" id="remember" />
              <label for="remember">Remember Me</label>
            </div>
          </form>
        </div>
      </div>

      <div class="image-section">
        <div class="overlay">
          <h2>Welcome to Login</h2>
          <p>Don't have an account?</p>
          <a href="${pageContext.request.contextPath}/register">
          <button  class="signup-btn">Sign Up</button>
          </a>
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
            src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3153.1189602153655!2d-122.41941508468143!3d37.77492977975956!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x80858064c1b9f7b7%3A0x8b0a8a85b8a4eec1!2sSan%20Francisco%2C%20CA!5e0!3m2!1sen!2sus!4v1616180798880!5m2!1sen!2sus" 
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