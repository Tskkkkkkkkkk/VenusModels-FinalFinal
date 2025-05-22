<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>

<html lang="en">

<head>

  <meta charset="UTF-8" />

  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>

  <title>Venus Sign Up Page</title>

  <link rel="stylesheet" href="${pageContext.request.contextPath}/css/registerpage.css"/>
 

</head>

<body>

    <header>

        <div class="top-bar">

          <h1>Venus</h1>

        </div>

    </header>
  



  <main class="main">

    <div class="box">

      <div class="login-section">

        <div class="login-form">

          <div class="header-with-icons">

            <h2>Register</h2>

            <div class="social-icons">

              <img src="${pageContext.request.contextPath}/images/ficon.png" alt="Facebook" />

              <img src="${pageContext.request.contextPath}/images/iicon.png" alt="Instagram" />

            </div>

          </div>



          <!-- Success Message -->

          <!-- Success Message -->
        <c:if test="${not empty message}">
          <p style="color: green;">${message}</p>
        </c:if>

        <!-- Error Message -->
        <c:if test="${not empty error}">
          <p style="color: red;">${error}</p>
        </c:if>


          <!-- Registration Form -->

          <form action="${pageContext.request.contextPath}/register" method="POST">

            <div class="form-row">

              <div class="form-group">

                <label for="firstName">First Name</label>

                <input type="text" id="firstName" name="firstName"/>

              </div>

              <div class="form-group">

                <label for="lastName">Last Name</label>

                <input type="text" id="lastName" name="lastName" />

              </div>

            </div>



            <div class="form-row">

              <div class="form-group">

                <label for="email">Email</label>

                <input type="email" id="email" name="email"/>

              </div>

                <div class="form-group">

                <label for="contact">Contact Number</label>

                <input type="text" id="contact" name="contact"/>

              </div>

            </div>



            <div class="form-row">

              <div class="form-group">

                <label for="username">Username</label>

                <input type="text" id="username" name="username"/>

              </div>

              <div class="form-group">

                <label for="password">Password</label>

                <input type="password" id="password" name="password"/>

              </div>

            </div>



            <div class="form-group">

              <label for="confirm_password">Confirm Password</label>

              <input type="password" id="confirm_password" name="confirm_password"/>

            </div>



            <button type="submit">Sign Up</button>

          </form>

        </div>

      </div>



      <div class="image-section">
  <div class="image-wrapper">
    <img src="${pageContext.request.contextPath}/images/back.jpg" alt="Welcome Image" class="signup-image"/>
    </div>
    <div class="overlay">
     <h2>Welcome to Venus</h2>
     <p>Already have an account?</p>
     <button onclick="window.location.href='${pageContext.request.contextPath}/login'" class="signup-btn">Log In</button>
    </div>
</div>

    </div>

  </main>



 <footer>

    <div class="footer-container">

      <div class="footer-top">

        <div class="footer-socials">

                 <a href="https://www.instagram.com/islingtoncollege?utm_source=ig_web_button_share_sheet&igsh=ZDNlZDc0MzIxNw==" target="_blank">

  <img src="${pageContext.request.contextPath}/images/Instagram Black And White Logo Vector Png.jpg" alt="Instagram">

</a>



        <a href="https://www.tiktok.com/@islingtoncollege?_t=ZS-8wWzfmXmpWu&_r=1" target="_blank">

        

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