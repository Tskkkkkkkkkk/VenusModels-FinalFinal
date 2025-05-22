<%@ page language="java" contentType="text/html; charset=UTF-8"

    pageEncoding="UTF-8"%>

<!DOCTYPE html>

<html lang="en">

<head>

  <meta charset="UTF-8">

  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>Venus Models Agency</title>

  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
 <link rel="stylesheet" href="${pageContext.request.contextPath}/css/admindire.css"/>



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

  <a href="${pageContext.request.contextPath}/admin">Dashboard</a>

  <a href="${pageContext.request.contextPath}/login">Login</a>

          </div>

        </nav>

      </header>



  <main class="gallery">
    <div class="model add-model-card" onclick="addModel()">
      <div class="overlay">
   <a href="${pageContext.request.contextPath}/addmodel" style="text-decoration: none; color: inherit;">
  <p style="font-size: 1.2rem; font-weight: bold;">+ Add Model</p>
</a>

  </div>
</div>
    <a href="portfolio/portfolio3.html">
    <div class="model">

        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.22.27.png" alt="Model 1">

        <div class="overlay">

            <p><strong>Name:</strong> Terra Kinnimonth</p>

            <p><strong>Height:</strong> 180 cm</p>

            <p><strong>Weight:</strong> 55</p>

            <p><strong>Eye Color:</strong> Green</p>
            <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

          </div>

      </div>

    </a>

      <div class="model">

      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.17.12.png" alt="Model 2">

      <div class="overlay">

        <p><strong>Name:</strong>Hailey Freeman</p>

        <p><strong>Height:</strong> 175 cm</p>

        <p><strong>Weight:</strong> 45</p>

        <p><strong>Eye Color:</strong> Brown</p>
        <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

      </div>

    </div>

    <a href="portfolio/portfolio3.html">

    <div class="model">

      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.21.49.png" alt="Model 3">

      <div class="overlay">

        <p><strong>Name:</strong>Soy Kim</p>

        <p><strong>Height:</strong> 172 cm</p>

        <p><strong>Weight:</strong> 48</p>

        <p><strong>Eye Color:</strong> Brown</p>
        <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

      </div>

    </div>

    </a>

    <div class="model">

      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.21.07 copy.png" alt="Model 4">

      <div class="overlay">

        <p><strong>Name:</strong>Dave Kabamba</p>

        <p><strong>Height:</strong> 187 cm</p>

        <p><strong>Weight:</strong> 60</p>

        <p><strong>Eye Color:</strong> Brown</p>
        <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

      </div>

    </div>

    <a href="${pageContext.request.contextPath}/Portfolioo">

    <div class="model">

      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.14.15.png" alt="Model 5">

      <div class="overlay">

        <p><strong>Name:</strong>Lara Jade</p>

        <p><strong>Height:</strong> 172 cm</p>

        <p><strong>Weight:</strong> 50</p>

        <p><strong>Eye Color:</strong> Brown</p>
        <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

      </div>

    </div>

    </a>

    <div class="model">

      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.15.06.png" alt="Model 6">

      <div class="overlay">

        <p><strong>Name:</strong> Liu Wen</p>

        <p><strong>Height:</strong> 177 cm</p>

        <p><strong>Weight:</strong> 50</p>

        <p><strong>Eye Color:</strong> Brown</p>
        <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

      </div>

    </div>

    <div class="model">

        <a href="${pageContext.request.contextPath}/Portfolioo">

      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.38.16.png" alt="Model 7">

      <div class="overlay">

        <p><strong>Name:</strong> Julia Hafstrom</p>

        <p><strong>Height:</strong> 170 cm</p>

        <p><strong>Age:</strong> 25</p>

        <p><strong>Eye Color:</strong> Brown</p>
        <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

      </div>

    </a>

    </div>

    <div class="model">

      <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.37.33.png" alt="Model 8">

      <div class="overlay">

        <p><strong>Name:</strong> Ida Auke</p>

        <p><strong>Height:</strong> 170 cm</p>

        <p><strong>Weight:</strong> 49</p>

        <p><strong>Eye Color:</strong> Brown</p>
        <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

      </div>

    </div>

    <div class="model">

        <a href="portfolio/portfolio9.html">

        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.37.00.png" alt="Model 9">

        <div class="overlay">

            <p><strong>Name:</strong> Gustave Lorré</p>

            <p><strong>Height:</strong> 195 cm</p>

            <p><strong>Weight:</strong> 70</p>

            <p><strong>Eye Color:</strong> Brown</p>
            <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

          </div>

        </a>

    </div>

    <div class="model">

        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 18.36.17.png" alt="Model 10">

        <div class="overlay">

            <p><strong>Name:</strong> Alexander Holdbrook</p>

            <p><strong>Height:</strong> 175 cm</p>

            <p><strong>Weight:</strong> 50</p>

            <p><strong>Eye Color:</strong> Brown</p>
            <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

          </div>

    </div>

    <div class="model">

        <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 19.03.55.png" alt="Model 11">

        <div class="overlay">

            <p><strong>Name:</strong> Orlagh Mortan</p>

            <p><strong>Height:</strong> 175 cm</p>

            <p><strong>Weight:</strong> 50</p>

            <p><strong>Eye Color:</strong> Blue</p>
            <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

          </div>

    </div>

        <div class="model">

            <img src="${pageContext.request.contextPath}/images/Screenshot 2025-04-14 at 19.02.48.png" alt="Model 12">

            <div class="overlay">

                <p><strong>Name:</strong>Jeneil</p>

                <p><strong>Height:</strong> 177 cm</p>

                <p><strong>Weight:</strong> 56</p>

                <p><strong>Eye Color:</strong> Brown</p>
                <button class="delete-btn" onclick="deleteModel(this)">Delete</button>

              </div>

    </div>

  </main>



  <footer>

    <div class="footer-content">

      <div class="socials">

        <a href="https://instagram.com" target="#">

          <img src="${pageContext.request.contextPath}/images/Instagram Black And White Logo Vector Png.jpg" alt="Instagram">

        </a>

        <a href="https://tiktok.com" target="#">

          <img src="${pageContext.request.contextPath}/images/colorful tiktok logo on transparent background PNG.jpg" alt="TikTok">

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

 <script>
  function deleteModel(button) {
    const modelCard = button.closest('.model');
    if (confirm("Are you sure you want to delete this model?")) {
      modelCard.remove();
    }
  }
</script>

</body>

</html>