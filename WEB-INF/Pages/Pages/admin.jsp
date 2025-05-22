<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Venus Admin Dashboard</title>
  <link rel="stylesheet" href="${pageContext.request.contextPath}/css/admindash.css"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=Playfair+Display:wght@600&display=swap" rel="stylesheet">
</head>
<body class="vs-bg">
  <div class="dashboard">
    <aside class="sidebar">
      <h2 class="logo">Admin</h2>
      <nav class="nav">
        <a href="${pageContext.request.contextPath}/admin" class="nav-link"> Dashboard</a>
       <a href="${pageContext.request.contextPath}/AdmindirectoryController" class="nav-link"> Directory</a>
       <a href="#" class="nav-link">Booking Inquiries</a>
        <a href="settings.html" class="nav-link">Settings</a>
        <a href="${pageContext.request.contextPath}/logout" class="nav-link">Logout</a>
      </nav>
    </aside>

    <main class="main">
      <div class="top-center">
        <h1 class="venus-title">Venus</h1>
        <div class="search-container">
          <input type="text" placeholder="Search..." class="search-input">
          <span class="search-icon">
            <i class="fas fa-search"></i>
          </span>
        </div>
        
      </div>

      <div class="info-cards">
        <div class="card">Total Portfolio<br><strong>40</strong></div>
        <div class="card">Selected Portfolio<br><strong>12</strong></div>
        <div class="card">Messages<br><strong>3</strong></div>
      </div>

      <div class="model-table">
        <table>
          <thead>
            <tr>
              <th>Model ID</th>
              <th>Model Name</th>
              <th>Model Contact</th>
              <th>Height</th>
              <th>Weight</th>
              <th>Eye Color</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>001<br>
              <td>Kaia Gerber</td>
              <td>kaia@gmail.com</td>
              <td>170CM</td>
              <td>50kg</td>
              <td>Blue</td>
            </tr>
            <tr>
                <td>002<br>
                <td>Bella Hdid</td>
                <td>bella@gmail.com</td>
                <td>178CM</td>
                <td>48kg</td>
                 <td>Blue</td>
            </tr>
            <tr>
                <td>003<br>
                <td>Alex Consani</td>
                <td>alex@gmail.com</td>
                <td>172CM</td>
                <td>54kg</td>
                <td>Brown</td>
            </tr>
            <tr>
                <td>004<br>
                <td>Liu Wen</td>
                <td>liu@gmail.com</td>
                <td>177CM</td>
                <td>56kg</td>
                 <td>Blue</td>
            </tr>
          </tbody>
        </table>
      </div>
    </main>
  </div>
</body>