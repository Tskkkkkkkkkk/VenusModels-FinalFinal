package com.venus.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import com.venus.model.UserModel;
import com.venus.util.CookieUtil;
import com.venus.util.SessionUtil;
import com.venus.service.LoginService;

/**
 * Servlet implementation class LoginController
 */
@WebServlet(asyncSupported = true, urlPatterns = { "/login" })
public class LoginController extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private final LoginService loginService = new LoginService();

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public LoginController() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// Forward to login page
		request.getRequestDispatcher("/WEB-INF/Pages/login.jsp").forward(request, response);
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		String username = request.getParameter("username");
		String password = request.getParameter("password");
		
		System.out.println(username);
		System.out.println(password);


		// Validate empty input
		if (username == null || password == null || username.isEmpty() || password.isEmpty()) {
			request.setAttribute("error", "Username and password must not be empty.");
			request.getRequestDispatcher("/WEB-INF/Pages/login.jsp").forward(request, response);
			return;
		}

		// Admin check
		if ("admin".equals(username) && "admin".equals(password)) {
			CookieUtil.addCookie(response, "role", "admin", 5 * 60); // 5 hours
			SessionUtil.setAttribute(request, "username", username);
			response.sendRedirect(request.getContextPath() + "/admin");
			return;
		}

		// Regular user login
		UserModel userModel = new UserModel(username, password);
		Boolean loginStatus = loginService.loginUser(userModel);
		System.out.println("Login Status: " + loginStatus);

		if (Boolean.TRUE.equals(loginStatus)) {
			SessionUtil.setAttribute(request, "username", username);
			CookieUtil.addCookie(response, "role", "student", 5 * 60); // 5 hours
			response.sendRedirect(request.getContextPath() + "/clientdirectory");
		} else {
			handleLoginFailure(request, response, loginStatus);
		}
	}

	private void handleLoginFailure(HttpServletRequest request, HttpServletResponse response, Boolean loginStatus)
			throws ServletException, IOException {

		String errorMessage;
		if (loginStatus == null) {
			errorMessage = "Our server is under maintenance. Please try again later!";
		} else {
			errorMessage = "User credential mismatch. Please try again!";
		}

		request.setAttribute("error", errorMessage);
		request.getRequestDispatcher("/WEB-INF/Pages/login.jsp").forward(request, response);
	}
}
