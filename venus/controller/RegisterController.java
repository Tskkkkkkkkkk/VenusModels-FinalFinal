package com.venus.controller;
import com.venus.model.UserModel;
import com.venus.service.RegisterService;
import com.venus.util.PasswordUtil;
import com.venus.util.ValidationUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Handles user registration with validation and encrypted password storage.
 */
@WebServlet(urlPatterns = { "/register", "/" })
public class RegisterController extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private final RegisterService registerService = new RegisterService();

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		request.getRequestDispatcher("/WEB-INF/Pages/register.jsp").forward(request, response);
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		String userName = request.getParameter("username");
		String contact = request.getParameter("contact");
		String password = request.getParameter("password");
		String confirmPassword = request.getParameter("confirm_password");

		String validationError = validateRegistrationForm(userName, contact, password, confirmPassword);
		if (validationError != null) {
			request.setAttribute("error", validationError);
			request.getRequestDispatcher("/WEB-INF/Pages/register.jsp").forward(request, response);
			return;
		}

		try {
			String encryptedPassword = PasswordUtil.encrypt(userName, password);
			UserModel user = new UserModel(userName, contact, encryptedPassword);

			if (registerService.isUsernameTaken(userName)) {
				request.setAttribute("error", "An account with this username already exists.");
				request.getRequestDispatcher("/WEB-INF/Pages/register.jsp").forward(request, response);
				return;
			}

			boolean isRegistered = registerService.register(user);

			if (isRegistered) {
				request.setAttribute("message", "Registration successful! Please log in.");
				request.getRequestDispatcher("/WEB-INF/Pages/register.jsp").forward(request, response);
			} else {
				request.setAttribute("error", "Registration failed. Please try again later.");
				request.getRequestDispatcher("/WEB-INF/Pages/register.jsp").forward(request, response);
			}

		} catch (Exception e) {
			request.setAttribute("error", "Unexpected error occurred.");
			request.getRequestDispatcher("/WEB-INF/Pages/register.jsp").forward(request, response);
			e.printStackTrace();
		}
	}

	private String validateRegistrationForm(String username, String contact, String password, String confirmPassword) {
		if (ValidationUtil.isNullOrEmpty(username))
			return "Username is required.";
		if (ValidationUtil.isNullOrEmpty(contact))
			return "Contact number is required.";
		if (ValidationUtil.isNullOrEmpty(password))
			return "Password is required.";
		if (ValidationUtil.isNullOrEmpty(confirmPassword))
			return "Please confirm your password.";

		if (!ValidationUtil.isValidPhoneNumber(contact))
			return "Invalid phone number format.";
		if (!ValidationUtil.isValidPassword(password))
			return "Password must contain 1 uppercase, 1 number, and 1 symbol.";
		if (!ValidationUtil.doPasswordsMatch(password, confirmPassword))
			return "Passwords do not match.";

		return null;
	}
}

