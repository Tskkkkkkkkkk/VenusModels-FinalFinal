package com.venus.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.venus.util.CookieUtil;
import com.venus.util.SessionUtil;

import java.io.IOException;

/**
 * Servlet implementation class LogoutController
 * Handles both GET and POST logout requests.
 */
@WebServlet(asyncSupported = true, urlPatterns = {"/logout"})
public class LogoutController extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /**
     * Processes logout for both GET and POST methods.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logoutUser(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logoutUser(request, response);
    }

    /**
     * Common logout logic to clear session and cookies.
     */
    private void logoutUser(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Remove authentication cookie and invalidate session
        CookieUtil.deleteCookie(response, "role");
        SessionUtil.invalidate(request);
        response.sendRedirect(request.getContextPath() + "/login");
    }
}
