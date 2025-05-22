package com.venus.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Arrays;

/**
 * Utility class for managing cookies in the Venus Models web application.
 */
public class CookieUtil {

    /**
     * Adds a cookie to the response.
     *
     * @param response HttpServletResponse to add the cookie to
     * @param name     Name of the cookie
     * @param value    Value of the cookie
     * @param maxAge   Expiration time in seconds
     */
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setMaxAge(maxAge);
        cookie.setPath("/"); // Make available across entire application
        response.addCookie(cookie);
    }

    /**
     * Retrieves a cookie by name from the request.
     *
     * @param request HttpServletRequest containing cookies
     * @param name    Name of the cookie to find
     * @return The Cookie object if found, else null
     */
    public static Cookie getCookie(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                         .filter(c -> name.equals(c.getName()))
                         .findFirst()
                         .orElse(null);
        }
        return null;
    }

    /**
     * Deletes a cookie by setting its max age to 0.
     *
     * @param response HttpServletResponse to send the deletion
     * @param name     Name of the cookie to delete
     */
    public static void deleteCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
