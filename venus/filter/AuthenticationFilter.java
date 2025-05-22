package com.venus.filter;

import com.venus.util.CookieUtil;
import com.venus.util.SessionUtil;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Authentication filter for Venus Models that restricts access based on session and cookie role.
 */
@WebFilter("/*")
public class AuthenticationFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
            }

    @Override
    public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String uri = req.getRequestURI();
        boolean isLoggedIn = SessionUtil.getAttribute(req, "username") != null;
        String role = null;
        if (CookieUtil.getCookie(req, "role") != null) {
            role = CookieUtil.getCookie(req, "role").getValue();
        }
        if (uri.endsWith("/login") || uri.endsWith("/signup")
            || uri.endsWith("register.jsp") || uri.endsWith("/register")
            || uri.endsWith("index.jsp") || uri.endsWith("/index")
            || uri.endsWith("directory.jsp") || uri.endsWith("/directory")
            || uri.contains("/css/") || uri.contains("/js/") || uri.contains("/images/")
            || uri.contains("/fonts/") || uri.contains("/favicon.ico")) {
            chain.doFilter(request, response);
            return;
        }

        if (isLoggedIn) {
            if ("admin".equals(role) && uri.contains("/admin")) {
                chain.doFilter(request, response);
                return;
            } else if ("client".equals(role) && !uri.contains("/admin")) {
                chain.doFilter(request, response);
                return;
            } else if (!uri.contains("/admin")) {
                chain.doFilter(request, response);
                return;
            }
        }

        res.sendRedirect(req.getContextPath() + "/login");
    }

    @Override
    public void destroy() {
    }
}

