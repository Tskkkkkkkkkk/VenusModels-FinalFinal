package com.venus.controller;

import com.venus.model.BookingModel;
import com.venus.service.BookingService;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@WebServlet("/book")
public class BookingController extends HttpServlet {

    private BookingService bookingService = new BookingService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String bookingName = req.getParameter("bookingName");
        String bookingDate = req.getParameter("bookingDate");
        String bookingTime = req.getParameter("bookingTime");

        BookingModel booking = new BookingModel(bookingName, bookingDate, bookingTime);
        bookingService.saveBooking(booking);
    }
}
