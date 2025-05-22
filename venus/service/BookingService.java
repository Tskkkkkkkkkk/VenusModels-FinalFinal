package com.venus.service;

import com.venus.config.DbConfig;
import com.venus.model.BookingModel;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class BookingService {

    public void saveBooking(BookingModel booking) {
        String sql = "INSERT INTO bookings (BookingName, BookingDate, BookingTime) VALUES (?, ?, ?)";

        try (Connection conn = DbConfig.getDbConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, booking.getBookingName());
            stmt.setString(2, booking.getBookingDate());
            stmt.setString(3, booking.getBookingTime());
            stmt.executeUpdate();

        } catch (SQLException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
