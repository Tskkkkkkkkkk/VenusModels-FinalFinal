package com.venus.service;

import com.venus.config.DbConfig;
import com.venus.model.UserModel;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Service class for dashboard-related operations in Venus Models.
 */
public class DashboardService {

    /**
     * Fetches a user's data from the database by username.
     *
     * @param username the username of the logged-in user
     * @return a UserModel object with data, or null if not found
     * @throws ClassNotFoundException 
     */
    public UserModel getUserByUsername(String username) throws ClassNotFoundException {
        String sql = "SELECT * FROM users WHERE username = ?";

        try (Connection conn = DbConfig.getDbConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                UserModel user = new UserModel();
                user.setUserID(rs.getInt("id"));
                user.setUserName(rs.getString("username"));
                user.setUserContact(rs.getString("contact"));
                user.setUserRole(rs.getString("role"));
                user.setPassword(rs.getString("password")); // optional: avoid returning password
                return user;
            }

        } catch (SQLException e) {
            e.printStackTrace(); // or use proper logging
        }

        return null;
    }
}
