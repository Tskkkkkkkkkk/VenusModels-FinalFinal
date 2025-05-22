package com.venus.service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.ResultSet;

import com.venus.config.DbConfig;
import com.venus.model.UserModel;

public class RegisterService {

    private Connection dbConn;

    public RegisterService() {
        try {
            this.dbConn = DbConfig.getDbConnection();
        } catch (Exception ex) {
            System.err.println(" DB Connection Error: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    public boolean register(UserModel user) {
        if (dbConn == null) {
            System.err.println(" DB connection is null.");
            return false;
        }

        String sql = "INSERT INTO User (UserName, UserContact, password) VALUES (?, ?, ?)";

        try (PreparedStatement stmt = dbConn.prepareStatement(sql)) {
            System.out.println("✔ Inserting user: " + user.getUserName());

            stmt.setString(1, user.getUserName());
            stmt.setString(2, user.getUserContact());
            stmt.setString(3, user.getPassword());

            int result = stmt.executeUpdate();
            System.out.println("⏺ Rows inserted: " + result);
            return result > 0;

        } catch (SQLException e) {
            System.err.println("Error inserting user: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public boolean isUsernameTaken(String username) {
        String query = "SELECT COUNT(*) FROM User WHERE UserName = ?";

        try (PreparedStatement stmt = dbConn.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            return rs.next() && rs.getInt(1) > 0;
        } catch (SQLException e) {
            System.err.println(" Username check failed: " + e.getMessage());
            e.printStackTrace();
            return true;
        }
    }
}


