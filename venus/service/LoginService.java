package com.venus.service;

import com.venus.config.DbConfig;
import com.venus.model.UserModel;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import com.venus.util.PasswordUtil;

public class LoginService {

	private Connection dbConn;

	private boolean isConnectionError = false;

	/**
	 * 
	 * Constructor initializes the database connection. Sets the connection error
	 * 
	 * flag if the connection fails.
	 * 
	 */

	public LoginService() {

		try {

			dbConn = DbConfig.getDbConnection();

		} catch (SQLException | ClassNotFoundException ex) {

			ex.printStackTrace();

			isConnectionError = true;

		}

	}

	/**
	 * 
	 * Validates the user credentials against the database records.
	 *
	 * 
	 * 
	 * @param studentModel the StudentModel object containing user credentials
	 * 
	 * @return true if the user credentials are valid, false otherwise; null if a
	 * 
	 *         connection error occurs
	 * 
	 */

	public Boolean loginUser(UserModel usermodel) {

		if (isConnectionError) {

			System.out.println("Connection Error!");

			return null;

		}

		String query = "SELECT UserName, password FROM user WHERE UserName = ?";

		try (PreparedStatement stmt = dbConn.prepareStatement(query)) {

			stmt.setString(1, usermodel.getUserName());

			ResultSet result = stmt.executeQuery();

			if (result.next()) {

				return validatePassword(result, usermodel);

			}

		} catch (SQLException e) {

			e.printStackTrace();

			return null;

		}

		return false;

	}

	/**
	 * 
	 * Validates the password retrieved from the database.
	 *
	 * 
	 * 
	 * @param result       the ResultSet containing the username and password from
	 * 
	 *                     the database
	 * 
	 * @param studentModel the StudentModel object containing user credentials
	 * 
	 * @return true if the passwords match, false otherwise
	 * 
	 * @throws SQLException if a database access error occurs
	 * 
	 */

	private boolean validatePassword(ResultSet result, UserModel usermodel) throws SQLException {

		String dbUsername = result.getString("username");

		String dbPassword = result.getString("password");

		System.out.println("DB Username: " + dbUsername);

		System.out.println("DB Encrypted Password: " + dbPassword);

		String decryptedPassword = PasswordUtil.decrypt(dbPassword, dbUsername);

		System.out.println("Decrypted Password: " + decryptedPassword);

		System.out.println("User Entered Password: " + usermodel.getPassword());

		return dbUsername.equals(usermodel.getUserName())
				&& PasswordUtil.decrypt(dbPassword, dbUsername).equals(usermodel.getPassword());

	}

}