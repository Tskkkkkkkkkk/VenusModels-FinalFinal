package com.venus.config;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DbConfig {



	private static final String DB_Name = "Agency";

	private static final String URL = "jdbc:mysql://localhost:3316/" + DB_Name;

	private static final String USERNAME= "root";

	private static final String PASSWORD = "";




	/**

	 *

	 * @return Connection object for the database

	 * @throws SQLException  if a database access error occurs

	 * @throws ClassNotFoundException if the JDBC driver class is not found b

	 */


	public static Connection getDbConnection()

			throws SQLException, ClassNotFoundException{

		Class.forName("com.mysql.cj.jdbc.Driver");

		return DriverManager.getConnection(URL, USERNAME, PASSWORD);

	}


	public static void main(String[] args) {

        try (Connection conn = getDbConnection()) {

            if (conn != null) {

                System.out.println("Database Connection Successful!");

                System.out.println("Connected to database: " + conn.getCatalog());

            }

        } catch (SQLException | ClassNotFoundException e) {

            System.out.println("Database Connection Failed: " + e.getMessage());

        }

    }

}