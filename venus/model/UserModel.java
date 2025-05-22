package com.venus.model;

public class UserModel {

    private int userID;
    private String userName;
    private String userContact;
    private String userRole;
    private String password;

    // Default constructor
    public UserModel() {
    }

    // Full constructor
    public UserModel(int userID, String userName, String userContact, String userRole, String password) {
        this.userID = userID;
        this.userName = userName;
        this.userContact = userContact;
        this.userRole = userRole;
        this.password = password;
    }

    // Constructor for registration (without userID and role)
    public UserModel(String userName, String userContact, String password) {
        this.userName = userName;
        this.userContact = userContact;
        this.password = password;
    }

    // Constructor for login
    public UserModel(String userName, String password) {
        this.userName = userName;
        this.password = password;
    }

    public int getUserID() {
        return userID;
    }

    public void setUserID(int userID) {
        this.userID = userID;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserContact() {
        return userContact;
    }

    public void setUserContact(String userContact) {
        this.userContact = userContact;
    }

    public String getUserRole() {
        return userRole;
    }

    public void setUserRole(String userRole) {
        this.userRole = userRole;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
