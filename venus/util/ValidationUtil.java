package com.venus.util;

import java.util.regex.Pattern;

public class ValidationUtil {

    // 1. Check if field is null or empty
    public static boolean isNullOrEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    // 2. Validate alphabetic names
    public static boolean isOnlyAlphabets(String value) {
        return value != null && value.matches("^[a-zA-Z]+$");
    }

    // 3. Validate alphanumeric username (starting with letter)
    public static boolean isAlphanumericStartingWithLetter(String value) {
        return value != null && value.matches("^[a-zA-Z][a-zA-Z0-9]{5,}$");
    }

    // 4. Validate valid gender
    public static boolean isValidGender(String value) {
        return value != null && (value.equalsIgnoreCase("male") || value.equalsIgnoreCase("female") || value.equalsIgnoreCase("other"));
    }

    // 5. Validate valid email
    public static boolean isValidEmail(String email) {
        String emailRegex = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$";
        return email != null && Pattern.matches(emailRegex, email);
    }

    // 6. Validate phone number starting with 98 and 10 digits
    public static boolean isValidPhoneNumber(String number) {
        return number != null && number.matches("^98\\d{8}$");
    }

    // 7. Validate secure password: 1 uppercase, 1 number, 1 special char, min 8 chars
    public static boolean isValidPassword(String password) {
        // Accepts any special character (non-letter/number)
        String passwordRegex = "^(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}$";
        return password != null && password.matches(passwordRegex);
    }

    // 8. Confirm password match
    public static boolean doPasswordsMatch(String password, String confirmPassword) {
        return password != null && password.equals(confirmPassword);
    }
}
