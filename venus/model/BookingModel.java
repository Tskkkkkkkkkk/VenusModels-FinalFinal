package com.venus.model;

public class BookingModel {

    private int BookingID;
    private String BookingName;
    private String BookingDate;
    private String BookingTime;

    public BookingModel() {}

    public BookingModel(int bookingId, String bookingName, String bookingDate, String bookingTime) {
        this.BookingID = bookingId;
        this.BookingName = bookingName;
        this.BookingDate = bookingDate;
        this.BookingTime = bookingTime;
    }

    public BookingModel(String bookingName, String bookingDate, String bookingTime) {
        this.BookingName = bookingName;
        this.BookingDate = bookingDate;
        this.BookingTime = bookingTime;
    }

    // Getters and Setters
    public int getBookingId() {
        return BookingID;
    }

    public void setBookingId(int bookingId) {
        this.BookingID = bookingId;
    }

    public String getBookingName() {
        return BookingName;
    }

    public void setBookingName(String bookingName) {
        this.BookingName = bookingName;
    }

    public String getBookingDate() {
        return BookingDate;
    }

    public void setBookingDate(String bookingDate) {
        this.BookingDate = bookingDate;
    }

    public String getBookingTime() {
        return BookingTime;
    }

    public void setBookingTime(String bookingTime) {
        this.BookingTime = bookingTime;
    }
}
