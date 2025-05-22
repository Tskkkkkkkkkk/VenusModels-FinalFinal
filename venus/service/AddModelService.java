package com.venus.service;

import com.venus.config.DbConfig;
import com.venus.model.ModelModel;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class AddModelService {

    public boolean addModel(ModelModel model) {
        String sql = "INSERT INTO model (ModelID, ModelName, ModelContact, Height, Weight, Eyecolor) VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DbConfig.getDbConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setInt(1, model.getModelID());
            stmt.setString(2, model.getModelName());
            stmt.setString(3, model.getModelContact());
            stmt.setString(4, model.getHeight());
            stmt.setString(5, model.getWeight());
            stmt.setString(6, model.getEyecolor());

            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}