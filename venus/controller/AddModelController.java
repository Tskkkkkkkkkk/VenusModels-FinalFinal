package com.venus.controller;

import com.venus.model.ModelModel;
import com.venus.service.AddModelService;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@WebServlet("/addmodel")
public class AddModelController<ModelService> extends HttpServlet {
    private final AddModelService modelService = new AddModelService();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        request.getRequestDispatcher("/WEB-INF/Pages/addmodel.jsp").forward(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            int modelID = Integer.parseInt(request.getParameter("modelID"));
            String modelName = request.getParameter("modelName");
            String modelContact = request.getParameter("modelContact");
            String height = request.getParameter("height");
            String weight = request.getParameter("weight");
            String eyeColor = request.getParameter("eyeColor");

            ModelModel model = new ModelModel(modelID, modelName, modelContact, height, weight, eyeColor);
            boolean success = modelService.addModel(model);

            if (success) {
                request.setAttribute("message", "Model added successfully!");
            } else {
                request.setAttribute("error", "Failed to add model. Try again.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            request.setAttribute("error", "Invalid input or internal error.");
        }
        request.getRequestDispatcher("/WEB-INF/Pages/addmodel.jsp").forward(request, response);
    }
}