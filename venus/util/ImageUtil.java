package com.venus.util;

import java.io.File;
import java.io.IOException;

import jakarta.servlet.http.Part;

/**
 * Utility class for handling image uploads in the Venus Models project.
 */
public class ImageUtil {

    /**
     * Extracts the image file name from the Part header.
     */
    public String getImageNameFromPart(Part part) {
        String contentDisp = part.getHeader("content-disposition");
        String[] items = contentDisp.split(";");
        String fileName = null;

        for (String s : items) {
            if (s.trim().startsWith("filename")) {
                fileName = s.substring(s.indexOf("=") + 2, s.length() - 1);
            }
        }

        return (fileName == null || fileName.isEmpty()) ? "default.png" : fileName;
    }

    /**
     * Saves the image file to a given folder.
     *
     * @param part      the uploaded Part (image)
     * @param folder    subfolder name inside /resources/images/
     * @return the saved image filename, or null on error
     */
    public String uploadImage(Part part, String folder) {
        String savePath = getSavePath(folder);
        File dir = new File(savePath);
        if (!dir.exists() && !dir.mkdirs()) return null;

        try {
            String imageName = getImageNameFromPart(part);
            String filePath = savePath + File.separator + imageName;
            part.write(filePath);
            return imageName;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Builds the full save path based on the server file system.
     */
    public String getSavePath(String folder) {
        return "C:/Users/Prithivi/eclipse-workspace/venus-model-agency/src/main/webapp/resources/images/" + folder;
    }
}
