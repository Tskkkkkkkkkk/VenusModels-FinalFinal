package com.venus.model;
public class ImageModel {

    private int ImageID;
    private String ImageName;
    public ImageModel() {}
	public ImageModel(int imageID, String imageName) {
		super();
		this.ImageID = imageID;
		this.ImageName = imageName;
	}
	public int getImageID() {
		return ImageID;
	}
	public void setImageID(int imageID) {
		ImageID = imageID;
	}
	public String getImageName() {
		return ImageName;
	}
	public void setImageName(String imageName) {
		ImageName = imageName;
	}
}
