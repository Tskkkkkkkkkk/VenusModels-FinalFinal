package com.venus.model;
public class ModelModel{

     private int ModelID;
     private String ModelName;
     private String ModelContact;
     private String Height;
     private String Weight;
     private String Eyecolor;
     public ModelModel() {}
	public ModelModel(int modelID, String modelName, String modelContact, String height, String weight,
			String eyecolor) {
		super();
		ModelID = modelID;
		ModelName = modelName;
		ModelContact = modelContact;
		Height = height;
		Weight = weight;
		Eyecolor = eyecolor;
	}
	public int getModelID() {
		return ModelID;
	}
	public void setModelID(int modelID) {
		ModelID = modelID;
	}
	public String getModelName() {
		return ModelName;
	}
	public void setModelName(String modelName) {
		ModelName = modelName;
	}
	public String getModelContact() {
		return ModelContact;
	}
	public void setModelContact(String modelContact) {
		ModelContact = modelContact;
	}
	public String getHeight() {
		return Height;
	}
	public void setHeight(String height) {
		Height = height;
	}
	public String getWeight() {
		return Weight;
	}
	public void setWeight(String weight) {
		Weight = weight;
	}
	public String getEyecolor() {
		return Eyecolor;
	}
	public void setEyecolor(String eyecolor) {
		Eyecolor = eyecolor;
	}

}