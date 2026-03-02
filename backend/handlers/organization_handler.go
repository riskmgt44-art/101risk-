package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"riskmgt/models"
	"riskmgt/utils"
)

type createOrgPayload struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Industry       string `json:"industry"`
	Size           string `json:"size,omitempty"`
	Country        string `json:"country"`
	Timezone       string `json:"timezone"`
	AdminFirstName string `json:"adminFirstName"`
	AdminLastName  string `json:"adminLastName"`
	AdminEmail     string `json:"adminEmail"`
	AdminJobTitle  string `json:"adminJobTitle"`
	AdminPassword  string `json:"adminPassword"`
	AdminPhone     string `json:"adminPhone,omitempty"`
}

func CreateOrganization(w http.ResponseWriter, r *http.Request) {
	var payload createOrgPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request payload format")
		return
	}

	// Required field validation
	if payload.Name == "" || payload.Type == "" || payload.Industry == "" ||
		payload.Country == "" || payload.Timezone == "" || payload.AdminFirstName == "" ||
		payload.AdminLastName == "" || payload.AdminEmail == "" || payload.AdminJobTitle == "" ||
		payload.AdminPassword == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Missing one or more required fields")
		return
	}

	ctx := r.Context()

	// Check duplicate org name
	count, err := orgCollection.CountDocuments(ctx, bson.M{"name": payload.Name})
	if err != nil {
		log.Printf("org unique check error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	if count > 0 {
		utils.RespondWithError(w, http.StatusConflict, "organization name already exists")
		return
	}

	// Check duplicate admin email
	count, err = userCollection.CountDocuments(ctx, bson.M{"email": payload.AdminEmail})
	if err != nil {
		log.Printf("user unique check error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	if count > 0 {
		utils.RespondWithError(w, http.StatusConflict, "admin email already exists")
		return
	}

	// 1. Create Organization
	org := models.Organization{
		ID:        primitive.NewObjectID(),
		Name:      payload.Name,
		Type:      payload.Type,
		Industry:  payload.Industry,
		Size:      payload.Size,
		Country:   payload.Country,
		Timezone:  payload.Timezone,
		CreatedAt: time.Now().UTC(),
	}

	_, err = orgCollection.InsertOne(ctx, org)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create organization")
		return
	}

	// 2. Hash admin password
	hash, err := utils.HashPassword(payload.AdminPassword)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to process password")
		return
	}

	// 3. Create Super Admin user
	user := models.User{
		ID:             primitive.NewObjectID(),
		FirstName:      payload.AdminFirstName,
		LastName:       payload.AdminLastName,
		Email:          payload.AdminEmail,
		JobTitle:       payload.AdminJobTitle,
		Phone:          payload.AdminPhone,
		PasswordHash:   hash,
		Role:           "superadmin",
		OrganizationID: org.ID,
		CreatedAt:      time.Now().UTC(),
	}

	_, err = userCollection.InsertOne(ctx, user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create super admin user")
		return
	}

	// 4. Generate JWT
	token, err := utils.GenerateJWT(
		user.ID.Hex(),
		user.FirstName+" "+user.LastName,
		user.Role,
		org.ID.Hex(),
	)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate authentication token")
		return
	}

	// 5. Success response
	response := map[string]interface{}{
		"message": "Organization and super admin created successfully",
		"token":   token,
		"user": map[string]string{
			"id":    user.ID.Hex(),
			"name":  user.FirstName + " " + user.LastName,
			"email": user.Email,
			"role":  user.Role,
		},
		"organization": map[string]string{
			"id":   org.ID.Hex(),
			"name": org.Name,
		},
	}

	utils.RespondWithJSON(w, http.StatusCreated, response)
}

// GetOrganization retrieves a single organization by ID
func GetOrganization(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	var org models.Organization
	err = orgCollection.FindOne(r.Context(), bson.M{"_id": orgID}).Decode(&org)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "Organization not found")
			return
		}
		log.Printf("Error fetching organization: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch organization")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, org)
}

// UpdateOrganization updates an organization
func UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Remove fields that shouldn't be updated
	delete(updateData, "_id")
	delete(updateData, "id")
	delete(updateData, "createdAt")

	updateData["updatedAt"] = time.Now().UTC()

	result, err := orgCollection.UpdateOne(
		r.Context(),
		bson.M{"_id": orgID},
		bson.M{"$set": updateData},
	)

	if err != nil {
		log.Printf("Error updating organization: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update organization")
		return
	}

	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "Organization not found")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Organization updated successfully"})
}

// DeleteOrganization deletes an organization
func DeleteOrganization(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Check if organization has users
	count, err := userCollection.CountDocuments(r.Context(), bson.M{"organizationId": orgID})
	if err != nil {
		log.Printf("Error checking organization users: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to delete organization")
		return
	}

	if count > 0 {
		utils.RespondWithError(w, http.StatusBadRequest, "Cannot delete organization with existing users")
		return
	}

	result, err := orgCollection.DeleteOne(r.Context(), bson.M{"_id": orgID})
	if err != nil {
		log.Printf("Error deleting organization: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to delete organization")
		return
	}

	if result.DeletedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "Organization not found")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Organization deleted successfully"})
}

// GetOrganizationStats returns statistics for an organization
func GetOrganizationStats(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get user count
	userCount, err := userCollection.CountDocuments(r.Context(), bson.M{"organizationId": orgID})
	if err != nil {
		log.Printf("Error counting users: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get organization stats")
		return
	}

	// Get asset count
	assetCount, err := assetCollection.CountDocuments(r.Context(), bson.M{"organizationId": orgID})
	if err != nil {
		log.Printf("Error counting assets: %v", err)
		assetCount = 0
	}

	// Get risk count
	riskCount, err := riskCollection.CountDocuments(r.Context(), bson.M{"organizationId": orgID})
	if err != nil {
		log.Printf("Error counting risks: %v", err)
		riskCount = 0
	}

	stats := map[string]interface{}{
		"totalUsers":  userCount,
		"totalAssets": assetCount,
		"totalRisks":  riskCount,
	}

	utils.RespondWithJSON(w, http.StatusOK, stats)
}

// GetOrganizationUsers returns all users in an organization
func GetOrganizationUsers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	cursor, err := userCollection.Find(r.Context(), bson.M{"organizationId": orgID})
	if err != nil {
		log.Printf("Error fetching organization users: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch users")
		return
	}
	defer cursor.Close(r.Context())

	var users []models.User
	if err = cursor.All(r.Context(), &users); err != nil {
		log.Printf("Error decoding users: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode users")
		return
	}

	// Remove password hashes
	for i := range users {
		users[i].PasswordHash = ""
	}

	utils.RespondWithJSON(w, http.StatusOK, users)
}