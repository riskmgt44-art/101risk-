package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"riskmgt/models"
	"riskmgt/utils"
)

type CreateUserRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	JobTitle  string `json:"jobTitle"`
	Role      string `json:"role"`
	Phone     string `json:"phone,omitempty"`
}

type UpdateUserRequest struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	JobTitle  string `json:"jobTitle,omitempty"`
	Role      string `json:"role,omitempty"`
	Phone     string `json:"phone,omitempty"`
}

// UserValidator validates user requests
type UserValidator struct{}

func (v *UserValidator) ValidateCreate(req CreateUserRequest) error {
	if req.FirstName == "" || len(req.FirstName) > 50 {
		return fmt.Errorf("firstName is required and must be less than 50 characters")
	}
	if req.LastName == "" || len(req.LastName) > 50 {
		return fmt.Errorf("lastName is required and must be less than 50 characters")
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		return fmt.Errorf("valid email is required")
	}
	if req.JobTitle == "" || len(req.JobTitle) > 100 {
		return fmt.Errorf("jobTitle is required and must be less than 100 characters")
	}
	if req.Role == "" || !isValidRole(req.Role) {
		return fmt.Errorf("role is required and must be one of: superadmin, admin, risk_manager, user")
	}
	return nil
}

func (v *UserValidator) ValidateUpdate(req UpdateUserRequest) error {
	if req.FirstName != "" && len(req.FirstName) > 50 {
		return fmt.Errorf("firstName must be less than 50 characters")
	}
	if req.LastName != "" && len(req.LastName) > 50 {
		return fmt.Errorf("lastName must be less than 50 characters")
	}
	if req.JobTitle != "" && len(req.JobTitle) > 100 {
		return fmt.Errorf("jobTitle must be less than 100 characters")
	}
	if req.Role != "" && !isValidRole(req.Role) {
		return fmt.Errorf("role must be one of: superadmin, admin, risk_manager, user")
	}
	return nil
}

func isValidRole(role string) bool {
	validRoles := []string{"superadmin", "admin", "risk_manager", "user"}
	for _, r := range validRoles {
		if r == role {
			return true
		}
	}
	return false
}

// GetCurrentUser - endpoint /api/user/me
func GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id format")
		return
	}

	ctx := r.Context()

	// Fetch current user
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("GetCurrentUser - user fetch error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	// Fetch organization
	var org models.Organization
	err = orgCollection.FindOne(ctx, bson.M{"_id": orgID}).Decode(&org)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			log.Printf("GetCurrentUser - organization not found for id: %s", orgIDStr)
			org.Name = "Unknown Organization"
		} else {
			log.Printf("GetCurrentUser - org fetch error: %v", err)
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch organization")
			return
		}
	}

	// Never expose password hash
	user.PasswordHash = ""

	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":        user.ID.Hex(),
			"firstName": user.FirstName,
			"lastName":  user.LastName,
			"email":     user.Email,
			"jobTitle":  user.JobTitle,
			"phone":     user.Phone,
			"role":      user.Role,
			"createdAt": user.CreatedAt,
			"assetIds":  user.AssetIDs, // Add asset IDs to response
		},
		"organization": map[string]string{
			"id":   org.ID.Hex(),
			"name": org.Name,
		},
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// Secure password generator
func generateSecureTempPassword(length int) (string, error) {
	if length < 8 {
		length = 12
	}

	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "@#$%^&*-_=+"
	)

	allChars := lowercase + uppercase + digits + special
	password := make([]byte, length)

	if _, err := rand.Read(password); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	for i := range password {
		password[i] = allChars[int(password[i])%len(allChars)]
	}

	// Ensure at least one of each character type
	indices := []int{0, 1, 2, 3}
	replacements := []byte{
		lowercase[int(password[0])%len(lowercase)],
		uppercase[int(password[1])%len(uppercase)],
		digits[int(password[2])%len(digits)],
		special[int(password[3])%len(special)],
	}

	for i, idx := range indices {
		if idx < len(password) {
			password[idx] = replacements[i]
		}
	}

	return string(password), nil
}

func InviteUsers(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID missing in context")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID format")
		return
	}

	// Check permissions
	role, ok := r.Context().Value("userRole").(string)
	if !ok || (role != "superadmin" && role != "admin") {
		utils.RespondWithError(w, http.StatusForbidden, "Only superadmin or admin can invite users")
		return
	}

	inviterIDStr, ok := r.Context().Value("userID").(string)
	if !ok || inviterIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "User ID required")
		return
	}

	inviterID, err := primitive.ObjectIDFromHex(inviterIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var requests []CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	if len(requests) == 0 {
		utils.RespondWithError(w, http.StatusBadRequest, "No users provided")
		return
	}

	// Limit batch size
	if len(requests) > 50 {
		utils.RespondWithError(w, http.StatusBadRequest, "Cannot invite more than 50 users at once")
		return
	}

	var results []map[string]interface{}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	validator := UserValidator{}

	for _, req := range requests {
		result := map[string]interface{}{
			"email":  req.Email,
			"status": "pending",
		}

		// Validate request
		if err := validator.ValidateCreate(req); err != nil {
			result["status"] = "failed"
			result["message"] = err.Error()
			results = append(results, result)
			continue
		}

		// Check for duplicate email
		count, err := userCollection.CountDocuments(ctx, bson.M{
			"email":          strings.ToLower(req.Email),
			"organizationId": orgID,
		})
		if err != nil {
			log.Printf("Error checking duplicate email %s: %v", req.Email, err)
			result["status"] = "failed"
			result["message"] = "Database error during duplicate check"
			results = append(results, result)
			continue
		}
		if count > 0 {
			result["status"] = "skipped"
			result["message"] = "User with this email already exists in organization"
			results = append(results, result)
			continue
		}

		// Generate secure temporary password
		tempPass, err := generateSecureTempPassword(12)
		if err != nil {
			result["status"] = "failed"
			result["message"] = "Failed to generate secure password"
			results = append(results, result)
			continue
		}

		hash, err := utils.HashPassword(tempPass)
		if err != nil {
			result["status"] = "failed"
			result["message"] = "Password hashing failed"
			results = append(results, result)
			continue
		}

		user := models.User{
			ID:             primitive.NewObjectID(),
			FirstName:      req.FirstName,
			LastName:       req.LastName,
			Email:          strings.ToLower(req.Email),
			JobTitle:       req.JobTitle,
			Phone:          req.Phone,
			Role:           req.Role,
			PasswordHash:   hash,
			OrganizationID: orgID,
			AssetIDs:       []primitive.ObjectID{}, // Initialize empty AssetIDs array
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}

		_, err = userCollection.InsertOne(ctx, user)
		if err != nil {
			if mongo.IsDuplicateKeyError(err) {
				result["status"] = "skipped"
				result["message"] = "Email already taken (race condition)"
			} else {
				log.Printf("Failed to insert user %s: %v", req.Email, err)
				result["status"] = "failed"
				result["message"] = "Failed to create user in database"
			}
			results = append(results, result)
			continue
		}

		// Create audit log
		audit := models.AuditLog{
			ID:             primitive.NewObjectID(),
			OrganizationID: orgID,
			UserID:         inviterID,
			Action:         "user_invite",
			EntityType:     "user",
			EntityID:       user.ID,
			Details: bson.M{
				"email":    user.Email,
				"role":     user.Role,
				"inviter":  inviterID.Hex(),
				"fullName": user.FirstName + " " + user.LastName,
			},
			CreatedAt: time.Now().UTC(),
		}
		
		if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
			log.Printf("Failed to create audit log for user invite: %v", err)
		}
		
		BroadcastAudit(&audit)

		// Log securely
		log.Printf("USER_INVITE | Org: %s | Email: %s | Name: %s %s | Role: %s",
			orgIDStr, req.Email, req.FirstName, req.LastName, req.Role)

		result["status"] = "created"
		result["fullName"] = req.FirstName + " " + req.LastName
		result["role"] = req.Role
		result["userId"] = user.ID.Hex()
		result["message"] = "User created successfully"

		results = append(results, result)
	}

	// Determine overall status
	status := http.StatusCreated
	hasSuccess := false
	for _, r := range results {
		if r["status"] == "created" {
			hasSuccess = true
			break
		}
	}

	if !hasSuccess {
		status = http.StatusOK
	}

	utils.RespondWithJSON(w, status, map[string]interface{}{
		"message": "Invitation process completed",
		"summary": map[string]interface{}{
			"total":    len(results),
			"created":  countByStatus(results, "created"),
			"skipped":  countByStatus(results, "skipped"),
			"failed":   countByStatus(results, "failed"),
		},
		"results": results,
	})
}

func countByStatus(results []map[string]interface{}, status string) int {
	count := 0
	for _, r := range results {
		if r["status"] == status {
			count++
		}
	}
	return count
}

func ListUsers(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	filter := bson.M{"organizationId": orgID, "deletedAt": nil}

	// Optional filters
	role := r.URL.Query().Get("role")
	if role != "" {
		filter["role"] = role
	}

	// Check if we need to include asset information
	withAssets := r.URL.Query().Get("withAssets")
	var opts *options.FindOptions
	
	if withAssets == "true" {
		opts = options.Find().SetSort(bson.D{{"lastName", 1}, {"firstName", 1}})
	} else {
		opts = options.Find().SetSort(bson.D{{"createdAt", -1}})
	}

	cursor, err := userCollection.Find(ctx, filter, opts)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, []models.User{})
			return
		}
		log.Printf("ListUsers - Find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to query users")
		return
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err = cursor.All(ctx, &users); err != nil {
		log.Printf("ListUsers - cursor decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode users")
		return
	}

	// Remove sensitive data
	for i := range users {
		users[i].PasswordHash = ""
	}

	if users == nil {
		users = []models.User{}
	}

	log.Printf("ListUsers - returned %d users for org %s", len(users), orgIDHex)
	utils.RespondWithJSON(w, http.StatusOK, users)
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	// Get user ID from path parameter
	vars := mux.Vars(r)
	userIDStr := vars["id"]
	if userIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "user id required")
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id format")
		return
	}

	// Check permissions
	requestorIDStr, _ := r.Context().Value("userID").(string)
	requestorRole, _ := r.Context().Value("userRole").(string)
	
	// Users can view their own profile, admins can view anyone
	if requestorIDStr != userIDStr && 
	   requestorRole != "superadmin" && 
	   requestorRole != "admin" {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to view this user")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("GetUser - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	// Remove sensitive data
	user.PasswordHash = ""

	utils.RespondWithJSON(w, http.StatusOK, user)
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	// Get user ID from path parameter
	vars := mux.Vars(r)
	userIDStr := vars["id"]
	if userIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "user id required")
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id format")
		return
	}

	// Check permissions
	requestorIDStr, _ := r.Context().Value("userID").(string)
	requestorRole, _ := r.Context().Value("userRole").(string)
	
	// Users can update their own profile (except role), admins can update anyone
	if requestorIDStr != userIDStr && 
	   requestorRole != "superadmin" && 
	   requestorRole != "admin" {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to update this user")
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// Validate request
	validator := UserValidator{}
	if err := validator.ValidateUpdate(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Non-admins cannot change role
	if requestorRole != "superadmin" && requestorRole != "admin" {
		if req.Role != "" {
			utils.RespondWithError(w, http.StatusForbidden, "only admins can change role")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check if user exists
	var existingUser models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&existingUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("UpdateUser - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	// Prepare update
	update := bson.M{
		"updatedAt": time.Now().UTC(),
	}
	
	if req.FirstName != "" {
		update["firstName"] = req.FirstName
	}
	if req.LastName != "" {
		update["lastName"] = req.LastName
	}
	if req.JobTitle != "" {
		update["jobTitle"] = req.JobTitle
	}
	if req.Phone != "" {
		update["phone"] = req.Phone
	}
	if req.Role != "" && (requestorRole == "superadmin" || requestorRole == "admin") {
		update["role"] = req.Role
	}

	if len(update) == 1 { // Only updatedAt was set
		utils.RespondWithError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	result, err := userCollection.UpdateOne(ctx, 
		bson.M{"_id": userID, "organizationId": orgID},
		bson.M{"$set": update},
	)
	if err != nil {
		log.Printf("UpdateUser - update error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update user")
		return
	}
	
	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "user not found")
		return
	}

	// Get updated user
	var updatedUser models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&updatedUser)
	if err != nil {
		log.Printf("UpdateUser - find updated error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch updated user")
		return
	}

	// Remove sensitive data
	updatedUser.PasswordHash = ""

	// Audit log
	updaterID, _ := primitive.ObjectIDFromHex(requestorIDStr)
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         updaterID,
		Action:         "user_update",
		EntityType:     "user",
		EntityID:       userID,
		Details:        update,
		CreatedAt:      time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, updatedUser)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	// Get user ID from path parameter
	vars := mux.Vars(r)
	userIDStr := vars["id"]
	if userIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "user id required")
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id format")
		return
	}

	// Check permissions - only superadmin and admin can delete users
	requestorRole, ok := r.Context().Value("userRole").(string)
	if !ok || (requestorRole != "superadmin" && requestorRole != "admin") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to delete users")
		return
	}

	requestorIDStr, _ := r.Context().Value("userID").(string)
	requestorID, _ := primitive.ObjectIDFromHex(requestorIDStr)

	// Cannot delete yourself
	if requestorIDStr == userIDStr {
		utils.RespondWithError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get user details for audit log
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("DeleteUser - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	// Soft delete - update with deletion marker
	update := bson.M{
		"deletedAt":  time.Now().UTC(),
		"deletedBy":  requestorID,
		"updatedAt":  time.Now().UTC(),
	}

	result, err := userCollection.UpdateOne(ctx,
		bson.M{"_id": userID, "organizationId": orgID},
		bson.M{"$set": update},
	)
	if err != nil {
		log.Printf("DeleteUser - update error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	
	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "user not found")
		return
	}

	// Remove user from all asset assignments
	// Remove user from asset's assignedUserIds
	_, err = assetCollection.UpdateMany(ctx,
		bson.M{"organizationId": orgID, "assignedUserIds": userID},
		bson.M{"$pull": bson.M{"assignedUserIds": userID}},
	)
	if err != nil {
		log.Printf("Warning: Failed to remove user from asset assignments: %v", err)
	}

	// Remove user as owner from assets
	_, err = assetCollection.UpdateMany(ctx,
		bson.M{"organizationId": orgID, "ownerUserId": userID},
		bson.M{"$set": bson.M{"ownerUserId": nil}},
	)
	if err != nil {
		log.Printf("Warning: Failed to remove user as owner from assets: %v", err)
	}

	// Audit log
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         requestorID,
		Action:         "user_delete",
		EntityType:     "user",
		EntityID:       userID,
		Details: bson.M{
			"email":     user.Email,
			"fullName":  user.FirstName + " " + user.LastName,
			"role":      user.Role,
			"deletedBy": requestorID.Hex(),
		},
		CreatedAt: time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "user deleted successfully",
		"userId":  userID.Hex(),
	})
}

// ChangePassword allows users to change their own password
func ChangePassword(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id format")
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// Validate new password
	if req.NewPassword == "" || len(req.NewPassword) < 8 {
		utils.RespondWithError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	if req.NewPassword != req.ConfirmPassword {
		utils.RespondWithError(w, http.StatusBadRequest, "new passwords do not match")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get user with password hash
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("ChangePassword - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	// Verify current password
	if !utils.CheckPasswordHash(req.CurrentPassword, user.PasswordHash) {
		utils.RespondWithError(w, http.StatusBadRequest, "current password is incorrect")
		return
	}

	// Hash new password
	newHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.Printf("ChangePassword - hash error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to hash new password")
		return
	}

	// Update password
	update := bson.M{
		"passwordHash":      newHash,
		"lastPasswordChange": time.Now().UTC(),
		"updatedAt":         time.Now().UTC(),
	}

	_, err = userCollection.UpdateOne(ctx,
		bson.M{"_id": userID, "organizationId": orgID},
		bson.M{"$set": update},
	)
	if err != nil {
		log.Printf("ChangePassword - update error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	// Audit log
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "password_change",
		EntityType:     "user",
		EntityID:       userID,
		Details:        bson.M{},
		CreatedAt:      time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "password changed successfully",
	})
}