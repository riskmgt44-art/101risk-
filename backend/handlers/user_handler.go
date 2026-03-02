package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
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
	FirstName   string     `json:"firstName,omitempty"`
	LastName    string     `json:"lastName,omitempty"`
	JobTitle    string     `json:"jobTitle,omitempty"`
	Role        string     `json:"role,omitempty"`
	Phone       string     `json:"phone,omitempty"`
	MFAEnabled  *bool      `json:"mfaEnabled,omitempty"`
	DeletedAt   *time.Time `json:"deletedAt,omitempty"`
	LastLogin   *time.Time `json:"lastLogin,omitempty"`
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
			"id":         user.ID.Hex(),
			"firstName":  user.FirstName,
			"lastName":   user.LastName,
			"email":      user.Email,
			"jobTitle":   user.JobTitle,
			"phone":      user.Phone,
			"role":       user.Role,
			"mfaEnabled": user.MFAEnabled,
			"lastLogin":  user.LastLogin,
			"status":     getUserStatus(user),
			"createdAt":  user.CreatedAt,
			"updatedAt":  user.UpdatedAt,
			"assetIds":   user.AssetIDs, // Add asset IDs to response
		},
		"organization": map[string]string{
			"id":   org.ID.Hex(),
			"name": org.Name,
		},
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// Helper function to determine user status
func getUserStatus(user models.User) string {
	if user.DeletedAt != nil && !user.DeletedAt.IsZero() {
		return "suspended"
	}
	return "active"
}

// GetUsersWithPagination - endpoint /api/users (with pagination and search)
func GetUsersWithPagination(w http.ResponseWriter, r *http.Request) {
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

	// Check permissions - only admins can view all users
	requestorRole, ok := r.Context().Value("userRole").(string)
	if !ok || (requestorRole != "superadmin" && requestorRole != "admin") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to view all users")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	search := r.URL.Query().Get("search")
	skip := (page - 1) * limit

	// Build filter
	filter := bson.M{
		"organizationId": orgID,
	}

	// Add search filter if provided
	if search != "" {
		filter["$or"] = []bson.M{
			{"firstName": bson.M{"$regex": search, "$options": "i"}},
			{"lastName": bson.M{"$regex": search, "$options": "i"}},
			{"email": bson.M{"$regex": search, "$options": "i"}},
			{"jobTitle": bson.M{"$regex": search, "$options": "i"}},
			{"role": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	// Get total count for pagination
	total, err := userCollection.CountDocuments(ctx, filter)
	if err != nil {
		log.Printf("GetUsersWithPagination - count error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to count users")
		return
	}

	// Find users with pagination
	opts := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(limit)).
		SetSort(bson.D{{"createdAt", -1}})

	cursor, err := userCollection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("GetUsersWithPagination - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to query users")
		return
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err = cursor.All(ctx, &users); err != nil {
		log.Printf("GetUsersWithPagination - decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode users")
		return
	}

	// Format users for frontend
	var formattedUsers []map[string]interface{}
	for _, user := range users {
		formattedUser := map[string]interface{}{
			"_id":        user.ID.Hex(),
			"id":         user.ID.Hex(),
			"firstName":  user.FirstName,
			"lastName":   user.LastName,
			"email":      user.Email,
			"jobTitle":   user.JobTitle,
			"phone":      user.Phone,
			"role":       user.Role,
			"mfaEnabled": user.MFAEnabled,
			"lastLogin":  user.LastLogin,
			"status":     getUserStatus(user),
			"createdAt":  user.CreatedAt,
			"updatedAt":  user.UpdatedAt,
		}

		// Handle deletedAt separately for frontend
		if user.DeletedAt != nil && !user.DeletedAt.IsZero() {
			formattedUser["deletedAt"] = user.DeletedAt
		}

		formattedUsers = append(formattedUsers, formattedUser)
	}

	// Format response to match frontend expectations
	response := map[string]interface{}{
		"users": formattedUsers,
		"pagination": map[string]interface{}{
			"total":       total,
			"totalPages":  int(math.Ceil(float64(total) / float64(limit))),
			"currentPage": page,
			"limit":       limit,
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
			MFAEnabled:     false,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
			Status:         "invited",
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
			"total":   len(results),
			"created": countByStatus(results, "created"),
			"skipped": countByStatus(results, "skipped"),
			"failed":  countByStatus(results, "failed"),
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

	filter := bson.M{"organizationId": orgID}

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

	// Format response for frontend
	response := map[string]interface{}{
		"_id":        user.ID.Hex(),
		"id":         user.ID.Hex(),
		"firstName":  user.FirstName,
		"lastName":   user.LastName,
		"email":      user.Email,
		"jobTitle":   user.JobTitle,
		"phone":      user.Phone,
		"role":       user.Role,
		"mfaEnabled": user.MFAEnabled,
		"lastLogin":  user.LastLogin,
		"status":     getUserStatus(user),
		"createdAt":  user.CreatedAt,
		"updatedAt":  user.UpdatedAt,
		"deletedAt":  user.DeletedAt,
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
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

	// Non-admins cannot change role or deleteAt
	if requestorRole != "superadmin" && requestorRole != "admin" {
		if req.Role != "" {
			utils.RespondWithError(w, http.StatusForbidden, "only admins can change role")
			return
		}
		if req.DeletedAt != nil {
			utils.RespondWithError(w, http.StatusForbidden, "only admins can change account status")
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
	if req.MFAEnabled != nil {
		update["mfaEnabled"] = *req.MFAEnabled
	}
	if req.LastLogin != nil {
		update["lastLogin"] = *req.LastLogin
	}
	// Handle deletion/reactivation
	if req.DeletedAt != nil && (requestorRole == "superadmin" || requestorRole == "admin") {
		update["deletedAt"] = req.DeletedAt
		if req.DeletedAt.IsZero() {
			update["deletedBy"] = nil
			update["status"] = "active"
		} else {
			deletedBy, _ := primitive.ObjectIDFromHex(requestorIDStr)
			update["deletedBy"] = deletedBy
			update["status"] = "suspended"
		}
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

	// Format response for frontend
	response := map[string]interface{}{
		"_id":        updatedUser.ID.Hex(),
		"id":         updatedUser.ID.Hex(),
		"firstName":  updatedUser.FirstName,
		"lastName":   updatedUser.LastName,
		"email":      updatedUser.Email,
		"jobTitle":   updatedUser.JobTitle,
		"phone":      updatedUser.Phone,
		"role":       updatedUser.Role,
		"mfaEnabled": updatedUser.MFAEnabled,
		"lastLogin":  updatedUser.LastLogin,
		"status":     getUserStatus(updatedUser),
		"createdAt":  updatedUser.CreatedAt,
		"updatedAt":  updatedUser.UpdatedAt,
		"deletedAt":  updatedUser.DeletedAt,
	}

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

	utils.RespondWithJSON(w, http.StatusOK, response)
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
		"status":     "suspended",
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

// ActivateUser - endpoint /api/users/{id}/activate
func ActivateUser(w http.ResponseWriter, r *http.Request) {
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

	// Check permissions - only superadmin and admin can activate users
	requestorRole, ok := r.Context().Value("userRole").(string)
	if !ok || (requestorRole != "superadmin" && requestorRole != "admin") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to activate users")
		return
	}

	requestorIDStr, _ := r.Context().Value("userID").(string)
	requestorID, _ := primitive.ObjectIDFromHex(requestorIDStr)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check if user exists
	var existingUser models.User
	err = userCollection.FindOne(ctx, bson.M{
		"_id":            userID,
		"organizationId": orgID,
	}).Decode(&existingUser)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("ActivateUser - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	// Check if already active
	if existingUser.DeletedAt == nil || existingUser.DeletedAt.IsZero() {
		utils.RespondWithError(w, http.StatusBadRequest, "user is already active")
		return
	}

	// Activate user - set deletedAt to nil
	update := bson.M{
		"deletedAt":  nil,
		"deletedBy":  nil,
		"updatedAt":  time.Now().UTC(),
		"status":     "active",
	}

	result, err := userCollection.UpdateOne(ctx,
		bson.M{"_id": userID, "organizationId": orgID},
		bson.M{"$set": update},
	)
	if err != nil {
		log.Printf("ActivateUser - update error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to activate user")
		return
	}

	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "user not found")
		return
	}

	// Remove user from asset assignments if needed
	_, err = assetCollection.UpdateMany(ctx,
		bson.M{"organizationId": orgID, "assignedUserIds": userID},
		bson.M{"$pull": bson.M{"assignedUserIds": userID}},
	)
	if err != nil {
		log.Printf("Warning: Failed to remove user from asset assignments: %v", err)
	}

	// Audit log
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         requestorID,
		Action:         "user_activate",
		EntityType:     "user",
		EntityID:       userID,
		Details: bson.M{
			"email":       existingUser.Email,
			"fullName":    existingUser.FirstName + " " + existingUser.LastName,
			"role":        existingUser.Role,
			"activatedBy": requestorID.Hex(),
		},
		CreatedAt: time.Now().UTC(),
	}

	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}

	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "user activated successfully",
		"userId":  userID.Hex(),
		"status":  "active",
	})
}

// SuspendUser - endpoint /api/users/{id}/suspend
func SuspendUser(w http.ResponseWriter, r *http.Request) {
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

	// Check permissions - only superadmin and admin can suspend users
	requestorRole, ok := r.Context().Value("userRole").(string)
	if !ok || (requestorRole != "superadmin" && requestorRole != "admin") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to suspend users")
		return
	}

	requestorIDStr, _ := r.Context().Value("userID").(string)
	requestorID, _ := primitive.ObjectIDFromHex(requestorIDStr)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check if user exists
	var existingUser models.User
	err = userCollection.FindOne(ctx, bson.M{
		"_id":            userID,
		"organizationId": orgID,
	}).Decode(&existingUser)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "user not found")
			return
		}
		log.Printf("SuspendUser - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	// Check if already suspended
	if existingUser.DeletedAt != nil && !existingUser.DeletedAt.IsZero() {
		utils.RespondWithError(w, http.StatusBadRequest, "user is already suspended")
		return
	}

	// Cannot suspend yourself
	if requestorIDStr == userID.Hex() {
		utils.RespondWithError(w, http.StatusBadRequest, "cannot suspend your own account")
		return
	}

	// Suspend user - set deletedAt to current time
	now := time.Now().UTC()
	update := bson.M{
		"deletedAt":  now,
		"deletedBy":  requestorID,
		"updatedAt":  now,
		"status":     "suspended",
	}

	result, err := userCollection.UpdateOne(ctx,
		bson.M{"_id": userID, "organizationId": orgID},
		bson.M{"$set": update},
	)
	if err != nil {
		log.Printf("SuspendUser - update error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to suspend user")
		return
	}

	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "user not found")
		return
	}

	// Remove user from asset assignments
	_, err = assetCollection.UpdateMany(ctx,
		bson.M{"organizationId": orgID, "assignedUserIds": userID},
		bson.M{"$pull": bson.M{"assignedUserIds": userID}},
	)
	if err != nil {
		log.Printf("Warning: Failed to remove user from asset assignments: %v", err)
	}

	// Audit log
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         requestorID,
		Action:         "user_suspend",
		EntityType:     "user",
		EntityID:       userID,
		Details: bson.M{
			"email":       existingUser.Email,
			"fullName":    existingUser.FirstName + " " + existingUser.LastName,
			"role":        existingUser.Role,
			"suspendedBy": requestorID.Hex(),
		},
		CreatedAt: now,
	}

	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}

	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "user suspended successfully",
		"userId":  userID.Hex(),
		"status":  "suspended",
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
		"passwordHash":       newHash,
		"lastPasswordChange": time.Now().UTC(),
		"updatedAt":          time.Now().UTC(),
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

// BulkUserActions - endpoint /api/users/bulk-action
func BulkUserActions(w http.ResponseWriter, r *http.Request) {
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

	// Check permissions - only superadmin and admin can perform bulk actions
	requestorRole, ok := r.Context().Value("userRole").(string)
	if !ok || (requestorRole != "superadmin" && requestorRole != "admin") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions for bulk actions")
		return
	}

	requestorIDStr, _ := r.Context().Value("userID").(string)
	requestorID, _ := primitive.ObjectIDFromHex(requestorIDStr)

	var req struct {
		Action  string   `json:"action"`
		UserIDs []string `json:"userIds"`
		NewRole string   `json:"newRole,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if len(req.UserIDs) == 0 {
		utils.RespondWithError(w, http.StatusBadRequest, "no users selected")
		return
	}

	if len(req.UserIDs) > 100 {
		utils.RespondWithError(w, http.StatusBadRequest, "cannot process more than 100 users at once")
		return
	}

	// Convert user IDs to ObjectIDs
	var userIDs []primitive.ObjectID
	for _, idStr := range req.UserIDs {
		if id, err := primitive.ObjectIDFromHex(idStr); err == nil {
			userIDs = append(userIDs, id)
		}
	}

	if len(userIDs) == 0 {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user IDs")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var modifiedCount int64
	var errors []string

	switch req.Action {
	case "suspend":
		modifiedCount, errors = bulkSuspendUsers(ctx, orgID, userIDs, requestorID)
	case "activate":
		modifiedCount, errors = bulkActivateUsers(ctx, orgID, userIDs, requestorID)
	case "changerole":
		if req.NewRole == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "newRole is required for role change")
			return
		}
		if !isValidRole(req.NewRole) {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid role")
			return
		}
		modifiedCount, errors = bulkChangeRole(ctx, orgID, userIDs, req.NewRole, requestorID)
	case "delete":
		modifiedCount, errors = bulkDeleteUsers(ctx, orgID, userIDs, requestorID)
	default:
		utils.RespondWithError(w, http.StatusBadRequest, "invalid action")
		return
	}

	if len(errors) > 0 {
		log.Printf("BulkUserActions - completed with %d errors: %v", len(errors), errors)
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":  fmt.Sprintf("bulk action completed: %d users modified", modifiedCount),
		"modified": modifiedCount,
		"errors":   errors,
	})
}

// Helper functions for bulk actions
func bulkSuspendUsers(ctx context.Context, orgID primitive.ObjectID, userIDs []primitive.ObjectID, requestorID primitive.ObjectID) (int64, []string) {
	now := time.Now().UTC()
	filter := bson.M{
		"_id":            bson.M{"$in": userIDs},
		"organizationId": orgID,
		"deletedAt":      nil, // Only suspend active users
	}

	update := bson.M{
		"$set": bson.M{
			"deletedAt":  now,
			"deletedBy":  requestorID,
			"updatedAt":  now,
			"status":     "suspended",
		},
	}

	result, err := userCollection.UpdateMany(ctx, filter, update)
	if err != nil {
		log.Printf("bulkSuspendUsers error: %v", err)
		return 0, []string{err.Error()}
	}

	// Create audit logs for each suspended user
	for _, userID := range userIDs {
		audit := models.AuditLog{
			ID:             primitive.NewObjectID(),
			OrganizationID: orgID,
			UserID:         requestorID,
			Action:         "user_suspend_bulk",
			EntityType:     "user",
			EntityID:       userID,
			Details: bson.M{
				"action":      "suspend",
				"bulk":        true,
				"suspendedBy": requestorID.Hex(),
			},
			CreatedAt: now,
		}

		if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
			log.Printf("Failed to create audit log for bulk suspend: %v", err)
		}

		BroadcastAudit(&audit)
	}

	return result.ModifiedCount, nil
}

func bulkActivateUsers(ctx context.Context, orgID primitive.ObjectID, userIDs []primitive.ObjectID, requestorID primitive.ObjectID) (int64, []string) {
	now := time.Now().UTC()
	filter := bson.M{
		"_id":            bson.M{"$in": userIDs},
		"organizationId": orgID,
		"deletedAt":      bson.M{"$ne": nil}, // Only activate suspended users
	}

	update := bson.M{
		"$set": bson.M{
			"deletedAt":  nil,
			"deletedBy":  nil,
			"updatedAt":  now,
			"status":     "active",
		},
	}

	result, err := userCollection.UpdateMany(ctx, filter, update)
	if err != nil {
		log.Printf("bulkActivateUsers error: %v", err)
		return 0, []string{err.Error()}
	}

	// Create audit logs for each activated user
	for _, userID := range userIDs {
		audit := models.AuditLog{
			ID:             primitive.NewObjectID(),
			OrganizationID: orgID,
			UserID:         requestorID,
			Action:         "user_activate_bulk",
			EntityType:     "user",
			EntityID:       userID,
			Details: bson.M{
				"action":      "activate",
				"bulk":        true,
				"activatedBy": requestorID.Hex(),
			},
			CreatedAt: now,
		}

		if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
			log.Printf("Failed to create audit log for bulk activate: %v", err)
		}

		BroadcastAudit(&audit)
	}

	return result.ModifiedCount, nil
}

func bulkChangeRole(ctx context.Context, orgID primitive.ObjectID, userIDs []primitive.ObjectID, newRole string, requestorID primitive.ObjectID) (int64, []string) {
	now := time.Now().UTC()
	filter := bson.M{
		"_id":            bson.M{"$in": userIDs},
		"organizationId": orgID,
	}

	update := bson.M{
		"$set": bson.M{
			"role":      newRole,
			"updatedAt": now,
		},
	}

	result, err := userCollection.UpdateMany(ctx, filter, update)
	if err != nil {
		log.Printf("bulkChangeRole error: %v", err)
		return 0, []string{err.Error()}
	}

	// Create audit logs for each user whose role changed
	for _, userID := range userIDs {
		audit := models.AuditLog{
			ID:             primitive.NewObjectID(),
			OrganizationID: orgID,
			UserID:         requestorID,
			Action:         "user_role_change_bulk",
			EntityType:     "user",
			EntityID:       userID,
			Details: bson.M{
				"action":    "role_change",
				"newRole":   newRole,
				"bulk":      true,
				"changedBy": requestorID.Hex(),
			},
			CreatedAt: now,
		}

		if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
			log.Printf("Failed to create audit log for bulk role change: %v", err)
		}

		BroadcastAudit(&audit)
	}

	return result.ModifiedCount, nil
}

func bulkDeleteUsers(ctx context.Context, orgID primitive.ObjectID, userIDs []primitive.ObjectID, requestorID primitive.ObjectID) (int64, []string) {
	now := time.Now().UTC()
	filter := bson.M{
		"_id":            bson.M{"$in": userIDs},
		"organizationId": orgID,
		"deletedAt":      nil, // Don't delete already deleted users
	}

	update := bson.M{
		"$set": bson.M{
			"deletedAt":  now,
			"deletedBy":  requestorID,
			"updatedAt":  now,
			"status":     "deleted",
		},
	}

	result, err := userCollection.UpdateMany(ctx, filter, update)
	if err != nil {
		log.Printf("bulkDeleteUsers error: %v", err)
		return 0, []string{err.Error()}
	}

	// Also remove users from asset assignments
	_, err = assetCollection.UpdateMany(ctx,
		bson.M{"organizationId": orgID, "assignedUserIds": bson.M{"$in": userIDs}},
		bson.M{"$pull": bson.M{"assignedUserIds": bson.M{"$in": userIDs}}},
	)
	if err != nil {
		log.Printf("Warning: Failed to remove users from asset assignments during bulk delete: %v", err)
	}

	// Create audit logs for each deleted user
	for _, userID := range userIDs {
		audit := models.AuditLog{
			ID:             primitive.NewObjectID(),
			OrganizationID: orgID,
			UserID:         requestorID,
			Action:         "user_delete_bulk",
			EntityType:     "user",
			EntityID:       userID,
			Details: bson.M{
				"action":    "delete",
				"bulk":      true,
				"deletedBy": requestorID.Hex(),
			},
			CreatedAt: now,
		}

		if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
			log.Printf("Failed to create audit log for bulk delete: %v", err)
		}

		BroadcastAudit(&audit)
	}

	return result.ModifiedCount, nil
}

// ExportUsers - endpoint /api/users/export
func ExportUsers(w http.ResponseWriter, r *http.Request) {
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

	// Check permissions - only admins can export users
	requestorRole, ok := r.Context().Value("userRole").(string)
	if !ok || (requestorRole != "superadmin" && requestorRole != "admin") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to export users")
		return
	}

	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		format = "json" // default to JSON
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Get all users for the organization
	filter := bson.M{"organizationId": orgID}
	cursor, err := userCollection.Find(ctx, filter, options.Find().SetSort(bson.D{{"createdAt", -1}}))
	if err != nil {
		log.Printf("ExportUsers - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to query users")
		return
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err = cursor.All(ctx, &users); err != nil {
		log.Printf("ExportUsers - decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode users")
		return
	}

	// Remove sensitive data
	for i := range users {
		users[i].PasswordHash = ""
	}

	// Create audit log
	requestorIDStr, _ := r.Context().Value("userID").(string)
	requestorID, _ := primitive.ObjectIDFromHex(requestorIDStr)
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         requestorID,
		Action:         "users_export",
		EntityType:     "users",
		EntityID:       primitive.NilObjectID,
		Details: bson.M{
			"format": format,
			"count":  len(users),
		},
		CreatedAt: time.Now().UTC(),
	}

	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log for export: %v", err)
	}

	BroadcastAudit(&audit)

	if format == "csv" {
		exportCSV(w, users)
	} else {
		exportJSON(w, users)
	}
}

func exportCSV(w http.ResponseWriter, users []models.User) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=users_export.csv")

	// Write CSV header
	csvHeader := "ID,First Name,Last Name,Email,Job Title,Phone,Role,Status,MFA Enabled,Last Login,Created At\n"
	w.Write([]byte(csvHeader))

	for _, user := range users {
		status := "active"
		if user.DeletedAt != nil && !user.DeletedAt.IsZero() {
			status = "suspended"
		}

		mfaEnabled := "false"
		if user.MFAEnabled {
			mfaEnabled = "true"
		}

		lastLogin := ""
		if user.LastLogin != nil && !user.LastLogin.IsZero() {
			lastLogin = user.LastLogin.Format("2006-01-02 15:04:05")
		}

		csvLine := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			user.ID.Hex(),
			escapeCSV(user.FirstName),
			escapeCSV(user.LastName),
			escapeCSV(user.Email),
			escapeCSV(user.JobTitle),
			escapeCSV(user.Phone),
			escapeCSV(user.Role),
			status,
			mfaEnabled,
			lastLogin,
			user.CreatedAt.Format("2006-01-02 15:04:05"),
		)
		w.Write([]byte(csvLine))
	}
}

func escapeCSV(field string) string {
	if strings.Contains(field, ",") || strings.Contains(field, "\"") || strings.Contains(field, "\n") {
		return "\"" + strings.ReplaceAll(field, "\"", "\"\"") + "\""
	}
	return field
}

func exportJSON(w http.ResponseWriter, users []models.User) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=users_export.json")

	// Format users for export
	var exportUsers []map[string]interface{}
	for _, user := range users {
		exportUser := map[string]interface{}{
			"id":         user.ID.Hex(),
			"firstName":  user.FirstName,
			"lastName":   user.LastName,
			"email":      user.Email,
			"jobTitle":   user.JobTitle,
			"phone":      user.Phone,
			"role":       user.Role,
			"mfaEnabled": user.MFAEnabled,
			"lastLogin":  user.LastLogin,
			"status":     getUserStatus(user),
			"createdAt":  user.CreatedAt,
			"updatedAt":  user.UpdatedAt,
		}
		exportUsers = append(exportUsers, exportUser)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"exportDate": time.Now().UTC(),
		"count":      len(exportUsers),
		"users":      exportUsers,
	})
}