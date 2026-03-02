// handlers/auth_handler.go
package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"riskmgt/models"
	"riskmgt/utils"
)

// NormalizeRole ensures consistent role naming for frontend mapping
func normalizeRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	
	// Only 4 valid roles
	switch role {
	case "superadmin":
		return "superadmin"
	case "admin":
		return "admin"
	case "analyst":
		return "analyst"
	case "viewer":
		return "viewer"
	default:
		return "analyst" // Default fallback
	}
}

// GetDashboardPath returns the appropriate dashboard path for a role
func getDashboardPath(role string) string {
	normalized := normalizeRole(role)
	
	switch normalized {
	case "superadmin":
		return "/dashboards/executive/index.html"
	case "admin":
		return "/dashboards/admin/index.html"
	case "analyst":
		return "/dashboards/analyst/index.html"
	case "viewer":
		return "/dashboards/viewer/index.html"
	default:
		return "/dashboards/analyst/index.html"
	}
}

// GetDefaultLandingPage returns the first page users should see after login
func getDefaultLandingPage(role string) string {
	return getDashboardPath(role) // All roles start at their dashboard index
}

// Login handles user authentication
func Login(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		log.Printf("Login request took %v", time.Since(start))
	}()

	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	// Validate input
	creds.Email = strings.TrimSpace(creds.Email)
	if creds.Email == "" || !strings.Contains(creds.Email, "@") {
		utils.RespondWithError(w, http.StatusBadRequest, "Valid email required")
		return
	}
	if len(creds.Password) < 6 {
		utils.RespondWithError(w, http.StatusBadRequest, "Password must be at least 6 characters")
		return
	}

	t1 := time.Now()
	var user models.User
	err := userCollection.FindOne(r.Context(), bson.M{
		"email":     creds.Email,
		"deletedAt": nil,
	}).Decode(&user)
	tFind := time.Since(t1)
	log.Printf("FindOne took %v", tFind)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			_ = utils.CheckPasswordHash("dummy_password", "$2a$10$dummyhashfordummycomparison")
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid email or password")
			return
		}
		log.Printf("Database error during login: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Authentication service unavailable")
		return
	}

	t2 := time.Now()
	passwordMatch := utils.CheckPasswordHash(creds.Password, user.PasswordHash)
	tHash := time.Since(t2)
	log.Printf("Password check took %v", tHash)

	if !passwordMatch {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// Normalize role
	normalizedRole := normalizeRole(user.Role)
	dashboardPath := getDashboardPath(normalizedRole)
	landingPage := getDefaultLandingPage(normalizedRole)

	// Generate JWT token
	t4 := time.Now()
	token, err := utils.GenerateJWT(
		user.ID.Hex(),
		user.FirstName+" "+user.LastName,
		normalizedRole,
		user.OrganizationID.Hex(),
	)
	tJWT := time.Since(t4)
	log.Printf("JWT generation took %v", tJWT)

	if err != nil {
		log.Printf("JWT generation error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate authentication token")
		return
	}

	// Update last login timestamp
	updateCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	
	_, err = userCollection.UpdateOne(
		updateCtx,
		bson.M{"_id": user.ID},
		bson.M{"$set": bson.M{
			"updatedAt": time.Now().UTC(),
		}},
	)
	if err != nil {
		log.Printf("Failed to update user timestamp: %v", err)
	}

	// Get user's permissions based on role
	permissions := getPermissionsForRole(normalizedRole)

	response := map[string]interface{}{
		"token": token,
		"user": map[string]interface{}{
			"id":           user.ID.Hex(),
			"name":         user.FirstName + " " + user.LastName,
			"firstName":    user.FirstName,
			"lastName":     user.LastName,
			"email":        user.Email,
			"jobTitle":     user.JobTitle,
			"phone":        user.Phone,
			"role":         normalizedRole,
			"dashboard":    dashboardPath,
			"landingPage":  landingPage,
			"organization": user.OrganizationID.Hex(),
			"permissions":  permissions,
			"createdAt":    user.CreatedAt,
		},
		"dashboardRedirect": dashboardPath,
		"landingPage":       landingPage,
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// getPermissionsForRole returns permissions based on role
func getPermissionsForRole(role string) map[string]bool {
	permissions := map[string]bool{}
	
	switch role {
	case "superadmin":
		// Full system access
		permissions = map[string]bool{
			"view_dashboard":      true,
			"edit_profile":        true,
			"create_risk":         true,
			"edit_all_risks":      true,
			"delete_risks":        true,
			"approve_risks":       true,
			"view_all_risks":      true,
			"create_action":       true,
			"edit_all_actions":    true,
			"delete_actions":      true,
			"view_all_actions":    true,
			"export_data":         true,
			"view_analytics":      true,
			"manage_users":        true,
			"delete_users":        true,
			"system_settings":     true,
			"view_audit_logs":     true,
			"view_system_logs":    true,
			"view_all_dashboards": true,
			"superadmin_access":   true,
		}
		
	case "admin":
		// Administrative access
		permissions = map[string]bool{
			"view_dashboard":      true,
			"edit_profile":        true,
			"create_risk":         true,
			"edit_all_risks":      true,
			"delete_risks":        true,
			"approve_risks":       true,
			"view_all_risks":      true,
			"create_action":       true,
			"edit_all_actions":    true,
			"delete_actions":      true,
			"view_all_actions":    true,
			"export_data":         true,
			"view_analytics":      true,
			"manage_users":        true,
			"system_settings":     true,
			"view_audit_logs":     true,
			"view_system_logs":    true,
			"view_all_dashboards": true,
		}
		
	case "analyst":
		// Create/edit own content
		permissions = map[string]bool{
			"view_dashboard":        true,
			"edit_profile":          true,
			"create_risk":           true,
			"edit_own_risks":        true,
			"submit_risk":           true,
			"view_own_risks":        true,
			"create_action":         true,
			"edit_own_actions":      true,
			"view_own_actions":      true,
			"export_data":           true,
			"view_personal_metrics": true,
		}
		
	case "viewer":
		// Read-only access
		permissions = map[string]bool{
			"view_dashboard":   true,
			"edit_profile":     true,
			"view_all_risks":   true,
			"view_all_actions": true,
			"export_data":      true,
		}
		
	default:
		// Default to analyst permissions
		permissions = map[string]bool{
			"view_dashboard": true,
			"edit_profile":   true,
			"create_risk":    true,
			"edit_own_risks": true,
			"submit_risk":    true,
			"view_own_risks": true,
		}
	}
	
	return permissions
}

// Logout handles user logout
func Logout(w http.ResponseWriter, r *http.Request) {
	// Clear any auth cookies if set
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// ForgotPassword handles password reset requests
func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		utils.RespondWithError(w, http.StatusBadRequest, "Valid email required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{
		"email":     req.Email,
		"deletedAt": nil,
	}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Return generic message for security
			utils.RespondWithJSON(w, http.StatusOK, map[string]string{
				"message": "If the email exists in our system, a password reset link has been sent.",
			})
			return
		}
		log.Printf("find user error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Generate secure reset token
	resetToken := utils.GenerateRandomPassword(32)
	expireAt := time.Now().UTC().Add(1 * time.Hour)

	update := bson.M{
		"resetToken":  resetToken,
		"resetExpire": expireAt,
		"updatedAt":   time.Now().UTC(),
	}
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": update})
	if err != nil {
		log.Printf("update reset token error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to set reset token")
		return
	}

	// TODO: In production → send real email with reset link
	log.Printf("PASSWORD RESET TOKEN for %s: %s (expires %v)", req.Email, resetToken, expireAt)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "If the email exists in our system, a password reset link has been sent.",
		"expires": expireAt.Format(time.RFC3339),
	})
}

// ResetPassword handles password reset with token
func ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	if req.Token == "" || req.Password == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "token and password required")
		return
	}

	// Password strength validation
	if len(req.Password) < 8 {
		utils.RespondWithError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{
		"resetToken":  req.Token,
		"resetExpire": bson.M{"$gt": time.Now().UTC()},
		"deletedAt":   nil,
	}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid or expired reset token")
			return
		}
		log.Printf("find user by token error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	update := bson.M{
		"passwordHash": hash,
		"resetToken":   nil,
		"resetExpire":  nil,
		"updatedAt":    time.Now().UTC(),
	}
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": update})
	if err != nil {
		log.Printf("update password error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Password has been reset successfully. You can now log in with your new password.",
	})
}

// ValidateToken endpoint to check if token is still valid
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "No authentication token")
		return
	}

	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	// Check if user still exists and not deleted
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var user models.User
	userID, _ := primitive.ObjectIDFromHex(claims.UserID)
	err = userCollection.FindOne(ctx, bson.M{
		"_id":       userID,
		"deletedAt": nil,
	}).Decode(&user)

	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "User account not found")
		return
	}

	normalizedRole := normalizeRole(user.Role)
	dashboardPath := getDashboardPath(normalizedRole)
	landingPage := getDefaultLandingPage(normalizedRole)

	response := map[string]interface{}{
		"valid": true,
		"user": map[string]interface{}{
			"id":          user.ID.Hex(),
			"name":        user.FirstName + " " + user.LastName,
			"email":       user.Email,
			"role":        normalizedRole,
			"dashboard":   dashboardPath,
			"landingPage": landingPage,
		},
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// GetUserProfile returns current user's profile information
func GetUserProfile(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var user models.User
	objID, _ := primitive.ObjectIDFromHex(claims.UserID)
	err = userCollection.FindOne(ctx, bson.M{"_id": objID, "deletedAt": nil}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	normalizedRole := normalizeRole(user.Role)
	dashboardPath := getDashboardPath(normalizedRole)
	landingPage := getDefaultLandingPage(normalizedRole)
	permissions := getPermissionsForRole(normalizedRole)

	response := map[string]interface{}{
		"id":           user.ID.Hex(),
		"firstName":    user.FirstName,
		"lastName":     user.LastName,
		"email":        user.Email,
		"jobTitle":     user.JobTitle,
		"phone":        user.Phone,
		"role":         normalizedRole,
		"dashboard":    dashboardPath,
		"landingPage":  landingPage,
		"organization": user.OrganizationID.Hex(),
		"createdAt":    user.CreatedAt,
		"permissions":  permissions,
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// UpdateUserProfile allows users to update their profile
func UpdateUserProfile(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	var updates struct {
		FirstName string `json:"firstName,omitempty"`
		LastName  string `json:"lastName,omitempty"`
		JobTitle  string `json:"jobTitle,omitempty"`
		Phone     string `json:"phone,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	// Validate inputs
	if updates.FirstName != "" && len(updates.FirstName) > 50 {
		utils.RespondWithError(w, http.StatusBadRequest, "First name too long")
		return
	}
	if updates.LastName != "" && len(updates.LastName) > 50 {
		utils.RespondWithError(w, http.StatusBadRequest, "Last name too long")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	objID, _ := primitive.ObjectIDFromHex(claims.UserID)
	updateFields := bson.M{
		"updatedAt": time.Now().UTC(),
	}
	
	if updates.FirstName != "" {
		updateFields["firstName"] = updates.FirstName
	}
	if updates.LastName != "" {
		updateFields["lastName"] = updates.LastName
	}
	if updates.JobTitle != "" {
		updateFields["jobTitle"] = updates.JobTitle
	}
	if updates.Phone != "" {
		updateFields["phone"] = updates.Phone
	}

	result, err := userCollection.UpdateOne(
		ctx,
		bson.M{"_id": objID, "deletedAt": nil},
		bson.M{"$set": updateFields},
	)
	
	if err != nil {
		log.Printf("Update profile error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update profile")
		return
	}
	
	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Profile updated successfully",
	})
}

// GetDashboardMenu returns navigation menu based on user role
func GetDashboardMenu(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	normalizedRole := normalizeRole(claims.Role)
	menu := getMenuForRole(normalizedRole)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"role": normalizedRole,
		"menu": menu,
	})
}

// getMenuForRole returns navigation menu items based on role
func getMenuForRole(role string) []map[string]interface{} {
	switch role {
	case "superadmin":
		return []map[string]interface{}{
			{
				"title": "Dashboard",
				"icon":  "dashboard",
				"items": []map[string]string{
					{"title": "System Overview", "path": "/dashboards/executive/system-overview.html"},
					{"title": "Enterprise Overview", "path": "/dashboards/executive/dashboards/enterprise-overview.html"},
					{"title": "Enterprise Trends", "path": "/dashboards/executive/dashboards/enterprise-trends.html"},
					{"title": "User Activity", "path": "/dashboards/executive/user-activity.html"},
				},
			},
			{
				"title": "Global Risk Register",
				"icon":  "risk",
				"items": []map[string]string{
					{"title": "All Risks", "path": "/dashboards/executive/global-risk-register/list.html"},
					{"title": "Risk History", "path": "/dashboards/executive/global-risk-register/history.html"},
					{"title": "Bowtie Analysis", "path": "/dashboards/executive/global-risk-register/Bowtie.html"},
				},
			},
			{
				"title": "Global Actions",
				"icon":  "task",
				"items": []map[string]string{
					{"title": "All Actions", "path": "/dashboards/executive/global-actions/list.html"},
					{"title": "Action History", "path": "/dashboards/executive/global-actions/history.html"},
				},
			},
			{
				"title": "Assets",
				"icon":  "asset",
				"items": []map[string]string{
					{"title": "Asset Overview", "path": "/dashboards/executive/assets/overview.html"},
					{"title": "Asset List", "path": "/dashboards/executive/assets/list.html"},
				},
			},
			{
				"title": "Governance",
				"icon":  "governance",
				"items": []map[string]string{
					{"title": "Approvals", "path": "/dashboards/executive/approvals.html"},
					{"title": "Audit Trail", "path": "/dashboards/executive/audit-trail.html"},
					{"title": "Delete Requests", "path": "/dashboards/executive/delete-requests.html"},
				},
			},
			{
				"title": "Admin",
				"icon":  "admin",
				"items": []map[string]string{
					{"title": "Users", "path": "/dashboards/executive/admin/users.html"},
					{"title": "Permissions", "path": "/dashboards/executive/admin/permissions.html"},
					{"title": "System Settings", "path": "/dashboards/executive/admin/system-settings.html"},
				},
			},
		}
		
	case "admin":
		return []map[string]interface{}{
			{
				"title": "Admin Dashboard",
				"icon":  "dashboard",
				"items": []map[string]string{
					{"title": "System Overview", "path": "/dashboards/executive/system-overview.html"},
					{"title": "User Management", "path": "/dashboards/executive/admin/users.html"},
				},
			},
			{
				"title": "Configuration",
				"icon":  "settings",
				"items": []map[string]string{
					{"title": "System Settings", "path": "/dashboards/executive/admin/system-settings.html"},
					{"title": "Permissions", "path": "/dashboards/executive/admin/permissions.html"},
				},
			},
			{
				"title": "Monitoring",
				"icon":  "monitor",
				"items": []map[string]string{
					{"title": "Audit Trail", "path": "/dashboards/executive/audit-trail.html"},
					{"title": "User Activity", "path": "/dashboards/executive/user-activity.html"},
					{"title": "System Logs", "path": "/dashboards/executive/admin/system-settings.html"},
				},
			},
		}
		
	case "analyst":
		return []map[string]interface{}{
			{
				"title": "Dashboard",
				"icon":  "dashboard",
				"items": []map[string]string{
					{"title": "Overview", "path": "/dashboards/analyst/dashboards/overview.html"},
					{"title": "My Work", "path": "/dashboards/analyst/my-work.html"},
					{"title": "Personal Metrics", "path": "/dashboards/analyst/dashboards/personal-metrics.html"},
				},
			},
			{
				"title": "Risk Register",
				"icon":  "risk",
				"items": []map[string]string{
					{"title": "Create Risk", "path": "/dashboards/analyst/risk-register/create.html"},
					{"title": "My Risks", "path": "/dashboards/analyst/risk-register/list.html"},
					{"title": "Submit for Review", "path": "/dashboards/analyst/risk-register/submit.html"},
				},
			},
			{
				"title": "Actions",
				"icon":  "task",
				"items": []map[string]string{
					{"title": "Create Action", "path": "/dashboards/analyst/actions/create.html"},
					{"title": "My Actions", "path": "/dashboards/analyst/actions/list.html"},
				},
			},
		}
		
	case "viewer":
		return []map[string]interface{}{
			{
				"title": "Dashboard",
				"icon":  "dashboard",
				"items": []map[string]string{
					{"title": "Overview", "path": "/dashboards/viewer/dashboards/overview.html"},
				},
			},
			{
				"title": "Risk Register",
				"icon":  "risk",
				"items": []map[string]string{
					{"title": "View Risks", "path": "/dashboards/viewer/risk-register/list.html"},
				},
			},
			{
				"title": "Actions",
				"icon":  "task",
				"items": []map[string]string{
					{"title": "View Actions", "path": "/dashboards/viewer/actions/list.html"},
				},
			},
		}
		
	default:
		return []map[string]interface{}{}
	}
}



// CheckAuth is a simple endpoint to verify authentication
func CheckAuth(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "No authentication token")
		return
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"userID":        claims.UserID,
		"role":          claims.Role,
		"name":          claims.Name,
		"organization":  claims.OrganizationID,
	})
}