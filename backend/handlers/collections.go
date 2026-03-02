// handlers/collections.go
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"riskmgt/database"
	"riskmgt/models"
)

// Database collections
var (
	db                         *mongo.Database
	orgCollection              *mongo.Collection
	userCollection             *mongo.Collection
	actionCollection           *mongo.Collection
	riskCollection             *mongo.Collection
	approvalCollection         *mongo.Collection
	auditLogCollection         *mongo.Collection
	roleCollection             *mongo.Collection
	assetCollection            *mongo.Collection
	assetAssignmentCollection  *mongo.Collection
)

// InitializeCollections - Consolidated initialization function
func InitializeCollections() {
	if database.Client == nil {
		log.Fatal("Database client is nil. Call database.Connect() first")
	}

	db = database.Client.Database("riskmgt")
	
	// Initialize ALL collections
	orgCollection = db.Collection("organizations")
	userCollection = db.Collection("users")
	actionCollection = db.Collection("actions")
	riskCollection = db.Collection("risks")
	approvalCollection = db.Collection("approvals")
	auditLogCollection = db.Collection("audit_logs")
	roleCollection = db.Collection("roles")
	assetCollection = db.Collection("assets")
	assetAssignmentCollection = db.Collection("asset_assignments")
	
	// Create indexes for better performance
	createIndexes()
	
	log.Printf("✅ Successfully initialized %d collections", 9)
	log.Printf("   approvalCollection initialized: %v", approvalCollection != nil)
}

// createIndexes creates necessary indexes for collections
func createIndexes() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Risk collection indexes
	riskIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "organizationId", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "assetId", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "riskId", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "createdAt", Value: -1}},
		},
		{
			Keys: bson.D{{Key: "status", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "createdBy", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "subProject", Value: 1}},
		},
	}
	
	if _, err := riskCollection.Indexes().CreateMany(ctx, riskIndexes); err != nil {
		log.Printf("Warning: Could not create risk indexes: %v", err)
	}

	// Approval collection indexes
	approvalIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "organizationId", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "status", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "submittedBy", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "createdAt", Value: -1}},
		},
	}
	
	if _, err := approvalCollection.Indexes().CreateMany(ctx, approvalIndexes); err != nil {
		log.Printf("Warning: Could not create approval indexes: %v", err)
	}

	// User collection indexes
	userIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "email", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "organizationId", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "role", Value: 1}},
		},
	}
	
	if _, err := userCollection.Indexes().CreateMany(ctx, userIndexes); err != nil {
		log.Printf("Warning: Could not create user indexes: %v", err)
	}

	// Asset collection indexes
	assetIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "organizationId", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "ownerUserId", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "assignedUserIds", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "status", Value: 1}},
		},
	}
	
	if _, err := assetCollection.Indexes().CreateMany(ctx, assetIndexes); err != nil {
		log.Printf("Warning: Could not create asset indexes: %v", err)
	}

	// Audit log indexes
	auditIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "organizationId", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "userId", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "action", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "createdAt", Value: -1}},
		},
	}
	
	if _, err := auditLogCollection.Indexes().CreateMany(ctx, auditIndexes); err != nil {
		log.Printf("Warning: Could not create audit log indexes: %v", err)
	}
}

// GetApprovalCollection returns the approval collection (for debugging)
func GetApprovalCollection() *mongo.Collection {
	return approvalCollection
}

// CreateAuditLog helper function
func CreateAuditLog(ctx context.Context, r *http.Request, action, entity string, entityID primitive.ObjectID, details interface{}) error {
	if auditLogCollection == nil {
		return fmt.Errorf("audit log collection not initialized")
	}

	// Get user info from context
	userID, ok1 := r.Context().Value("userID").(string)
	userName, ok2 := r.Context().Value("userName").(string)
	userRole, ok3 := r.Context().Value("userRole").(string)
	orgID, ok4 := r.Context().Value("orgID").(string)

	// Check if context values exist
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return fmt.Errorf("missing user context information")
	}

	// Parse IDs
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %v", err)
	}

	orgObjectID, err := primitive.ObjectIDFromHex(orgID)
	if err != nil {
		return fmt.Errorf("invalid org ID: %v", err)
	}

	// Convert details to bson.M if it's not already
	var detailsBSON interface{}
	switch v := details.(type) {
	case string:
		detailsBSON = v
	case map[string]interface{}:
		detailsBSON = v
	case bson.M:
		detailsBSON = v
	default:
		detailsBSON = fmt.Sprintf("%v", v)
	}

	// Create audit log
	auditLog := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgObjectID,
		UserID:         userObjectID,
		UserEmail:      userName,
		UserRole:       userRole,
		Action:         action,
		EntityType:     entity,
		EntityID:       entityID,
		Details:        detailsBSON,
		CreatedAt:      time.Now(),
		IPAddress:      r.RemoteAddr,
		UserAgent:      r.UserAgent(),
	}

	_, err = auditLogCollection.InsertOne(ctx, auditLog)
	if err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	return err
}

// CheckCollectionsStatus returns the status of all collections
func CheckCollectionsStatus() map[string]bool {
	return map[string]bool{
		"orgCollection":              orgCollection != nil,
		"userCollection":             userCollection != nil,
		"riskCollection":             riskCollection != nil,
		"approvalCollection":         approvalCollection != nil,
		"auditLogCollection":         auditLogCollection != nil,
		"assetCollection":            assetCollection != nil,
		"actionCollection":           actionCollection != nil,
		"roleCollection":             roleCollection != nil,
		"assetAssignmentCollection":  assetAssignmentCollection != nil,
	}
}

// GetRiskCollection returns the risk collection
func GetRiskCollection() *mongo.Collection {
	return riskCollection
}

// GetAssetCollection returns the asset collection
func GetAssetCollection() *mongo.Collection {
	return assetCollection
}

// GetUserCollection returns the user collection
func GetUserCollection() *mongo.Collection {
	return userCollection
}

// GetActionCollection returns the action collection
func GetActionCollection() *mongo.Collection {
	return actionCollection
}

// GetAuditLogCollection returns the audit log collection
func GetAuditLogCollection() *mongo.Collection {
	return auditLogCollection
}

// GetOrgCollection returns the organization collection
func GetOrgCollection() *mongo.Collection {
	return orgCollection
}