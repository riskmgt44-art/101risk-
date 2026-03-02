package routes

import (
	"fmt"
	"strings"

	"github.com/gorilla/mux"
	"riskmgt/handlers"
	"riskmgt/middleware"
)

// HTTP method constants for better maintainability
var (
	MethodsGetOnly     = []string{"GET", "OPTIONS"}
	MethodsPostOnly    = []string{"POST", "OPTIONS"}
	MethodsPutOnly     = []string{"PUT", "OPTIONS"}
	MethodsDeleteOnly  = []string{"DELETE", "OPTIONS"}
	MethodsGetPost     = []string{"GET", "POST", "OPTIONS"}
	MethodsGetPutDel   = []string{"GET", "PUT", "DELETE", "OPTIONS"}
	MethodsAllCRUD     = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
)

// Route grouping constants
const (
	PathAPI           = "/api"
	PathAuth          = "/api/auth"
	PathOrganizations = "/api/organizations"
	PathHealth        = "/health"
)

func RegisterRoutes(r *mux.Router) {
	// ====================
	// HEALTH CHECK (Public)
	// ====================
	r.HandleFunc(PathHealth, handlers.HealthCheck).Methods(MethodsGetOnly...)

	// ====================
	// AUTHENTICATION ROUTES (Public - No auth required)
	// ====================
	
	// Login/Logout
	r.HandleFunc("/api/auth/login", handlers.Login).Methods(MethodsPostOnly...)
	r.HandleFunc("/api/auth/logout", handlers.Logout).Methods(MethodsPostOnly...)
	
	// Password management
	r.HandleFunc("/api/auth/forgot-password", handlers.ForgotPassword).Methods(MethodsPostOnly...)
	r.HandleFunc("/api/auth/reset-password", handlers.ResetPassword).Methods(MethodsPostOnly...)
	
	// Token validation (public for initial check)
	r.HandleFunc("/api/auth/validate", handlers.ValidateToken).Methods(MethodsGetOnly...)
	r.HandleFunc("/api/auth/check", handlers.CheckAuth).Methods(MethodsGetOnly...)
	
	// ====================
	// PROTECTED API ROUTES (Require authentication)
	// ====================
	apiRouter := r.PathPrefix(PathAPI).Subrouter()
	apiRouter.Use(middleware.AuthMiddleware)
	
	// ====================
	// USER MANAGEMENT
	// ====================
	apiRouter.HandleFunc("/users", handlers.ListUsers).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/users", handlers.GetUsersWithPagination).Methods(MethodsGetOnly...).Queries("page", "{page:[0-9]+}", "limit", "{limit:[0-9]+}", "search", "{search}")
	apiRouter.HandleFunc("/users", handlers.GetUsersWithPagination).Methods(MethodsGetOnly...).Queries("page", "{page:[0-9]+}", "limit", "{limit:[0-9]+}")
	apiRouter.HandleFunc("/users", handlers.GetUsersWithPagination).Methods(MethodsGetOnly...)
	
	apiRouter.HandleFunc("/users/invite", handlers.InviteUsers).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/user/me", handlers.GetCurrentUser).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/user/assets/assigned", handlers.GetUserAssignedAssets).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/organization/users/available", handlers.GetAvailableUsersForAssignment).Methods(MethodsGetOnly...)
	
	// INDIVIDUAL USER ROUTES
	apiRouter.HandleFunc("/users/{id}", handlers.GetUser).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/users/{id}", handlers.UpdateUser).Methods(MethodsPutOnly...)
	apiRouter.HandleFunc("/users/{id}", handlers.DeleteUser).Methods(MethodsDeleteOnly...)
	
	// Bulk user actions
	apiRouter.HandleFunc("/users/bulk-action", handlers.BulkUserActions).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/users/export", handlers.ExportUsers).Methods(MethodsGetOnly...).Queries("format", "{format:csv|json}")
	apiRouter.HandleFunc("/users/export", handlers.ExportUsers).Methods(MethodsGetOnly...)

	// ====================
	// DASHBOARD ENDPOINTS
	// ====================
	apiRouter.HandleFunc("/dashboard/executive", handlers.GetExecutiveOverview).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/dashboard/admin", handlers.GetAdminDashboard).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/dashboard/analyst", handlers.GetAnalystDashboard).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/dashboard/analyst/assigned-assets", handlers.GetAnalystAssignedAssets).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/dashboard/analyst/overview", handlers.GetAnalystOverview).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/dashboard/analyst/charts", handlers.GetAnalystChartData).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/analyst/assets", handlers.GetAnalystAssignedAssets).Methods(MethodsGetOnly...)

	// ====================
	// VIEWER DASHBOARD ENDPOINTS
	// ====================
	apiRouter.HandleFunc("/viewer/dashboard", handlers.GetViewerDashboard).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/viewer/assets", handlers.GetViewerAssets).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/viewer/risks", handlers.GetViewerRisks).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/viewer/risks/{id}", handlers.GetViewerRisk).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/viewer/actions", handlers.GetViewerActions).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/viewer/audit", handlers.GetViewerAuditLogs).Methods(MethodsGetOnly...)

	// ====================
	// ASSETS
	// ====================
	apiRouter.HandleFunc("/assets", handlers.ListAssets).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/assets", handlers.CreateAsset).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/assets/{id}", handlers.GetAsset).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/assets/{id}", handlers.UpdateAsset).Methods(MethodsPutOnly...)
	apiRouter.HandleFunc("/assets/{id}", handlers.DeleteAsset).Methods(MethodsDeleteOnly...)
	apiRouter.HandleFunc("/assets/{id}/risks", handlers.GetAssetRisks).Methods(MethodsGetOnly...)
	
	// Asset-User assignment routes
	apiRouter.HandleFunc("/assets/{id}/users", handlers.AssignUsersToAsset).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/assets/{id}/users", handlers.GetAssetUsers).Methods(MethodsGetOnly...)

	// ====================
	// ACTIONS
	// ====================
	apiRouter.HandleFunc("/actions", handlers.ListActions).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/actions", handlers.CreateAction).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/actions/{id}", handlers.GetActionByID).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/actions/{id}", handlers.UpdateAction).Methods(MethodsPutOnly...)
	apiRouter.HandleFunc("/actions/{id}", handlers.DeleteAction).Methods(MethodsDeleteOnly...)
	apiRouter.HandleFunc("/actions/risk/{riskId}", handlers.GetActionsByRiskID).Methods(MethodsGetOnly...)

	// ====================
	// APPROVALS - GENERAL
	// ====================
	apiRouter.HandleFunc("/approvals", handlers.ListApprovals).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/approvals", handlers.CreateApproval).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/approvals/{id}", handlers.GetApproval).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/approvals/{id}", handlers.UpdateApprovalStatus).Methods(MethodsPutOnly...)
	apiRouter.HandleFunc("/approvals/{id}", handlers.DeleteApproval).Methods(MethodsDeleteOnly...)
	apiRouter.HandleFunc("/approvals/type/{type}", handlers.GetApprovalsByType).Methods(MethodsGetOnly...)
	
	// ====================
	// APPROVALS - ANALYST SPECIFIC
	// ====================
	apiRouter.HandleFunc("/approvals/analyst", handlers.GetAnalystApprovals).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/approvals/analyst/stats", handlers.GetAnalystApprovalStats).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/approvals/analyst/{id}", handlers.GetAnalystApproval).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/approvals/analyst/{id}/cancel", handlers.AnalystCancelApproval).Methods(MethodsPostOnly...)

	// ====================
	// RISKS - GENERAL
	// ====================
	apiRouter.HandleFunc("/risks", handlers.ListRisks).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/risks", handlers.CreateRisk).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/risks/{id}", handlers.GetRisk).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/risks/{id}", handlers.UpdateRisk).Methods(MethodsPutOnly...)
	apiRouter.HandleFunc("/risks/{id}", handlers.DeleteRisk).Methods(MethodsDeleteOnly...)
	apiRouter.HandleFunc("/risks/asset/{assetId}", handlers.GetRisksByAsset).Methods(MethodsGetOnly...)

	// ====================
	// RISKS - ANALYST SPECIFIC
	// ====================
	apiRouter.HandleFunc("/analyst/risks", handlers.GetAnalystRisks).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/analyst/risks", handlers.CreateAnalystRisk).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/analyst/risks/{id}", handlers.GetAnalystRisk).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/analyst/risks/stats", handlers.GetAnalystRiskStats).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/risks/analyst/{id}/resubmit", handlers.ResubmitAnalystRisk).Methods(MethodsPostOnly...)

	// ====================
	// RISKS - BOWTIE (NEW)
	// ====================
	apiRouter.HandleFunc("/risks/bowtie", handlers.CreateRiskV2).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/risks/bowtie/{id}", handlers.GetRiskBowtieView).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/risks/bowtie/{id}", handlers.UpdateRiskV2).Methods(MethodsPutOnly...)
	apiRouter.HandleFunc("/analyst/risks/bowtie", handlers.CreateAnalystRiskV2).Methods(MethodsPostOnly...)

	// ====================
	// HEATMAP
	// ====================
	apiRouter.HandleFunc("/heatmap", handlers.GetHeatmapData).Methods(MethodsGetOnly...)

	// ====================
	// AUDIT LOGS
	// ====================
	apiRouter.HandleFunc("/audit", handlers.ListAuditLogs).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/analyst/audit", handlers.ListAnalystAuditLogs).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/analyst/audit/stats", handlers.GetAnalystAuditStats).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/audit/stats", handlers.GetAuditStats).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/audit-logs", handlers.ListAuditLogs).Methods(MethodsGetOnly...)

	// ====================
	// USER PROFILE ROUTES
	// ====================
	apiRouter.HandleFunc("/user/profile", handlers.GetUserProfile).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/user/profile", handlers.UpdateUserProfile).Methods(MethodsPutOnly...)
	apiRouter.HandleFunc("/user/change-password", handlers.ChangePassword).Methods(MethodsPostOnly...)
	apiRouter.HandleFunc("/user/dashboard-menu", handlers.GetDashboardMenu).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/user/validate-token", handlers.ValidateToken).Methods(MethodsGetOnly...)
	apiRouter.HandleFunc("/user/check-auth", handlers.CheckAuth).Methods(MethodsGetOnly...)
	
	// Debug: Print all registered routes
	r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		t, err := route.GetPathTemplate()
		if err == nil {
			methods, _ := route.GetMethods()
			fmt.Printf("Route: %s %s\n", strings.Join(methods, ","), t)
		}
		return nil
	})
}