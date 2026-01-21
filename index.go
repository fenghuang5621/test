package plg_authorization_rbac

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	. "github.com/mickael-kerjean/filestash/server/common"
)

func init() {
	Hooks.Register.AuthorisationMiddleware(RBACAuth{})
}

// RBACAuth 插件主结构
type RBACAuth struct {
	configCache *RBACConfig
	cacheMutex  sync.RWMutex
}

// RBACConfig RBAC配置结构
type RBACConfig struct {
	Roles       map[string]Role       `json:"roles"`
	Permissions map[string]Permission `json:"permissions"`
	PathRules   []PathRule            `json:"path_rules"`
}

// Role 角色定义
type Role struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Inherits    []string `json:"inherits"`
}

// Permission 权限定义
type Permission struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"` // ls, cat, mkdir, save, rm, mv, touch
}

// PathRule 路径规则
type PathRule struct {
	Pattern     string   `json:"pattern"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Deny        bool     `json:"deny"`
}

// ------------------- Action 权限检查 -------------------

func (this RBACAuth) Ls(ctx *App, path string) error {
	return this.checkPermission(ctx, "ls", path)
}

func (this RBACAuth) Cat(ctx *App, path string) error {
	return this.checkPermission(ctx, "cat", path)
}

func (this RBACAuth) Mkdir(ctx *App, path string) error {
	return this.checkPermission(ctx, "mkdir", path)
}

func (this RBACAuth) Rm(ctx *App, path string) error {
	return this.checkPermission(ctx, "rm", path)
}

func (this RBACAuth) Mv(ctx *App, from string, to string) error {
	if err := this.checkPermission(ctx, "mv", from); err != nil {
		return err
	}
	return this.checkPermission(ctx, "mv", to)
}

func (this RBACAuth) Save(ctx *App, path string) error {
	return this.checkPermission(ctx, "save", path)
}

func (this RBACAuth) Touch(ctx *App, path string) error {
	return this.checkPermission(ctx, "touch", path)
}

// ------------------- 核心逻辑 -------------------

func (this RBACAuth) checkPermission(ctx *App, action string, path string) error {
	config, err := this.loadConfig(ctx)
	if err != nil {
		Log.Warning("plg_authorization_rbac: Failed to load config: %v", err)
		return ErrNotAllowed
	}

	userRoles := this.getUserRoles(ctx, config)
	if len(userRoles) == 0 {
		Log.Debug("plg_authorization_rbac: No roles found for user")
		return ErrNotAllowed
	}

	allowed := this.checkPathRules(config, userRoles, path, action)
	if !allowed {
		Log.Info("plg_authorization_rbac: Access denied - user=%s, roles=%v, action=%s, path=%s",
			this.getUsername(ctx), userRoles, action, path)
		return ErrNotAllowed
	}

	Log.Debug("plg_authorization_rbac: Access granted - user=%s, roles=%v, action=%s, path=%s",
		this.getUsername(ctx), userRoles, action, path)
	return nil
}

// ------------------- 配置加载 -------------------

func (this *RBACAuth) loadConfig(ctx *App) (*RBACConfig, error) {
	this.cacheMutex.RLock()
	if this.configCache != nil {
		defer this.cacheMutex.RUnlock()
		return this.configCache, nil
	}
	this.cacheMutex.RUnlock()

	configStr := Config.Get("auth.rbac_config").String()
	if configStr == "" {
		return nil, fmt.Errorf("RBAC configuration is empty")
	}

	var config RBACConfig
	if err := json.Unmarshal([]byte(configStr), &config); err != nil {
		return nil, fmt.Errorf("failed to parse RBAC config: %v", err)
	}

	this.cacheMutex.Lock()
	this.configCache = &config
	this.cacheMutex.Unlock()

	return &config, nil
}

// ------------------- 用户角色 -------------------

func (this RBACAuth) getUserRoles(ctx *App, config *RBACConfig) []string {
	roleAttr := Config.Get("auth.role_attribute").String()
	if roleAttr == "" {
		roleAttr = "role"
	}

	var userRoleStr string
	if val, ok := ctx.Session[roleAttr]; ok && val != "" {
		userRoleStr = val
	}

	if userRoleStr == "" {
		defaultRole := Config.Get("auth.default_role").String()
		if defaultRole == "" {
			defaultRole = "viewer"
		}
		userRoleStr = defaultRole
	}

	roleNames := strings.Split(userRoleStr, ",")
	allRoles := make(map[string]bool)

	for _, roleName := range roleNames {
		roleName = strings.TrimSpace(roleName)
		this.expandRoles(config, roleName, allRoles)
	}

	result := make([]string, 0, len(allRoles))
	for role := range allRoles {
		result = append(result, role)
	}

	return result
}

func (this RBACAuth) expandRoles(config *RBACConfig, roleName string, expanded map[string]bool) {
	if expanded[roleName] {
		return
	}
	role, exists := config.Roles[roleName]
	if !exists {
		return
	}
	expanded[roleName] = true
	for _, inheritRole := range role.Inherits {
		this.expandRoles(config, inheritRole, expanded)
	}
}

// ------------------- PathRules -------------------

func (this RBACAuth) checkPathRules(config *RBACConfig, userRoles []string, path string, action string) bool {
	path = filepath.Clean("/" + path)

	var matchedAllow *PathRule
	var matchedDeny *PathRule
	var maxAllowLen, maxDenyLen int

	for i := range config.PathRules {
		rule := &config.PathRules[i]
		if !this.hasAnyRole(userRoles, rule.Roles) {
			continue
		}

		if this.matchPath(rule.Pattern, path) {
			if rule.Deny {
				if len(rule.Pattern) > maxDenyLen {
					maxDenyLen = len(rule.Pattern)
					matchedDeny = rule
				}
			} else {
				if len(rule.Pattern) > maxAllowLen {
					maxAllowLen = len(rule.Pattern)
					matchedAllow = rule
				}
			}
		}
	}

	// deny 优先
	if matchedDeny != nil {
		return false
	}

	if matchedAllow != nil {
		return this.checkPermissions(config, matchedAllow.Permissions, action)
	}

	// 默认拒绝
	return false
}

func (this RBACAuth) matchPath(pattern string, path string) bool {
	pattern = filepath.Clean("/" + pattern)

	if strings.Contains(pattern, "**") {
		prefix := strings.Split(pattern, "**")[0]
		prefix = strings.TrimRight(prefix, "/")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}

	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, path)
		return matched
	}

	return path == pattern || strings.HasPrefix(path, pattern+"/")
}

func (this RBACAuth) hasAnyRole(userRoles []string, requiredRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true
	}
	for _, ur := range userRoles {
		for _, rr := range requiredRoles {
			if ur == rr {
				return true
			}
		}
	}
	return false
}

func (this RBACAuth) checkPermissions(config *RBACConfig, permissionIDs []string, action string) bool {
	for _, permID := range permissionIDs {
		perm, exists := config.Permissions[permID]
		if !exists {
			continue
		}
		for _, act := range perm.Actions {
			if act == action || act == "*" {
				return true
			}
		}
	}
	return false
}

// ------------------- 用户名 -------------------

func (this RBACAuth) getUsername(ctx *App) string {
	if username, ok := ctx.Session["username"]; ok && username != "" {
		return username
	}
	if user, ok := ctx.Session["user"]; ok && user != "" {
		return user
	}
	return "unknown"
}
