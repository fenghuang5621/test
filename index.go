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

// Ls 列出目录权限检查
func (this RBACAuth) Ls(ctx *App, path string) error {
	return this.checkPermission(ctx, "ls", path)
}

// Cat 读取文件权限检查
func (this RBACAuth) Cat(ctx *App, path string) error {
	return this.checkPermission(ctx, "cat", path)
}

// Mkdir 创建目录权限检查
func (this RBACAuth) Mkdir(ctx *App, path string) error {
	return this.checkPermission(ctx, "mkdir", path)
}

// Rm 删除权限检查
func (this RBACAuth) Rm(ctx *App, path string) error {
	return this.checkPermission(ctx, "rm", path)
}

// Mv 移动/重命名权限检查
func (this RBACAuth) Mv(ctx *App, from string, to string) error {
	// 检查源文件的移动权限
	if err := this.checkPermission(ctx, "mv", from); err != nil {
		return err
	}
	// 检查目标位置的写入权限
	return this.checkPermission(ctx, "mv", to)
}

// Save 保存文件权限检查
func (this RBACAuth) Save(ctx *App, path string) error {
	return this.checkPermission(ctx, "save", path)
}

// Touch 创建空文件权限检查
func (this RBACAuth) Touch(ctx *App, path string) error {
	return this.checkPermission(ctx, "touch", path)
}

// checkPermission 通用权限检查逻辑
func (this RBACAuth) checkPermission(ctx *App, action string, path string) error {
	// 加载RBAC配置
	config, err := this.loadConfig(ctx)
	if err != nil {
		Log.Warning("plg_authorization_rbac: Failed to load config: %v", err)
		return ErrNotAllowed
	}

	// 获取用户角色
	userRoles := this.getUserRoles(ctx, config)
	if len(userRoles) == 0 {
		Log.Debug("plg_authorization_rbac: No roles found for user")
		return ErrNotAllowed
	}

	// 检查路径规则
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

// loadConfig 加载并缓存配置
func (this *RBACAuth) loadConfig(ctx *App) (*RBACConfig, error) {
	this.cacheMutex.RLock()
	if this.configCache != nil {
		defer this.cacheMutex.RUnlock()
		return this.configCache, nil
	}
	this.cacheMutex.RUnlock()

	// 获取配置字符串
	configStr := Config.Get("auth.rbac_config").String()
	if configStr == "" {
		return nil, fmt.Errorf("RBAC configuration is empty")
	}

	var config RBACConfig
	if err := json.Unmarshal([]byte(configStr), &config); err != nil {
		return nil, fmt.Errorf("failed to parse RBAC config: %v", err)
	}

	// 缓存配置
	this.cacheMutex.Lock()
	this.configCache = &config
	this.cacheMutex.Unlock()

	return &config, nil
}

// getUserRoles 获取用户的所有角色（包括继承）
func (this RBACAuth) getUserRoles(ctx *App, config *RBACConfig) []string {
	roleAttr := Config.Get("auth.role_attribute").String()
	if roleAttr == "" {
		roleAttr = "role"
	}

	// 从session获取用户角色
	var userRoleStr string
	if val := ctx.Session[roleAttr]; val != nil {
		userRoleStr = fmt.Sprintf("%v", val)
	}

	// 如果没有角色，尝试从其他属性获取
	if userRoleStr == "" {
		// 尝试从 attributes 中获取
		if attrs, ok := ctx.Session["attributes"].(map[string]interface{}); ok {
			if role, exists := attrs[roleAttr]; exists {
				userRoleStr = fmt.Sprintf("%v", role)
			}
		}
	}

	// 使用默认角色
	if userRoleStr == "" {
		defaultRole := Config.Get("auth.default_role").String()
		if defaultRole == "" {
			defaultRole = "viewer"
		}
		userRoleStr = defaultRole
	}

	// 解析角色列表（支持逗号分隔）
	roleNames := strings.Split(userRoleStr, ",")
	allRoles := make(map[string]bool)

	// 递归获取所有角色（包括继承）
	for _, roleName := range roleNames {
		roleName = strings.TrimSpace(roleName)
		this.expandRoles(config, roleName, allRoles)
	}

	// 转换为列表
	result := make([]string, 0, len(allRoles))
	for role := range allRoles {
		result = append(result, role)
	}

	return result
}

// expandRoles 递归展开角色继承
func (this RBACAuth) expandRoles(config *RBACConfig, roleName string, expanded map[string]bool) {
	if expanded[roleName] {
		return // 避免循环继承
	}

	role, exists := config.Roles[roleName]
	if !exists {
		return
	}

	expanded[roleName] = true

	// 递归展开继承的角色
	for _, inheritRole := range role.Inherits {
		this.expandRoles(config, inheritRole, expanded)
	}
}

// checkPathRules 检查路径规则
func (this RBACAuth) checkPathRules(config *RBACConfig, userRoles []string, path string, action string) bool {
	// 规范化路径
	path = filepath.Clean("/" + path)

	// 按优先级检查路径规则（更具体的规则优先）
	var matchedRule *PathRule
	var maxMatchLen int

	for i := range config.PathRules {
		rule := &config.PathRules[i]
		if this.matchPath(rule.Pattern, path) {
			// 检查用户是否有匹配的角色
			if !this.hasAnyRole(userRoles, rule.Roles) {
				continue
			}

			// 选择最具体的匹配规则
			patternLen := len(rule.Pattern)
			if patternLen > maxMatchLen {
				maxMatchLen = patternLen
				matchedRule = rule
			}
		}
	}

	// 如果没有匹配的规则，拒绝访问
	if matchedRule == nil {
		return false
	}

	// 如果规则明确拒绝，返回拒绝
	if matchedRule.Deny {
		return false
	}

	// 检查权限是否允许该操作
	return this.checkPermissions(config, matchedRule.Permissions, action)
}

// matchPath 匹配路径模式
func (this RBACAuth) matchPath(pattern string, path string) bool {
	pattern = filepath.Clean("/" + pattern)
	
	// 处理 ** 递归通配符
	if strings.Contains(pattern, "**") {
		prefix := strings.Split(pattern, "**")[0]
		return strings.HasPrefix(path, prefix)
	}

	// 处理 * 单层通配符
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, path)
		return matched
	}

	// 精确匹配或前缀匹配
	return path == pattern || strings.HasPrefix(path, pattern+"/")
}

// hasAnyRole 检查用户是否有任意一个指定角色
func (this RBACAuth) hasAnyRole(userRoles []string, requiredRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true
	}

	for _, userRole := range userRoles {
		for _, reqRole := range requiredRoles {
			if userRole == reqRole {
				return true
			}
		}
	}
	return false
}

// checkPermissions 检查权限是否允许操作
func (this RBACAuth) checkPermissions(config *RBACConfig, permissionIDs []string, action string) bool {
	for _, permID := range permissionIDs {
		perm, exists := config.Permissions[permID]
		if !exists {
			continue
		}

		// 检查权限是否包含该操作
		for _, allowedAction := range perm.Actions {
			if allowedAction == action || allowedAction == "*" {
				return true
			}
		}
	}

	return false
}

// getUsername 获取用户名（用于日志）
func (this RBACAuth) getUsername(ctx *App) string {
	if username := ctx.Session["username"]; username != nil {
		return fmt.Sprintf("%v", username)
	}
	if user := ctx.Session["user"]; user != nil {
		return fmt.Sprintf("%v", user)
	}
	return "unknown"
}
