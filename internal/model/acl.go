package model

import "time"

// ACLRule represents an access control rule for a specific role and path
type ACLRule struct {
	ID               uint      `json:"id" gorm:"primaryKey"`
	Role             string    `json:"role" gorm:"index;not null"`             // OIDC role name
	IsRegex          bool      `json:"is_regex" gorm:"default:false"`          // whether Role is a regex pattern
	Path             string    `json:"path" gorm:"not null"`                   // path pattern (e.g., "/", "/folder")
	ExcludeSubfolder bool      `json:"exclude_subfolder" gorm:"default:false"` // whether to exclude all subfolders (default: false)
	Permissions      int32     `json:"permissions"`                            // bitwise permissions
	Priority         int       `json:"priority" gorm:"default:0"`              // higher priority rules override lower ones
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// ACL Permission bits
const (
	ACLPermRead     int32 = 1 << iota // Read/List files
	ACLPermWrite                      // Upload/Create files
	ACLPermDelete                     // Delete files
	ACLPermManage                     // Manage (rename, move, copy)
	ACLPermShare                      // Create shares
	ACLPermDownload                   // Download files
)

// HasPermission checks if the rule has a specific permission
func (r *ACLRule) HasPermission(perm int32) bool {
	return r.Permissions&perm != 0
}

// ACLMatchedRule represents a matched rule with its details
type ACLMatchedRule struct {
	Rule        *ACLRule `json:"rule"`
	Permissions int32    `json:"permissions"`
	Path        string   `json:"path"`
}
