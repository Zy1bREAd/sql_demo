package apis

import "github.com/google/uuid"

// uuid v4
func GenerateUUIDKey() string {
	return uuid.New().String()
}
