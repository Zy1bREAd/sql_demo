package utils

import "github.com/go-playground/validator/v10"

var VA *validator.Validate

// ! 新建校验器,存在则继续沿用。
func NewValidator() *validator.Validate {
	if VA == nil {
		VA = validator.New()
	}
	return VA
}
