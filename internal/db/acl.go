package db

import (
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/pkg/errors"
)

func CreateACLRule(rule *model.ACLRule) error {
	return errors.WithStack(db.Create(rule).Error)
}

func DeleteACLRuleByID(id uint) error {
	return errors.WithStack(db.Where("id = ?", id).Delete(&model.ACLRule{}).Error)
}

func GetACLRuleByID(id uint) (*model.ACLRule, error) {
	var rule model.ACLRule
	if err := db.Where("id = ?", id).First(&rule).Error; err != nil {
		return nil, errors.WithStack(err)
	}
	return &rule, nil
}

func GetACLRules() ([]model.ACLRule, error) {
	var rules []model.ACLRule
	if err := db.Order("priority DESC, id ASC").Find(&rules).Error; err != nil {
		return nil, errors.WithStack(err)
	}
	return rules, nil
}

func GetACLRulesByRole(role string) ([]model.ACLRule, error) {
	var rules []model.ACLRule
	if err := db.Where("role = ?", role).Order("priority DESC, id ASC").Find(&rules).Error; err != nil {
		return nil, errors.WithStack(err)
	}
	return rules, nil
}

func UpdateACLRule(rule *model.ACLRule) error {
	return errors.WithStack(db.Save(rule).Error)
}
