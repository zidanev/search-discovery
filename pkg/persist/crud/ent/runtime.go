// Code generated by ent, DO NOT EDIT.

package ent

import (
	"github.com/kubuskotak/king/pkg/persist/crud/ent/article"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/user"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/ymir"
	"github.com/kubuskotak/king/pkg/persist/crud/schema"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	articleFields := schema.Article{}.Fields()
	_ = articleFields
	// articleDescTitle is the schema descriptor for title field.
	articleDescTitle := articleFields[0].Descriptor()
	// article.DefaultTitle holds the default value on creation for the title field.
	article.DefaultTitle = articleDescTitle.Default.(string)
	// article.TitleValidator is a validator for the "title" field. It is called by the builders before save.
	article.TitleValidator = articleDescTitle.Validators[0].(func(string) error)
	// articleDescBody is the schema descriptor for body field.
	articleDescBody := articleFields[1].Descriptor()
	// article.DefaultBody holds the default value on creation for the body field.
	article.DefaultBody = articleDescBody.Default.(string)
	// article.BodyValidator is a validator for the "body" field. It is called by the builders before save.
	article.BodyValidator = articleDescBody.Validators[0].(func(string) error)
	// articleDescDescription is the schema descriptor for description field.
	articleDescDescription := articleFields[2].Descriptor()
	// article.DefaultDescription holds the default value on creation for the description field.
	article.DefaultDescription = articleDescDescription.Default.(string)
	// article.DescriptionValidator is a validator for the "description" field. It is called by the builders before save.
	article.DescriptionValidator = articleDescDescription.Validators[0].(func(string) error)
	// articleDescSlug is the schema descriptor for slug field.
	articleDescSlug := articleFields[3].Descriptor()
	// article.SlugValidator is a validator for the "slug" field. It is called by the builders before save.
	article.SlugValidator = articleDescSlug.Validators[0].(func(string) error)
	userFields := schema.User{}.Fields()
	_ = userFields
	// userDescPassword is the schema descriptor for password field.
	userDescPassword := userFields[2].Descriptor()
	// user.PasswordValidator is a validator for the "password" field. It is called by the builders before save.
	user.PasswordValidator = userDescPassword.Validators[0].(func(string) error)
	ymirFields := schema.Ymir{}.Fields()
	_ = ymirFields
	// ymirDescVersion is the schema descriptor for version field.
	ymirDescVersion := ymirFields[0].Descriptor()
	// ymir.DefaultVersion holds the default value on creation for the version field.
	ymir.DefaultVersion = ymirDescVersion.Default.(string)
}
