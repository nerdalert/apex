package handlers

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nexodus-io/nexodus/internal/models"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/http"
)

// key for username in gin.Context
const AuthUserName string = "_nexodus.UserName"

func (api *API) CreateUserIfNotExists() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetString(gin.AuthUserKey)
		username := c.GetString(AuthUserName)
		_, err := api.createUserIfNotExists(c.Request.Context(), id, username)
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.Next()
	}
}

func (api *API) UserIsCurrentUser(c *gin.Context) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		userId := c.Value(gin.AuthUserKey).(string)

		// this could potentially be driven by rego output
		return db.Where("id = ?", userId)
	}
}

var noUUID = uuid.UUID{}

func (api *API) createUserIfNotExists(ctx context.Context, id string, userName string) (uuid.UUID, error) {
	ctx, span := tracer.Start(ctx, "createUserIfNotExists")
	defer span.End()
	span.SetAttributes(
		attribute.String("user-id", id),
		attribute.String("username", userName),
	)
	tx := api.db
	var user models.User
	res := tx.Unscoped().First(&user, "id = ?", id)
	if res.Error == nil {

		// Was the user was previously deleted... lets make him active again.
		if user.DeletedAt.Valid {
			user.DeletedAt = gorm.DeletedAt{}
			res = tx.Unscoped().Model(&user).Update("DeletedAt", user.DeletedAt)
			if res.Error != nil {
				return noUUID, res.Error
			}
		}

		// Check if the UserName has changed since the last time we saw this user
		if user.UserName != userName {
			res = tx.Model(&user).Update("UserName", userName)
			if res.Error != nil {
				return noUUID, res.Error
			}
		}

		return api.createUserOrgIfNotExists(ctx, id, userName)
	}

	if !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return noUUID, fmt.Errorf("can't find record for user id %s", id)
	}
	user.ID = id
	user.UserName = userName
	res = tx.Create(&user)
	if res.Error == nil {
		return api.createUserOrgIfNotExists(ctx, id, userName)
	}
	if res.Error.Error() != "duplicated key not allowed" {
		return noUUID, fmt.Errorf("can't create user record: %w", res.Error)
	}

	// is another concurrent request creating the user???
	user = models.User{}
	if tx.Unscoped().First(&user, "id = ?", id).Error == nil {
		return api.createUserOrgIfNotExists(ctx, id, userName)
	}

	return noUUID, fmt.Errorf("can't create user record: %w", res.Error)
}

func (api *API) createUserOrgIfNotExists(ctx context.Context, userId string, userName string) (uuid.UUID, error) {

	// Get the first org the use owns.
	org := models.Organization{}
	res := api.db.Where("owner_id = ?", userId).First(&org)
	if res.Error == nil {
		return org.ID, nil
	}
	if !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return noUUID, res.Error
	}

	sg, err := api.createDefaultSecurityGroup(ctx, uuid.Nil.String())
	if err != nil {
		return noUUID, fmt.Errorf("failed to create the default security group: %w", res.Error)
	}

	org = models.Organization{
		Name:        userName,
		OwnerID:     userId,
		Description: fmt.Sprintf("%s's organization", userName),
		IpCidr:      defaultOrganizationPrefixIPv4,
		IpCidrV6:    defaultOrganizationPrefixIPv6,
		HubZone:     true,
		Users: []*models.User{&models.User{
			ID: userId,
		}},
		SecurityGroupIds: sg.ID,
	}
	if res = api.db.Create(&org); res.Error == nil {

		if err := api.ipam.CreateNamespace(ctx, org.ID); err != nil {
			return noUUID, fmt.Errorf("failed to create ipam namespace: %w", err)
		}
		if err := api.ipam.AssignPrefix(ctx, org.ID, defaultOrganizationPrefixIPv4); err != nil {
			return noUUID, fmt.Errorf("can't assign default ipam v4 prefix: %w", err)
		}
		if err := api.ipam.AssignPrefix(ctx, org.ID, defaultOrganizationPrefixIPv6); err != nil {
			return noUUID, fmt.Errorf("can't assign default ipam v6 prefix: %w", err)
		}

		if sg.OrganizationId != org.SecurityGroupIds {
			// Update the default security group with the new organization id
			if err := api.updateDefaultSecurityGroupOrgId(ctx, sg.ID.String(), org.ID); err != nil {
				return noUUID, fmt.Errorf("failed to create the default security group: %w", res.Error)
			}
		}

		return org.ID, nil
	}

	if res.Error.Error() != "duplicated key not allowed" {
		return noUUID, fmt.Errorf("can't create organization record: %w", res.Error)
	}

	// maybe another concurrent request created it...
	org = models.Organization{}
	if api.db.Where("owner_id = ?", userId).First(&org).Error == nil {
		return org.ID, nil
	}

	return noUUID, fmt.Errorf("can't create organization record: %w", res.Error)
}

// GetUser gets a user
// @Summary      Get User
// @Description  Gets a user
// @Id           GetUser
// @Tags         Users
// @Accepts		 json
// @Produce      json
// @Param        id  path       string  true  "User ID"
// @Success      200  {object}  models.User
// @Failure      400  {object}  models.BaseError
// @Failure		 401  {object}  models.BaseError
// @Failure      404  {object}  models.BaseError
// @Failure		 429  {object}  models.BaseError
// @Failure      500  {object}  models.BaseError
// @Router       /api/users/{id} [get]
func (api *API) GetUser(c *gin.Context) {
	ctx, span := tracer.Start(c.Request.Context(), "GetUser",
		trace.WithAttributes(
			attribute.String("id", c.Param("id")),
		))
	defer span.End()
	userId := c.Param("id")
	if userId == "" {
		c.JSON(http.StatusBadRequest, models.NewBadPathParameterError("id"))
		return
	}

	var user models.User
	if userId == "me" {
		userId = c.GetString(gin.AuthUserKey)
	}

	if res := api.db.WithContext(ctx).
		Scopes(api.UserIsCurrentUser(c)).
		First(&user, "id = ?", userId); res.Error != nil {
		c.JSON(http.StatusNotFound, models.NewNotFoundError("user"))
		return
	}
	c.JSON(http.StatusOK, user)
}

// ListUsers lists users
// @Summary      List Users
// @Description  Lists all users
// @Id           ListUsers
// @Tags         Users
// @Accepts		 json
// @Produce      json
// @Success      200  {object}  []models.User
// @Failure		 401  {object}  models.BaseError
// @Failure		 429  {object}  models.BaseError
// @Router       /api/users [get]
func (api *API) ListUsers(c *gin.Context) {
	ctx, span := tracer.Start(c.Request.Context(), "ListUsers")
	defer span.End()
	users := make([]*models.User, 0)
	result := api.db.WithContext(ctx).
		Scopes(api.UserIsCurrentUser(c)).
		Scopes(FilterAndPaginate(&models.User{}, c, "user_name")).
		Find(&users)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "error fetching keys from db"})
		return
	}
	c.JSON(http.StatusOK, users)
}

// DeleteUser delete a user
// @Summary      Delete User
// @Description  Delete a user
// @Id           DeleteUser
// @Tags         Users
// @Accepts		 json
// @Produce      json
// @Param        id  path       string  true  "User ID"
// @Success      200  {object}  models.User
// @Failure		 400  {object}  models.BaseError
// @Failure      400  {object}  models.BaseError
// @Failure		 429  {object}  models.BaseError
// @Failure      500  {object}  models.BaseError
// @Router       /api/users/{id} [delete]
func (api *API) DeleteUser(c *gin.Context) {
	ctx, span := tracer.Start(c.Request.Context(), "DeleteUser")
	defer span.End()
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, models.NewBadPathParameterError("id"))
		return
	}

	var user models.User
	err := api.transaction(ctx, func(tx *gorm.DB) error {
		if res := api.db.
			Scopes(api.UserIsCurrentUser(c)).
			First(&user, "id = ?", userID); res.Error != nil {
			return errUserNotFound
		}
		if res := api.db.Select(clause.Associations).Delete(&user); res.Error != nil {
			c.JSON(http.StatusInternalServerError, models.NewApiInternalError(fmt.Errorf("failed to delete user: %w", res.Error)))
		}

		return nil
	})

	if err != nil {
		if errors.Is(err, errUserNotFound) {
			c.JSON(http.StatusNotFound, models.NewNotFoundError("user"))
		} else {
			c.JSON(http.StatusInternalServerError, models.NewApiInternalError(err))
		}
		return
	}
	c.JSON(http.StatusOK, user)
}

type UserOrganization struct {
	UserID         string    `json:"user_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
}

// DeleteUserFromOrganization removes a user from an organization
// @Summary      Remove a User from an Organization
// @Description  Deletes an existing organization associated to a user
// @Id			 DeleteUserFromOrganization
// @Tags         Users
// @Accepts		 json
// @Produce      json
// @Param        id             path      string  true "User ID"
// @Param        organization   path      string  true "Organization ID"
// @Success      204  {object}  models.User
// @Failure      400  {object}  models.BaseError
// @Failure      400  {object}  models.BaseError
// @Failure      500  {object}  models.BaseError
// @Router       /api/users/{id}/organizations/{organization} [delete]
func (api *API) DeleteUserFromOrganization(c *gin.Context) {
	ctx, span := tracer.Start(c.Request.Context(), "DeleteUser")
	defer span.End()
	userID := c.Param("id")

	if userID == "" {
		c.JSON(http.StatusBadRequest, models.NewBadPathParameterError("id"))
		return
	}

	orgID := c.Param("organization")
	if userID == "" {
		c.JSON(http.StatusBadRequest, models.NewBadPathParameterError("organization"))
		return
	}

	var user models.User
	var organization models.Organization
	err := api.transaction(ctx, func(tx *gorm.DB) error {
		if res := api.db.First(&user, "id = ?", userID); res.Error != nil {
			return errUserNotFound
		}
		if res := api.db.First(&organization, "id = ?", orgID); res.Error != nil {
			return errOrgNotFound
		}
		if res := api.db.
			Select(clause.Associations).
			Where("user_id = ?", userID).
			Where("organization_id = ?", orgID).
			Delete(&UserOrganization{}); res.Error != nil {
			c.JSON(http.StatusInternalServerError, models.NewApiInternalError(fmt.Errorf("failed to remove the association from the user_organizations table: %w", res.Error)))
		}
		return nil
	})

	if err != nil {
		if errors.Is(err, errUserNotFound) {
			c.JSON(http.StatusNotFound, models.NewNotFoundError("user"))
		}
		if errors.Is(err, errOrgNotFound) {
			c.JSON(http.StatusNotFound, models.NewNotFoundError("organization"))
		} else {
			c.JSON(http.StatusInternalServerError, models.NewApiInternalError(err))
		}
		return
	}

	c.JSON(http.StatusOK, user)
}
