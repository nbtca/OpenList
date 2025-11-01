package fs

import (
	"context"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// List files
func list(ctx context.Context, path string, args *ListArgs) ([]model.Obj, error) {
	// Check ACL permission for listing
	if _, err := op.CheckACLPermission(ctx, path, model.ACLPermRead); err != nil {
		return nil, err
	}

	meta, _ := ctx.Value(conf.MetaKey).(*model.Meta)
	user, _ := ctx.Value(conf.UserKey).(*model.User)
	virtualFiles := op.GetStorageVirtualFilesWithDetailsByPath(ctx, path, !args.WithStorageDetails, args.Refresh)
	storage, actualPath, err := op.GetStorageAndActualPath(path)
	if err != nil && len(virtualFiles) == 0 {
		return nil, errors.WithMessage(err, "failed get storage")
	}

	var _objs []model.Obj
	if storage != nil {
		_objs, err = op.List(ctx, storage, actualPath, model.ListArgs{
			ReqPath:            path,
			Refresh:            args.Refresh,
			WithStorageDetails: args.WithStorageDetails,
		})
		if err != nil {
			if !args.NoLog {
				log.Errorf("fs/list: %+v", err)
			}
			if len(virtualFiles) == 0 {
				return nil, errors.WithMessage(err, "failed get objs")
			}
		}
	}

	om := model.NewObjMerge()
	if whetherHide(user, meta, path) {
		om.InitHideReg(meta.Hide)
	}
	objs := om.Merge(_objs, virtualFiles...)

	// Filter objects based on ACL permissions
	filteredObjs := filterObjsByACL(ctx, objs, path)
	return filteredObjs, nil
}

// filterObjsByACL filters objects based on ACL permissions
func filterObjsByACL(ctx context.Context, objs []model.Obj, parentPath string) []model.Obj {
	user, _ := ctx.Value(conf.UserKey).(*model.User)

	// Admin users bypass ACL filtering
	if user != nil && user.IsAdmin() {
		return objs
	}

	filteredObjs := make([]model.Obj, 0, len(objs))
	for _, obj := range objs {
		objPath := utils.FixAndCleanPath(parentPath + "/" + obj.GetName())

		// Check read permission for each object
		if obj.IsDir() {
			// For directories, check list permission
			if _, err := op.CheckACLPermission(ctx, objPath, model.ACLPermRead); err == nil {
				filteredObjs = append(filteredObjs, obj)
			}
		} else {
			// For files, check read permission
			if _, err := op.CheckACLPermission(ctx, objPath, model.ACLPermRead); err == nil {
				filteredObjs = append(filteredObjs, obj)
			}
		}
	}
	return filteredObjs
}

func whetherHide(user *model.User, meta *model.Meta, path string) bool {
	// if is admin, don't hide
	if user == nil || user.CanSeeHides() {
		return false
	}
	// if meta is nil, don't hide
	if meta == nil {
		return false
	}
	// if meta.Hide is empty, don't hide
	if meta.Hide == "" {
		return false
	}
	// if meta doesn't apply to sub_folder, don't hide
	if !utils.PathEqual(meta.Path, path) && !meta.HSub {
		return false
	}
	// if is guest, hide
	return true
}
