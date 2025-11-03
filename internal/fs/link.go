package fs

import (
	"context"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/pkg/errors"
)

func link(ctx context.Context, path string, args model.LinkArgs) (*model.Link, model.Obj, error) {
	// Check ACL permission for download
	// if _, err := op.CheckACLPermission(ctx, path, model.ACLPermDownload); err != nil {
	// 	return nil, nil, err
	// }

	storage, actualPath, err := op.GetStorageAndActualPath(path)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed get storage")
	}
	l, obj, err := op.Link(ctx, storage, actualPath, args)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed link")
	}
	if l.URL != "" && !strings.HasPrefix(l.URL, "http://") && !strings.HasPrefix(l.URL, "https://") {
		l.URL = common.GetApiUrl(ctx) + l.URL
	}
	return l, obj, nil
}
