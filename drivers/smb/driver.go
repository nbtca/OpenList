package smb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"

	"github.com/cloudsoda/go-smb2"
)

type SMB struct {
	lastConnTime int64
	model.Storage
	Addition
	fs *smb2.Share
	
	// thumbnail support
	thumbConcurrency      int
	thumbTokenBucket      TokenBucket
	videoThumbPos         float64
	videoThumbPosIsPercentage bool
}

func (d *SMB) Config() driver.Config {
	return config
}

func (d *SMB) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *SMB) Init(ctx context.Context) error {
	if !strings.Contains(d.Addition.Address, ":") {
		d.Addition.Address = d.Addition.Address + ":445"
	}
	
	// Initialize thumbnail settings
	if d.ThumbCacheFolder != "" && !utils.Exists(d.ThumbCacheFolder) {
		err := os.MkdirAll(d.ThumbCacheFolder, 0755)
		if err != nil {
			return err
		}
	}
	if d.ThumbConcurrency != "" {
		v, err := strconv.ParseUint(d.ThumbConcurrency, 10, 32)
		if err != nil {
			return err
		}
		d.thumbConcurrency = int(v)
	}
	if d.thumbConcurrency == 0 {
		d.thumbTokenBucket = NewNopTokenBucket()
	} else {
		d.thumbTokenBucket = NewStaticTokenBucketWithMigration(d.thumbTokenBucket, d.thumbConcurrency)
	}
	
	// Check the VideoThumbPos value
	if d.VideoThumbPos == "" {
		d.VideoThumbPos = "20%"
	}
	if strings.HasSuffix(d.VideoThumbPos, "%") {
		percentage := strings.TrimSuffix(d.VideoThumbPos, "%")
		val, err := strconv.ParseFloat(percentage, 64)
		if err != nil {
			return fmt.Errorf("invalid video_thumb_pos value: %s, err: %s", d.VideoThumbPos, err)
		}
		if val < 0 || val > 100 {
			return fmt.Errorf("invalid video_thumb_pos value: %s, the percentage must be a number between 0 and 100", d.VideoThumbPos)
		}
		d.videoThumbPosIsPercentage = true
		d.videoThumbPos = val / 100
	} else {
		val, err := strconv.ParseFloat(d.VideoThumbPos, 64)
		if err != nil {
			return fmt.Errorf("invalid video_thumb_pos value: %s, err: %s", d.VideoThumbPos, err)
		}
		if val < 0 {
			return fmt.Errorf("invalid video_thumb_pos value: %s, the time must be a positive number", d.VideoThumbPos)
		}
		d.videoThumbPosIsPercentage = false
		d.videoThumbPos = val
	}
	
	return d._initFS(ctx)
}

func (d *SMB) Drop(ctx context.Context) error {
	if d.fs != nil {
		_ = d.fs.Umount()
	}
	return nil
}

func (d *SMB) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	if err := d.checkConn(ctx); err != nil {
		return nil, err
	}
	fullPath := dir.GetPath()
	rawFiles, err := d.fs.ReadDir(fullPath)
	if err != nil {
		d.cleanLastConnTime()
		return nil, err
	}
	d.updateLastConnTime()
	var files []model.Obj
	for _, f := range rawFiles {
		file := model.ObjThumb{
			Object: model.Object{
				Name:     f.Name(),
				Modified: f.ModTime(),
				Size:     f.Size(),
				IsFolder: f.IsDir(),
				Ctime:    f.(*smb2.FileStat).CreationTime,
			},
		}
		files = append(files, &file)
	}
	return files, nil
}

func (d *SMB) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if err := d.checkConn(ctx); err != nil {
		return nil, err
	}
	
	link := &model.Link{}
	var MFile model.File
	
	// Handle thumbnail requests
	if args.Type == "thumb" && d.Thumbnail && utils.Ext(file.GetName()) != "svg" {
		var buf *bytes.Buffer
		var thumbPath *string
		err := d.thumbTokenBucket.Do(ctx, func() error {
			var err error
			buf, thumbPath, err = d.getThumb(file)
			return err
		})
		if err != nil {
			return nil, err
		}
		link.Header = http.Header{
			"Content-Type": []string{"image/png"},
		}
		if thumbPath != nil {
			open, err := os.Open(*thumbPath)
			if err != nil {
				return nil, err
			}
			stat, err := open.Stat()
			if err != nil {
				open.Close()
				return nil, err
			}
			link.ContentLength = int64(stat.Size())
			MFile = open
		} else {
			MFile = bytes.NewReader(buf.Bytes())
			link.ContentLength = int64(buf.Len())
		}
		link.SyncClosers.AddIfCloser(MFile)
		link.RangeReader = stream.GetRangeReaderFromMFile(link.ContentLength, MFile)
		link.RequireReference = link.SyncClosers.Length() > 0
		return link, nil
	}
	
	fullPath := file.GetPath()
	remoteFile, err := d.fs.Open(fullPath)
	if err != nil {
		d.cleanLastConnTime()
		return nil, err
	}
	d.updateLastConnTime()
	mFile := &stream.RateLimitFile{
		File:    remoteFile,
		Limiter: stream.ServerDownloadLimit,
		Ctx:     ctx,
	}
	return &model.Link{
		RangeReader:      stream.GetRangeReaderFromMFile(file.GetSize(), mFile),
		SyncClosers:      utils.NewSyncClosers(remoteFile),
		RequireReference: true,
	}, nil
}

func (d *SMB) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	if err := d.checkConn(ctx); err != nil {
		return err
	}
	fullPath := filepath.Join(parentDir.GetPath(), dirName)
	err := d.fs.MkdirAll(fullPath, 0700)
	if err != nil {
		d.cleanLastConnTime()
		return err
	}
	d.updateLastConnTime()
	return nil
}

func (d *SMB) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	if err := d.checkConn(ctx); err != nil {
		return err
	}
	srcPath := srcObj.GetPath()
	dstPath := filepath.Join(dstDir.GetPath(), srcObj.GetName())
	err := d.fs.Rename(srcPath, dstPath)
	if err != nil {
		d.cleanLastConnTime()
		return err
	}
	d.updateLastConnTime()
	return nil
}

func (d *SMB) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	if err := d.checkConn(ctx); err != nil {
		return err
	}
	srcPath := srcObj.GetPath()
	dstPath := filepath.Join(filepath.Dir(srcPath), newName)
	err := d.fs.Rename(srcPath, dstPath)
	if err != nil {
		d.cleanLastConnTime()
		return err
	}
	d.updateLastConnTime()
	return nil
}

func (d *SMB) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	if err := d.checkConn(ctx); err != nil {
		return err
	}
	srcPath := srcObj.GetPath()
	dstPath := filepath.Join(dstDir.GetPath(), srcObj.GetName())
	var err error
	if srcObj.IsDir() {
		err = d.CopyDir(srcPath, dstPath)
	} else {
		err = d.CopyFile(srcPath, dstPath)
	}
	if err != nil {
		d.cleanLastConnTime()
		return err
	}
	d.updateLastConnTime()
	return nil
}

func (d *SMB) Remove(ctx context.Context, obj model.Obj) error {
	if err := d.checkConn(ctx); err != nil {
		return err
	}
	var err error
	fullPath := obj.GetPath()
	
	// Handle recycle bin
	if !utils.SliceContains([]string{"", "delete permanently"}, d.RecycleBinPath) {
		objName := obj.GetName()
		var relPath string
		relPath, err = filepath.Rel(d.RootFolderPath, filepath.Dir(fullPath))
		if err != nil {
			return err
		}
		recycleBinPath := filepath.Join(d.RecycleBinPath, relPath)
		
		// Create recycle bin directory if it doesn't exist
		if !utils.Exists(recycleBinPath) {
			err = os.MkdirAll(recycleBinPath, 0755)
			if err != nil {
				return err
			}
		}
		
		dstPath := filepath.Join(recycleBinPath, objName)
		if utils.Exists(dstPath) {
			dstPath = filepath.Join(recycleBinPath, objName+"_"+time.Now().Format("20060102150405"))
		}
		
		// Move to recycle bin
		err = d.fs.Rename(fullPath, dstPath)
	} else {
		// Delete permanently
		if obj.IsDir() {
			err = d.fs.RemoveAll(fullPath)
		} else {
			err = d.fs.Remove(fullPath)
		}
	}
	
	if err != nil {
		d.cleanLastConnTime()
		return err
	}
	d.updateLastConnTime()
	return nil
}

func (d *SMB) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	if err := d.checkConn(ctx); err != nil {
		return err
	}
	fullPath := filepath.Join(dstDir.GetPath(), stream.GetName())
	out, err := d.fs.Create(fullPath)
	if err != nil {
		d.cleanLastConnTime()
		return err
	}
	d.updateLastConnTime()
	defer func() {
		_ = out.Close()
		if errors.Is(err, context.Canceled) {
			_ = d.fs.Remove(fullPath)
		}
	}()
	err = utils.CopyWithCtx(ctx, out, driver.NewLimitedUploadStream(ctx, stream), stream.GetSize(), up)
	if err != nil {
		return err
	}
	return nil
}

func (d *SMB) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	if err := d.checkConn(ctx); err != nil {
		return nil, err
	}
	stat, err := d.fs.Statfs(d.RootFolderPath)
	if err != nil {
		return nil, err
	}
	return &model.StorageDetails{
		DiskUsage: model.DiskUsage{
			TotalSpace: stat.BlockSize() * stat.TotalBlockCount(),
			FreeSpace:  stat.BlockSize() * stat.AvailableBlockCount(),
		},
	}, nil
}

//func (d *SMB) Other(ctx context.Context, args model.OtherArgs) (interface{}, error) {
//	return nil, errs.NotSupport
//}

var _ driver.Driver = (*SMB)(nil)
