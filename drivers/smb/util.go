package smb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/singleflight"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/disintegration/imaging"
	ffmpeg "github.com/u2takey/ffmpeg-go"
	_ "golang.org/x/image/webp"

	"github.com/cloudsoda/go-smb2"
)

func (d *SMB) updateLastConnTime() {
	atomic.StoreInt64(&d.lastConnTime, time.Now().Unix())
}

func (d *SMB) cleanLastConnTime() {
	atomic.StoreInt64(&d.lastConnTime, 0)
}

func (d *SMB) getLastConnTime() time.Time {
	return time.Unix(atomic.LoadInt64(&d.lastConnTime), 0)
}

func (d *SMB) initFS(ctx context.Context) error {
	_, err, _ := singleflight.AnyGroup.Do(fmt.Sprintf("SMB.initFS:%p", d), func() (any, error) {
		return nil, d._initFS(ctx)
	})
	return err
}
func (d *SMB) _initFS(ctx context.Context) error {
	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     d.Username,
			Password: d.Password,
		},
	}
	s, err := dialer.Dial(ctx, d.Address)
	if err != nil {
		return err
	}
	d.fs, err = s.Mount(d.ShareName)
	if err != nil {
		return err
	}
	d.updateLastConnTime()
	return err
}

func (d *SMB) checkConn(ctx context.Context) error {
	if time.Since(d.getLastConnTime()) < 5*time.Minute {
		return nil
	}
	if d.fs != nil {
		_ = d.fs.Umount()
	}
	return d.initFS(ctx)
}

// CopyFile File copies a single file from src to dst
func (d *SMB) CopyFile(src, dst string) error {
	var err error
	var srcfd *smb2.File
	var dstfd *smb2.File
	var srcinfo fs.FileInfo

	if srcfd, err = d.fs.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = d.CreateNestedFile(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = utils.CopyWithBuffer(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = d.fs.Stat(src); err != nil {
		return err
	}
	return d.fs.Chmod(dst, srcinfo.Mode())
}

// CopyDir Dir copies a whole directory recursively
func (d *SMB) CopyDir(src string, dst string) error {
	var err error
	var fds []fs.FileInfo
	var srcinfo fs.FileInfo

	if srcinfo, err = d.fs.Stat(src); err != nil {
		return err
	}
	if err = d.fs.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}
	if fds, err = d.fs.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcfp := filepath.Join(src, fd.Name())
		dstfp := filepath.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = d.CopyDir(srcfp, dstfp); err != nil {
				return err
			}
		} else {
			if err = d.CopyFile(srcfp, dstfp); err != nil {
				return err
			}
		}
	}
	return nil
}

// Exists determine whether the file exists
func (d *SMB) Exists(name string) bool {
	if _, err := d.fs.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// CreateNestedFile create nested file
func (d *SMB) CreateNestedFile(path string) (*smb2.File, error) {
	basePath := filepath.Dir(path)
	if !d.Exists(basePath) {
		err := d.fs.MkdirAll(basePath, 0700)
		if err != nil {
			return nil, err
		}
	}
	return d.fs.Create(path)
}

// Get the snapshot of the video
func (d *SMB) GetSnapshot(videoPath string, tempFile string) (*bytes.Buffer, error) {
	// Run ffprobe to get the video duration
	jsonOutput, err := ffmpeg.Probe(tempFile)
	if err != nil {
		return nil, err
	}
	// get format.duration from the json string
	type probeFormat struct {
		Duration string `json:"duration"`
	}
	type probeData struct {
		Format probeFormat `json:"format"`
	}
	var probe probeData
	err = json.Unmarshal([]byte(jsonOutput), &probe)
	if err != nil {
		return nil, err
	}
	totalDuration, err := strconv.ParseFloat(probe.Format.Duration, 64)
	if err != nil {
		return nil, err
	}

	var ss string
	if d.videoThumbPosIsPercentage {
		ss = fmt.Sprintf("%f", totalDuration*d.videoThumbPos)
	} else {
		// If the value is greater than the total duration, use the total duration
		if d.videoThumbPos > totalDuration {
			ss = fmt.Sprintf("%f", totalDuration)
		} else {
			ss = fmt.Sprintf("%f", d.videoThumbPos)
		}
	}

	// Run ffmpeg to get the snapshot
	srcBuf := bytes.NewBuffer(nil)
	stream := ffmpeg.Input(tempFile, ffmpeg.KwArgs{"ss": ss, "noaccurate_seek": ""}).
		Output("pipe:", ffmpeg.KwArgs{"vframes": 1, "format": "image2", "vcodec": "mjpeg"}).
		GlobalArgs("-loglevel", "error").Silent(true).
		WithOutput(srcBuf, os.Stdout)
	if err = stream.Run(); err != nil {
		return nil, err
	}
	return srcBuf, nil
}

func (d *SMB) getThumb(file model.Obj) (*bytes.Buffer, *string, error) {
	fullPath := file.GetPath()
	thumbPrefix := "openlist_thumb_"
	thumbName := thumbPrefix + utils.GetMD5EncodeStr(fullPath) + ".png"
	if d.ThumbCacheFolder != "" {
		// skip if the file is a thumbnail
		if strings.HasPrefix(file.GetName(), thumbPrefix) {
			return nil, &fullPath, nil
		}
		thumbPath := filepath.Join(d.ThumbCacheFolder, thumbName)
		if utils.Exists(thumbPath) {
			return nil, &thumbPath, nil
		}
	}
	
	var srcBuf *bytes.Buffer
	fileType := utils.GetFileType(file.GetName())
	
	if fileType == conf.VIDEO {
		// For video files, we need to download to a temp file first
		tempFile := filepath.Join(os.TempDir(), "openlist_temp_"+utils.GetMD5EncodeStr(fullPath)+filepath.Ext(file.GetName()))
		defer os.Remove(tempFile)
		
		// Download the video file from SMB to temp
		remoteFile, err := d.fs.Open(fullPath)
		if err != nil {
			return nil, nil, err
		}
		defer remoteFile.Close()
		
		localFile, err := os.Create(tempFile)
		if err != nil {
			return nil, nil, err
		}
		
		_, err = io.Copy(localFile, remoteFile)
		localFile.Close()
		if err != nil {
			return nil, nil, err
		}
		
		videoBuf, err := d.GetSnapshot(fullPath, tempFile)
		if err != nil {
			return nil, nil, err
		}
		srcBuf = videoBuf
	} else {
		// For image files, read directly from SMB
		remoteFile, err := d.fs.Open(fullPath)
		if err != nil {
			return nil, nil, err
		}
		defer remoteFile.Close()
		
		imgData, err := io.ReadAll(remoteFile)
		if err != nil {
			return nil, nil, err
		}
		imgBuf := bytes.NewBuffer(imgData)
		srcBuf = imgBuf
	}

	image, err := imaging.Decode(srcBuf, imaging.AutoOrientation(true))
	if err != nil {
		return nil, nil, err
	}
	thumbImg := imaging.Resize(image, 144, 0, imaging.Lanczos)
	var buf bytes.Buffer
	err = imaging.Encode(&buf, thumbImg, imaging.PNG)
	if err != nil {
		return nil, nil, err
	}
	if d.ThumbCacheFolder != "" {
		err = os.WriteFile(filepath.Join(d.ThumbCacheFolder, thumbName), buf.Bytes(), 0666)
		if err != nil {
			return nil, nil, err
		}
	}
	return &buf, nil, nil
}

