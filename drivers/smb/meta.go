package smb

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	driver.RootPath
	Address          string `json:"address" required:"true"`
	Username         string `json:"username" required:"true"`
	Password         string `json:"password"`
	ShareName        string `json:"share_name" required:"true"`
	Thumbnail        bool   `json:"thumbnail" required:"false" help:"enable thumbnail" default:"false"`
	ThumbCacheFolder string `json:"thumb_cache_folder" help:"path to store thumbnail cache"`
	ThumbConcurrency string `json:"thumb_concurrency" default:"16" required:"false" help:"Number of concurrent thumbnail generation goroutines. This controls how many thumbnails can be generated in parallel."`
	VideoThumbPos    string `json:"video_thumb_pos" default:"20%" required:"false" help:"The position of the video thumbnail. If the value is a number (integer ot floating point), it represents the time in seconds. If the value ends with '%', it represents the percentage of the video duration."`
	RecycleBinPath   string `json:"recycle_bin_path" default:"delete permanently" help:"path to recycle bin, delete permanently if empty or keep 'delete permanently'"`
}

var config = driver.Config{
	Name:        "SMB",
	LocalSort:   true,
	OnlyProxy:   true,
	DefaultRoot: ".",
	NoCache:     true,
	NoLinkURL:   true,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &SMB{}
	})
}
