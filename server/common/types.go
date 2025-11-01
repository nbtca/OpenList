package common

// IDReq represents a request with an ID parameter
type IDReq struct {
	ID uint `json:"id" form:"id" binding:"required"`
}
