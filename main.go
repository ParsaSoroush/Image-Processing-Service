package main

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"unique;not null" json:"username"`
	Password  string    `gorm:"not null" json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type ImageAsset struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint `gorm:"index"`
	Filename  string
	URL       string
	Width     int
	Height    int
	CreatedAt time.Time
}

var (
	db           *gorm.DB
	JwtSecretKey = []byte("SECRET_KEY")
	uploadDir    = "./uploads"
)

func generateTokenForUser(u *User, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  u.ID,
		"username": u.Username,
		"exp":      time.Now().Add(expiry).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecretKey)
}

func parseTokenString(tokenString string) (jwt.MapClaims, error) {
	if tokenString == "" {
		return nil, errors.New("❌🔑 no token provided")
	}
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("❌ unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("❌🔑 invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	exp := int64(claims["exp"].(float64))
	if time.Now().After(time.Unix(exp, 0)) {
		return nil, errors.New("❌📆 token expired")
	}

	return claims, nil
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := parseTokenString(c.GetHeader("Authorization"))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func userIDFromContext(c *gin.Context) (uint, error) {
	claims := c.MustGet("claims").(jwt.MapClaims)
	return uint(claims["user_id"].(float64)), nil
}

func Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "invalid input"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	user := User{Username: req.Username, Password: string(hash)}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": err.Error()})
		return
	}

	token, _ := generateTokenForUser(&user, time.Hour)

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user,
	})
}

func Login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	c.ShouldBindJSON(&req)

	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"❌error❌": "invalid credentials"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"❌error❌": "invalid credentials"})
		return
	}

	token, _ := generateTokenForUser(&user, time.Hour)
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func UploadImage(c *gin.Context) {
	userID, _ := userIDFromContext(c)

	file, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "image required"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "cannot open file"})
		return
	}
	defer src.Close()

	img, format, err := image.Decode(src)
	if err != nil || (format != "jpeg" && format != "png") {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "only jpeg or png allowed"})
		return
	}

	img = imaging.Fit(img, 1024, 1024, imaging.Lanczos)

	filename := uuid.New().String() + ".jpg"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Fatal(err)
	}

	savePath := filepath.Join(uploadDir, filename)
	if err := imaging.Save(img, savePath, imaging.JPEGQuality(85)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"❌error❌": "failed to save image"})
		return
	}

	w := img.Bounds().Dx()
	h := img.Bounds().Dy()

	imageURL := "/uploads/" + filename

	record := ImageAsset{
		UserID:   userID,
		Filename: filename,
		URL:      imageURL,
		Width:    w,
		Height:   h,
	}

	db.Create(&record)

	c.JSON(http.StatusOK, gin.H{
		"id":       record.ID,
		"url":      record.URL,
		"width":    w,
		"height":   h,
		"format":   "jpeg",
		"uploaded": record.CreatedAt,
	})
}

func GetImages(c *gin.Context) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if err != nil || limit < 1 {
		limit = 10
	}

	offset := (page - 1) * limit

	rows, err := db.Raw(
		`SELECT id, user_id, filename, url, width, height, created_at
		 FROM image_assets
		 LIMIT ? OFFSET ?`,
		limit, offset,
	).Rows()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"❌error❌": "failed to fetch images"})
		return
	}
	defer rows.Close()

	images := []gin.H{}

	for rows.Next() {
		var (
			id        uint
			userID    uint
			filename  string
			url       string
			width     int
			height    int
			createdAt time.Time
		)

		if err := rows.Scan(
			&id,
			&userID,
			&filename,
			&url,
			&width,
			&height,
			&createdAt,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"❌error❌": "failed to read images"})
			return
		}

		images = append(images, gin.H{
			"id":         id,
			"user_id":    userID,
			"filename":   filename,
			"url":        url,
			"width":      width,
			"height":     height,
			"created_at": createdAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"page":   page,
		"limit":  limit,
		"images": images,
	})
}

func TransformImage(c *gin.Context) {
	userID, _ := userIDFromContext(c)

	imageID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "invalid image id"})
		return
	}

	var asset ImageAsset
	if err := db.Where("id = ? AND user_id = ?", imageID, userID).
		First(&asset).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"❌error❌": "image not found"})
		return
	}

	var req struct {
		Transformations struct {
			Resize *struct {
				Width  int `json:"width"`
				Height int `json:"height"`
			} `json:"resize,omitempty"`

			Crop *struct {
				Width  int `json:"width"`
				Height int `json:"height"`
			} `json:"crop,omitempty"`

			Watermark *struct {
				ImageID uint    `json:"image_id"`
				X       int     `json:"x"`
				Y       int     `json:"y"`
				Width   int     `json:"width,omitempty"`
				Height  int     `json:"height,omitempty"`
				Opacity float64 `json:"opacity,omitempty"`
			} `json:"watermark,omitempty"`

			Rotate *float64 `json:"rotate,omitempty"`
			Mirror *string  `json:"mirror,omitempty"`
			Format *string  `json:"format,omitempty"`

			Filters *struct {
				Grayscale bool `json:"grayscale"`
				Sepia     bool `json:"sepia"`
			} `json:"filters,omitempty"`
		} `json:"transformations"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "invalid request body"})
		return
	}

	if req.Transformations.Resize == nil &&
		req.Transformations.Rotate == nil &&
		req.Transformations.Crop == nil &&
		req.Transformations.Watermark == nil &&
		req.Transformations.Mirror == nil &&
		req.Transformations.Format == nil &&
		req.Transformations.Filters == nil {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "no transformations provided"})
		return
	}

	srcPath := filepath.Join(uploadDir, asset.Filename)

	img, err := imaging.Open(srcPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"❌error❌": "failed to open image"})
		return
	}

	/* ---------------- Resize ---------------- */
	if r := req.Transformations.Resize; r != nil {
		if r.Width <= 0 || r.Height <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "width and height must be positive"})
			return
		}
		img = imaging.Resize(img, r.Width, r.Height, imaging.Lanczos)
	}

	/* ---------------- Rotate ---------------- */
	if deg := req.Transformations.Rotate; deg != nil {
		if *deg == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "rotate degrees must be non-zero"})
			return
		}
		img = imaging.Rotate(img, *deg, image.Transparent)
	}

	/* ---------------- Crop ---------------- */
	if crop := req.Transformations.Crop; crop != nil {
		if crop.Width <= 0 || crop.Height <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "crop width and height must be positive"})
			return
		}

		b := img.Bounds()
		if crop.Width > b.Dx() || crop.Height > b.Dy() {
			c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "crop size exceeds image dimensions"})
			return
		}

		img = imaging.CropCenter(img, crop.Width, crop.Height)
	}

	/* ---------------- Mirror ---------------- */
	if m := req.Transformations.Mirror; m != nil {
		switch strings.ToLower(*m) {
		case "horizontal":
			img = imaging.FlipH(img)
		case "vertical":
			img = imaging.FlipV(img)
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"❌error❌": "mirror must be 'horizontal' or 'vertical'",
			})
			return
		}
	}

	/* ---------------- Filters ---------------- */
	if f := req.Transformations.Filters; f != nil {
		if f.Grayscale {
			img = imaging.Grayscale(img)
		}

		if f.Sepia {
			img = imaging.AdjustFunc(img, func(c color.NRGBA) color.NRGBA {
				r := float64(c.R)
				g := float64(c.G)
				b := float64(c.B)

				tr := 0.393*r + 0.769*g + 0.189*b
				tg := 0.349*r + 0.686*g + 0.168*b
				tb := 0.272*r + 0.534*g + 0.131*b

				c.R = uint8(min(tr, 255))
				c.G = uint8(min(tg, 255))
				c.B = uint8(min(tb, 255))

				return c
			})
		}
	}

	/* ---------------- Watermark ---------------- */
	if w := req.Transformations.Watermark; w != nil {
		var wmAsset ImageAsset
		if err := db.Where("id = ? AND user_id = ?", w.ImageID, userID).
			First(&wmAsset).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "watermark image not found"})
			return
		}

		wmImg, err := imaging.Open(filepath.Join(uploadDir, wmAsset.Filename))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"❌error❌": "cannot open watermark"})
			return
		}

		if w.Width > 0 && w.Height > 0 {
			wmImg = imaging.Resize(wmImg, w.Width, w.Height, imaging.Lanczos)
		}

		opacity := 1.0
		if w.Opacity > 0 && w.Opacity <= 1 {
			opacity = w.Opacity
		}

		img = imaging.Overlay(img, wmImg, image.Pt(w.X, w.Y), opacity)
	}

	/* ---------------- Format ---------------- */
	outputFormat := "jpeg"
	if f := req.Transformations.Format; f != nil {
		switch strings.ToLower(*f) {
		case "jpeg", "jpg":
			outputFormat = "jpeg"
		case "png":
			outputFormat = "png"
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"❌error❌": "format must be jpeg/jpg or png",
			})
			return
		}
	}

	newFilename := uuid.New().String() + "." + outputFormat
	newPath := filepath.Join(uploadDir, newFilename)

	switch outputFormat {
	case "jpeg":
		err = imaging.Save(img, newPath, imaging.JPEGQuality(85))
	case "png":
		err = imaging.Save(img, newPath)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"❌error❌": "failed to save image"})
		return
	}

	record := ImageAsset{
		UserID:   userID,
		Filename: newFilename,
		URL:      "/uploads/" + newFilename,
		Width:    img.Bounds().Dx(),
		Height:   img.Bounds().Dy(),
	}

	db.Create(&record)

	c.JSON(http.StatusOK, gin.H{
		"id":     record.ID,
		"url":    record.URL,
		"width":  record.Width,
		"height": record.Height,
		"format": outputFormat,
	})
}

func GetImageWithDetails(c *gin.Context) {
	userID, _ := userIDFromContext(c)

	imageID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"❌error❌": "invalid image id"})
		return
	}

	var asset ImageAsset
	if err := db.
		Where("id = ? AND user_id = ?", imageID, userID).
		First(&asset).Error; err != nil {

		c.JSON(http.StatusNotFound, gin.H{"❌error❌": "image not found"})
		return
	}

	imagePath := filepath.Join(uploadDir, asset.Filename)

	if _, err := os.Stat(imagePath); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"❌error❌": "image file missing"})
		return
	}

	ext := strings.ToLower(filepath.Ext(asset.Filename))
	contentType := "image/jpeg"
	if ext == ".png" {
		contentType = "image/png"
	}

	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, asset.Filename))
	c.Header("Last-Modified", asset.CreatedAt.UTC().Format(http.TimeFormat))

	c.Header("X-Image-ID", fmt.Sprint(asset.ID))
	c.Header("X-User-ID", fmt.Sprint(asset.UserID))
	c.Header("X-Image-Width", fmt.Sprint(asset.Width))
	c.Header("X-Image-Height", fmt.Sprint(asset.Height))
	c.Header("X-Image-URL", asset.URL)

	c.File(imagePath)
}


func connectDB() {
	dsn := "image_processing_user:Image_Processing_Password$1234@tcp(localhost:3306)/image_processing_db?parseTime=true"
	database, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	db = database
	db.AutoMigrate(&User{}, &ImageAsset{})
}

func main() {
	connectDB()

	r := gin.Default()
	r.Static("/uploads", uploadDir)

	r.POST("/register", Register)
	r.POST("/login", Login)

	auth := r.Group("/")
	auth.Use(AuthRequired())
	auth.POST("/images", UploadImage)
	auth.GET("/images", GetImages)
	auth.POST("images/:id/transform", TransformImage)
	auth.GET("/images/:id", GetImageWithDetails)

	log.Println("✅Server running on :8080🚀")
	r.Run(":8080")
}
