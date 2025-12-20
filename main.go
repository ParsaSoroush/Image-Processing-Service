package main

import (
	"errors"
	"fmt"
	"image"
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
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"index"`
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
		return nil, errors.New("no token provided")
	}
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	exp := int64(claims["exp"].(float64))
	if time.Now().After(time.Unix(exp, 0)) {
		return nil, errors.New("token expired")
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	user := User{Username: req.Username, Password: string(hash)}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, _ := generateTokenForUser(&user, time.Hour)
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func UploadImage(c *gin.Context) {
	userID, _ := userIDFromContext(c)

	file, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "image required"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot open file"})
		return
	}
	defer src.Close()

	img, format, err := image.Decode(src)
	if err != nil || (format != "jpeg" && format != "png") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only jpeg or png allowed"})
		return
	}

	img = imaging.Fit(img, 1024, 1024, imaging.Lanczos)

	filename := uuid.New().String() + ".jpg"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Fatal(err)
	}

	savePath := filepath.Join(uploadDir, filename)
	if err := imaging.Save(img, savePath, imaging.JPEGQuality(85)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save image"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch images"})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read images"})
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

func ResizeImage(c *gin.Context) {
	userID, _ := userIDFromContext(c)

	imageID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid image id"})
		return
	}

	var asset ImageAsset
	if err := db.Where("id = ? AND user_id = ?", imageID, userID).First(&asset).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "image not found"})
		return
	}

	var req struct {
		Transformations struct {
			Resize struct {
				Width  int `json:"width"`
				Height int `json:"height"`
			} `json:"resize"`
		} `json:"transformations"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.Transformations.Resize.Width <= 0 || req.Transformations.Resize.Height <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "width and height must be positive"})
		return
	}

	srcPath := filepath.Join(uploadDir, asset.Filename)

	img, err := imaging.Open(srcPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open image"})
		return
	}

	resized := imaging.Resize(
		img,
		req.Transformations.Resize.Width,
		req.Transformations.Resize.Height,
		imaging.Lanczos,
	)

	newFilename := uuid.New().String() + ".jpg"
	newPath := filepath.Join(uploadDir, newFilename)

	if err := imaging.Save(resized, newPath, imaging.JPEGQuality(85)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save image"})
		return
	}

	record := ImageAsset{
		UserID:   userID,
		Filename: newFilename,
		URL:      "/uploads/" + newFilename,
		Width:    resized.Bounds().Dx(),
		Height:   resized.Bounds().Dy(),
	}

	db.Create(&record)

	c.JSON(http.StatusOK, gin.H{
		"id":     record.ID,
		"url":    record.URL,
		"width":  record.Width,
		"height": record.Height,
	})
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
	auth.POST("images/:id/transform", ResizeImage)

	log.Println("✅Server running on :8080🚀")
	r.Run(":8080")
}
