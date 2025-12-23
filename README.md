# 🖼️ Image Processing Service
---
A simple RESTful API that allows users to SignUp, SingIn, Add Images, manage them and Apply Transformations.

🔗 [Project URL](https://roadmap.sh/projects/expense-tracker-api)

## 🛠️ Tech Stack
- Go
- Gin
- GORM
- MySQL
- JWT
---

## ⭐ Features
- 🔑Register
    - Using an uniqe **username** and **password**
- 🔒Login
    - Using the **usernmae** and **password** of the User
- ➕Adding Image
    - Uisng the `MultiPart form` and the `image` key
- 📂Get All Images
    - We will just use the `JWT` and it will show all images that is related to the User
- ✨Transform Imege
    - 🖌️This is all Transformation
        1. 📏Resize
            - We use `width` and `height` for resizing an Image
        2. ✂️Crop
            - We user `width` and `height` for crop an Image
        3. 🔄Rotate
            - We use a number for rotate that degres like `180` we will rotate it `180` degres
        4. 🔧Foemat
            - We just take three options, `png`, `jpg` and `jpeg`
        5. 🔍Filter
            We have two options, `grayscale` and `sepia` that both of them takje `boolean`
---

## 🔧Installation
### 1️⃣ Cloen the Repository
```bash
git clone https://github.com/ParsaSoroush/Image-Processing-Service.git
cd Image-Processing-Service
```

### 2️⃣ Install dependencies
```bash
go mod tidy
```

### 3️⃣ Run the Server
```bash
go run main.go
```

## 🔑Main Endpoints

| Method | Endpoint           | Description                         |
| ------ | ------------------ | ----------------------------------- |
| POST   | `/register`        | Register + receive JWT token        |
| POST   | `/login`           | Login + receive JWT token           |
| POST   | `/images`          | Adding a new Image                  |
| GET    | `/images`          | Get All images                      |
| POST   | `/image/:id`       | Add Transformations to Image        |
| GET    | `/images/:id`      | Get Detailof an Image               |