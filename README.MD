Bước 1: Đăng ký user
Request:

Method: POST

URL: http://localhost:3003/auth/register

Body (raw JSON):
{
  "username": "testuser1",
  "password": "password123"
}
![alt text](public/img/1.png)
ước 2: Đăng nhập để lấy token
Request:

Method: POST

URL: http://localhost:3003/auth/login

Body (raw JSON):
{
  "username": "testuser1",
  "password": "password123"
}
![alt text](public/img/2.png)
Lưu token này để dùng cho các request sau
Bước 3: Test dashboard (protected route)
Request:

Method: GET

URL: http://localhost:3003/auth/dashboard

Headers:

x-auth-token: [token từ bước 2]
![alt text](public/img/3.png)
Bước 4: Tạo product
Request:

Method: POST

URL: http://localhost:3003/products/api/products

Headers:

Authorization: Bearer [token từ bước 2]

Body (raw JSON):
{
  "name": "iPhone 19",
  "price": 999,
  "description": "Latest iPhone"
}
![alt text](public/img/4.png)
Bước 5: Lấy danh sách products
Request:

Method: GET

URL: http://localhost:3003/products/api/products
Headers:

Authorization: Bearer [token từ bước 2]
![alt text](public/img/5.png)
Bước 6: Mua hàng (tạo order)
Request:

Method: POST

URL: http://localhost:3003/products/api/products/buy

Headers:

Authorization: Bearer [token từ bước 2]

Body (raw JSON):
{
  "ids": ["product_id_1", "product_id_2"]
}
![alt text](public/img/6.png)