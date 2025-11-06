## Thông tin Sinh viên

* **Họ và tên:** Phạm Lê Gia Bảo
* **Mã số sinh viên:** 2374802010045

---

## 1. Giới thiệu Dự án

Đây là một ứng dụng web blog được xây dựng bằng Python và framework Flask. Ứng dụng mô phỏng các tính năng của một mạng xã hội blog cơ bản, bao gồm các chức năng cốt lõi:

* Xác thực người dùng (Đăng ký, Đăng nhập, Đăng xuất, Xác thực Email).
* Quản lý hồ sơ người dùng (Profile).
* Hệ thống bài đăng (CRUD - Tạo, Xem, Sửa).
* Định dạng bài đăng bằng Markdown (Rich Text).
* Hệ thống bình luận (Comment) trên các bài đăng.
* Hệ thống "Follow" (Theo dõi) người dùng khác.
* Lọc bài đăng trên trang chủ (Tất cả bài đăng / Bài đăng của người đang theo dõi).
* Hệ thống phân quyền (User, Moderator, Administrator).
* Chức năng kiểm duyệt: Chủ bài viết (hoặc Admin) có thể ẩn/hiện bình luận.

## 2. Công nghệ sử dụng

* **Backend:** Python 3, Flask
* **Database:** MySQL (Sử dụng Flask-SQLAlchemy)
* **Quản lý DB:** Flask-Migrate
* **Xác thực:** Flask-Login, Flask-Mail (gửi email), itsdangerous (tạo token)
* **Frontend:** Flask-Bootstrap
* **Rich Text:** Flask-PageDown, Markdown, Bleach (lọc XSS)
* **Hiển thị thời gian:** Flask-Moment

---

## 3. Hướng dẫn Cài đặt và Chạy ứng dụng

### ⚠️ Yêu cầu trước khi cài đặt
1.Yêu cầu tạo database trước khi chạy code
CREATE DATABASE flasky_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
2.Chạy file requirement 

pip install -r requirements.txt


