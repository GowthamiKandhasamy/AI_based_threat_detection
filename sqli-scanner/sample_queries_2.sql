-- Sample SQL Injection and safe queries
SELECT * FROM users WHERE username = 'admin' AND password = 'password'; -- Vulnerable
SELECT * FROM products WHERE price < 100; -- Safe Query
SELECT * FROM orders WHERE order_id = '1' UNION SELECT username, password FROM users; -- Vulnerable
INSERT INTO orders (user_id, product_id) VALUES (1, 2); -- Safe Query
DELETE FROM products WHERE product_id = '3'; -- Vulnerable
SELECT * FROM employees WHERE employee_id = '1' OR '1'='1'; -- Vulnerable
SELECT * FROM customers WHERE name = 'John Doe' AND email = 'johndoe@example.com'; -- Safe Query
EXEC xp_cmdshell('net user'); -- Vulnerable
SELECT * FROM products WHERE category = (SELECT category FROM categories WHERE name = 'Electronics'); -- Safe Query
SELECT * FROM sessions WHERE session_id = 'abc123'; -- Safe Query

SELECT * FROM accounts WHERE username = '' OR '1'='1'; -- Vulnerable
SELECT * FROM transactions WHERE user_id = '42'; -- Safe Query
SELECT * FROM users WHERE email = 'admin@example.com' -- Comment-based SQL Injection
SELECT * FROM orders WHERE order_id = '1' AND '1'='1'; -- Vulnerable
DROP TABLE IF EXISTS temp_table; -- Vulnerable
SELECT * FROM logs WHERE timestamp > '2023-01-01' UNION SELECT * FROM users; -- Vulnerable
SELECT * FROM products WHERE name LIKE '%widget%'; -- Safe Query
SELECT * FROM employees WHERE employee_id = '1'; -- Safe Query
UPDATE accounts SET balance = balance + 100 WHERE account_id = '123'; -- Safe Query
SELECT COUNT(*) FROM products WHERE price > 50; -- Safe Query
SELECT * FROM users WHERE username = 'admin' AND password = 'anything' OR 'x'='x'; -- Vulnerable

SELECT * FROM books WHERE author = 'Jane Austen' AND published_year = '1811'; -- Safe Query
SELECT * FROM students WHERE student_id = '1' AND '1'='1'; -- Vulnerable
DELETE FROM logs WHERE log_id = '2' OR 1=1; -- Vulnerable
UPDATE users SET last_login = NOW() WHERE username = 'admin'; -- Safe Query
SELECT * FROM transactions WHERE user_id = '42'; -- Safe Query
SELECT * FROM accounts WHERE username = 'admin' AND password = 'anything' OR 'x'='x'; -- Vulnerable
SELECT * FROM products WHERE name = 'example' AND price < 20; -- Safe Query
SELECT * FROM users WHERE username = '' OR 1=1; -- Vulnerable
SELECT * FROM products WHERE id = '5'; -- Safe Query
SELECT * FROM customers WHERE id = 1 OR '1'='1'; -- Vulnerable
SELECT * FROM logs WHERE log_id = '1'; -- Safe Query

SELECT * FROM orders WHERE product_id = (SELECT id FROM products WHERE name = 'Widget'); -- Safe Query
INSERT INTO users (username, password) VALUES ('newuser', 'newpassword'); -- Safe Query
SELECT * FROM employees WHERE employee_id = '1' AND 1=1; -- Vulnerable
SELECT * FROM logs WHERE log_id = '' OR 'x'='x'; -- Vulnerable
SELECT name FROM users WHERE email = 'test@example.com'; -- Safe Query
UPDATE products SET price = price * 1.1; -- Safe Query
SELECT * FROM categories WHERE name = 'Electronics'; -- Safe Query
SELECT * FROM students WHERE student_id = '1' OR 1=1; -- Vulnerable
SELECT * FROM users WHERE id IN (SELECT user_id FROM orders); -- Safe Query
INSERT INTO orders (user_id, product_id) VALUES ('1', '2'); -- Safe Query
DROP TABLE IF EXISTS users; -- Vulnerable
