-- Safe query: No injection here
SELECT * FROM users WHERE id = 1;

-- Classic SQL Injection
SELECT * FROM users WHERE username = 'admin' AND password = 'password123';  -- Vulnerable

-- Union-Based SQL Injection
SELECT * FROM products WHERE id = 1 UNION SELECT username, password FROM users;  -- Vulnerable

-- Time-Based SQL Injection
SELECT * FROM users WHERE id = 1 AND IF(1=1, SLEEP(5), 0);  -- Vulnerable

-- Comment Injection
SELECT * FROM orders WHERE customer_id = '1' OR '1'='1';  -- Vulnerable

-- Blind SQL Injection
SELECT * FROM employees WHERE email = 'employee@example.com' AND EXISTS(SELECT * FROM users);  -- Vulnerable

-- Insert Statement Injection
INSERT INTO users (username, password) VALUES ('new_user', 'new_password');  -- Safe Query

-- Update Statement Injection
UPDATE products SET price = price * 1.1 WHERE category_id = 1;  -- Safe Query

-- Delete Statement Injection
DELETE FROM users WHERE username = 'admin' OR '1'='1';  -- Vulnerable

-- Drop Table Injection
DROP TABLE IF EXISTS users;  -- Vulnerable

-- Out-of-Band SQL Injection
SELECT * FROM users WHERE username = 'admin'; EXEC xp_cmdshell('ping example.com');  -- Vulnerable

-- Stored Procedure Example
EXEC get_user_info('admin');  -- Safe Query if properly parameterized

-- Incorrectly sanitized input leading to error-based SQL injection
SELECT * FROM products WHERE id = (SELECT id FROM products WHERE name = '' OR 1=1);  -- Vulnerable

-- Additional comment to demonstrate handling
-- SELECT * FROM users WHERE id = 1; -- Comment
