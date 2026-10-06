-- Admin
INSERT INTO Admin (email, password_hash) 
VALUES ('admin@org.com', 'admin123');

-- Test User (Status starts as 'pending')
INSERT INTO User (u_id,email, password_hash, role ,status) 
VALUES (1,'admin@org.com', 'admin123', 'admin', 'active'),
(2,'user1@test.com' , 'user1' , 'user' ,'active'),
(3,'user2@test.com' , 'user2' , 'user', 'pending');

-- Test File (Owned by User )permissionpermission
CREATE TABLE `permission` (
  `p_id` int NOT NULL AUTO_INCREMENT,
  `access_level` varchar(50) NOT NULL,
  `admin_id` int DEFAULT NULL,
  `user_id` int DEFAULT NULL,
  `file_id` int DEFAULT NULL,
  PRIMARY KEY (`p_id`),
  KEY `admin_id` (`admin_id`),
  KEY `user_id` (`user_id`),
  KEY `file_id` (`file_id`),
  CONSTRAINT `permission_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `admin` (`a_id`),
  CONSTRAINT `permission_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `user` (`u_id`),
  CONSTRAINT `permission_ibfk_3` FOREIGN KEY (`file_id`) REFERENCES `file` (`f_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE `Admin` (
  `a_id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  PRIMARY KEY (`a_id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE `audit_log` (
  `log_id` int NOT NULL AUTO_INCREMENT,
  `action_type` varchar(100) DEFAULT NULL,
  `action_timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `actor_id` int DEFAULT NULL,
  `actor_type` varchar(10) DEFAULT NULL,
  `detail` text,
  PRIMARY KEY (`log_id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO File (f_name, f_path, owner_id) VALUES 
('admin.pdf', '/uploads/report.pdf', 1), -- only admin can see it
('synopsis.pdf', '/uploads/synopsis.pdf', 2), -- only user1 can see it
('user2.pdf', '/uploads/synopsis.pdf', 2); -- only user2 can see it

