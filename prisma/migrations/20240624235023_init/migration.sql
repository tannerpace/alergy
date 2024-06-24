-- CreateTable
CREATE TABLE `User` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `email` VARCHAR(191) NOT NULL,
    `first_name` VARCHAR(191) NULL,
    `last_name` VARCHAR(191) NULL,
    `user_name` VARCHAR(191) NULL,
    `password` VARCHAR(191) NULL,
    `token` VARCHAR(191) NULL,
    `refresh_token` VARCHAR(191) NULL,
    `last_login` DATETIME(3) NULL,
    `salt` VARCHAR(191) NULL,
    `role` ENUM('GUEST', 'USER', 'ADMIN', 'SUPERADMIN', 'API_USER') NOT NULL DEFAULT 'USER',

    UNIQUE INDEX `User_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
