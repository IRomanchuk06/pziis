-- Лабораторная работа 8: тестовая БД company
-- employees  - таблица с колонками разной чувствительности:
--              id, name (публичные), salary (конфиденциальная),
--              passport_no (строго конфиденциальная)
-- audit_log  - журнал действий

CREATE DATABASE IF NOT EXISTS company CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE company;

CREATE TABLE IF NOT EXISTS employees (
    id          INT           NOT NULL AUTO_INCREMENT,
    name        VARCHAR(100)  NOT NULL,
    salary      DECIMAL(10,2) NOT NULL,
    passport_no VARCHAR(20)   NULL,
    PRIMARY KEY (id)
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS audit_log (
    id      BIGINT       NOT NULL AUTO_INCREMENT,
    ts      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    db_user VARCHAR(64)  NOT NULL,
    action  VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
) ENGINE = InnoDB;

-- Наполнение employees только если таблица пуста (идемпотентность)
INSERT INTO employees (name, salary, passport_no)
SELECT s.name, s.salary, s.passport_no FROM (
    SELECT 'Ivanov Ivan'      AS name, 1200.00 AS salary, 'MP1234567' AS passport_no
    UNION ALL SELECT 'Petrov Petr',     950.50,            'MP7654321'
    UNION ALL SELECT 'Sidorov Sidor',  2100.00,            'KB1122334'
    UNION ALL SELECT 'Kovalenko Anna', 1500.75,            'KB4433221'
) AS s
WHERE NOT EXISTS (SELECT 1 FROM employees);
