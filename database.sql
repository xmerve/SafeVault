PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS Users (
    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL UNIQUE CHECK (Username GLOB '[A-Za-z0-9_.-]*'),
    Email TEXT NOT NULL CHECK (Email != ''),
    PasswordHash TEXT NOT NULL,
    Role TEXT NOT NULL CHECK (Role IN ('admin', 'user'))
);

CREATE INDEX IF NOT EXISTS IX_Users_Role ON Users(Role);

-- Parameterised query example (SQLite syntax):
-- INSERT INTO Users (Username, Email) VALUES ($username, $email);
-- The $parameter placeholders MUST be bound through a command object to prevent injection.

