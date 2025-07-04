// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/admin/register": {
            "post": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Create a new admin user (requires admin role)",
                "tags": [
                    "admin"
                ],
                "summary": "Register a new admin user",
                "parameters": [
                    {
                        "description": "Admin registration data",
                        "name": "admin",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.RegisterAdminReq"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/storage.UserInfo"
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "409": {
                        "description": "Email already exists",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/admin/users": {
            "get": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Get a list of users (requires admin role)",
                "tags": [
                    "admin"
                ],
                "summary": "List users (admin only)",
                "parameters": [
                    {
                        "type": "integer",
                        "default": 1,
                        "description": "Page number",
                        "name": "page",
                        "in": "query"
                    },
                    {
                        "type": "integer",
                        "default": 10,
                        "description": "Items per page",
                        "name": "limit",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.UserListResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/auth/forgot-password/{email}": {
            "post": {
                "description": "Send password reset code to user's email",
                "tags": [
                    "auth"
                ],
                "summary": "Forgot Password",
                "parameters": [
                    {
                        "type": "string",
                        "description": "USER email",
                        "name": "email",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "message",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid email format",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "404": {
                        "description": "Email not found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/auth/login": {
            "post": {
                "description": "it generates new access and refresh tokens",
                "tags": [
                    "auth"
                ],
                "summary": "login user",
                "parameters": [
                    {
                        "description": "username and password",
                        "name": "userinfo",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.LoginReq"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Tokenlar",
                        "schema": {
                            "$ref": "#/definitions/api.Tokens"
                        }
                    },
                    "400": {
                        "description": "Noto'g'ri so'rov",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Kirish rad etildi",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Server xatosi",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/auth/logout": {
            "post": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Invalidate the current session's tokens",
                "tags": [
                    "auth"
                ],
                "summary": "Logout user",
                "responses": {
                    "200": {
                        "description": "message",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/auth/register": {
            "post": {
                "description": "register new user",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "auth"
                ],
                "summary": "register user",
                "parameters": [
                    {
                        "description": "Foydalanuvchi ma'lumotlari",
                        "name": "info",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.RegisterUserReq"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Muvaffaqiyatli ro'yxatdan o'tish",
                        "schema": {
                            "$ref": "#/definitions/api.Tokens"
                        }
                    },
                    "400": {
                        "description": "Noto'g'ri so'rov formati",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Email yoki parol noto'g'ri",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "409": {
                        "description": "Email allaqachon mavjud",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Server ichki xatosi",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/auth/reset-password": {
            "post": {
                "description": "Reset user password with verification code",
                "tags": [
                    "auth"
                ],
                "summary": "Reset Password",
                "parameters": [
                    {
                        "description": "Reset Password Request",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.ResetPassReq"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "message",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Invalid or expired code",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/auth/user/{id}": {
            "get": {
                "description": "Get User By Id",
                "tags": [
                    "auth"
                ],
                "summary": "Get User By Id",
                "parameters": [
                    {
                        "type": "string",
                        "description": "USER ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/storage.UserInfo"
                        }
                    },
                    "400": {
                        "description": "Invalid user ID",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "404": {
                        "description": "User not found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/user/password": {
            "put": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Change the password of the authenticated user",
                "tags": [
                    "user"
                ],
                "summary": "Change user password",
                "parameters": [
                    {
                        "description": "Old and new passwords",
                        "name": "passwords",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.ChangePasswordReq"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "message",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized or old password incorrect",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/user/profile": {
            "get": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Get the profile of the authenticated user",
                "tags": [
                    "user"
                ],
                "summary": "Get user profile",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/storage.UserInfo"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "404": {
                        "description": "User not found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            },
            "put": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Update the profile of the authenticated user (does not update password)",
                "tags": [
                    "user"
                ],
                "summary": "Update user profile",
                "parameters": [
                    {
                        "description": "User data",
                        "name": "user",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/storage.UserInfo"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/storage.UserInfo"
                        }
                    },
                    "400": {
                        "description": "Invalid request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            },
            "delete": {
                "security": [
                    {
                        "ApiKeyAuth": []
                    }
                ],
                "description": "Delete the profile of the authenticated user (soft delete)",
                "tags": [
                    "user"
                ],
                "summary": "Delete user profile",
                "responses": {
                    "200": {
                        "description": "message",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "api.ChangePasswordReq": {
            "type": "object",
            "properties": {
                "new_password": {
                    "type": "string"
                },
                "old_password": {
                    "type": "string"
                }
            }
        },
        "api.LoginReq": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "example": "ali@example.com"
                },
                "password": {
                    "type": "string",
                    "example": "password123"
                }
            }
        },
        "api.RegisterAdminReq": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "example": "Tashkent"
                },
                "birth_date": {
                    "type": "string",
                    "example": "1990-01-01"
                },
                "email": {
                    "type": "string",
                    "example": "admin@example.com"
                },
                "gender": {
                    "type": "string",
                    "enum": [
                        "male",
                        "female",
                        "non-binary",
                        "other"
                    ],
                    "example": "male"
                },
                "name": {
                    "type": "string",
                    "example": "Admin"
                },
                "password": {
                    "type": "string",
                    "example": "securePassword123"
                },
                "phone_number": {
                    "type": "string",
                    "example": "+998901234567"
                },
                "role": {
                    "type": "string",
                    "enum": [
                        "admin",
                        "user"
                    ],
                    "example": "admin"
                },
                "surname": {
                    "type": "string",
                    "example": "Adminov"
                }
            }
        },
        "api.RegisterUserReq": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "example": "Tashkent"
                },
                "birth_date": {
                    "type": "string",
                    "example": "1999-01-01"
                },
                "email": {
                    "type": "string",
                    "example": "ali@example.com"
                },
                "gender": {
                    "type": "string",
                    "enum": [
                        "male",
                        "female"
                    ],
                    "example": "male"
                },
                "name": {
                    "type": "string",
                    "example": "Ali"
                },
                "password": {
                    "type": "string",
                    "example": "password123"
                },
                "phone_number": {
                    "type": "string",
                    "example": "+998901234567"
                },
                "surname": {
                    "type": "string",
                    "example": "Valiyev"
                }
            }
        },
        "api.ResetPassReq": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "example": "123456"
                },
                "email": {
                    "type": "string",
                    "example": "ali@example.com"
                },
                "password": {
                    "type": "string",
                    "example": "newPassword123"
                }
            }
        },
        "api.Tokens": {
            "type": "object",
            "properties": {
                "access_token": {
                    "type": "string"
                },
                "refresh_token": {
                    "type": "string"
                }
            }
        },
        "api.UserListResponse": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer"
                },
                "page": {
                    "type": "integer"
                },
                "total": {
                    "type": "integer"
                },
                "users": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/storage.UserInfo"
                    }
                }
            }
        },
        "storage.UserInfo": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "example": "Tashkent"
                },
                "birth_date": {
                    "type": "string",
                    "example": "1999-01-01"
                },
                "created_at": {
                    "type": "string"
                },
                "deleted_at": {
                    "type": "integer"
                },
                "email": {
                    "type": "string",
                    "example": "ali@example.com"
                },
                "gender": {
                    "type": "string",
                    "enum": [
                        "male",
                        "female"
                    ],
                    "example": "male"
                },
                "id": {
                    "type": "string",
                    "example": "550e8400-e29b-41d4-a716-446655440000"
                },
                "name": {
                    "type": "string",
                    "example": "Ali"
                },
                "password_hash": {
                    "type": "string",
                    "example": "password123"
                },
                "phone_number": {
                    "type": "string",
                    "example": "+998901234567"
                },
                "provider": {
                    "type": "string",
                    "enum": [
                        "google",
                        "any"
                    ],
                    "example": "any"
                },
                "role": {
                    "type": "string",
                    "enum": [
                        "admin",
                        "user"
                    ],
                    "example": "user"
                },
                "surname": {
                    "type": "string",
                    "example": "Valiyev"
                },
                "updated_at": {
                    "type": "string"
                }
            }
        }
    },
    "securityDefinitions": {
        "ApiKeyAuth": {
            "description": "API Gateway",
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
