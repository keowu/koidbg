/*
    File: lexer.hh
    Author: João Vitor(@Keowu)
    Created: 29/09/2024
    Last Update: 29/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef LEXER_H
#define LEXER_H

#include <QString>

class Token {
public:
    enum TokenType {
        COMMAND,
        ARGUMENT,
        END,
        INVALID
    };

    TokenType type;
    QString value;

    Token(TokenType t, QString v) : type(t), value(v) {}
};

class Lexer {
public:
    explicit Lexer(const QString& input) : input_(input), position_(0) {}

    Token nextToken() {
        skipWhitespace();

        if (position_ >= input_.size()) {
            return Token(Token::TokenType::END, "");
        }

        QChar current = input_[position_];

        if (current == '!') {
            return parseCommand();
        } else if (current.isDigit() || (current == '0' && position_ + 1 < input_.size() && input_[position_ + 1] == 'x')) {
            return parseArgument();
        } else if (current.isLetter() || current == '\\') {
            return parseArgument(); // Allow file paths or identifiers
        }

        return Token(Token::TokenType::INVALID, QString(current));
    }

private:
    QString input_;
    int position_;

    void skipWhitespace() {
        while (position_ < input_.size() && input_[position_].isSpace()) {
            ++position_;
        }
    }

    Token parseCommand() {
        int start = position_++;
        while (position_ < input_.size() && !input_[position_].isSpace()) {
            ++position_;
        }
        return Token(Token::TokenType::COMMAND, input_.mid(start, position_ - start));
    }

    Token parseArgument() {
        int start = position_;
        while (position_ < input_.size() && !input_[position_].isSpace()) {
            ++position_;
        }
        return Token(Token::TokenType::ARGUMENT, input_.mid(start, position_ - start));
    }
};

#endif // LEXER_H
