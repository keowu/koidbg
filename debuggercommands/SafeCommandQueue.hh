/*
    File: SafeCommandQueue.hh
    Authors: João Vitor(@Keowu)
    Created: 29/09/2024
    Last Update: 21/10/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef SAFECOMMANDQUEUE_H
#define SAFECOMMANDQUEUE_H

#include <vector>
#include <mutex>
#include "lexer.hh"

class SafeCommandQueue {
public:
    void push_back(Lexer* command) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_consoleCommandsToProcess.push_back(command);
    }

    std::vector<Lexer*> getCommands() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_consoleCommandsToProcess;
    }

    Lexer* getBack() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_consoleCommandsToProcess.back();
    }

    void popBack() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_consoleCommandsToProcess.pop_back();
    }

    bool isEmpty() {

        std::lock_guard<std::mutex> lock(m_mutex);

        return m_consoleCommandsToProcess.empty();
    }

private:
    std::vector<Lexer*> m_consoleCommandsToProcess;
    std::mutex m_mutex;  // Keep this as a regular mutex
};


#endif // SAFECOMMANDQUEUE_H
