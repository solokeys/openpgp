/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */

#include "stm32fs.h"

Stm32fs::Stm32fs(Stm32fsConfig_t config) {
    FsConfig = config;
    Valid = true;
    
}

bool Stm32fs::isValid() {
    return Valid;
}

Stm32File_t *Stm32fs::FindFirst(std::string_view fileFilter, Stm32File_t *filePtr) {

    return nullptr;
}

Stm32File_t *Stm32fs::FindNext(Stm32File_t *filePtr) {
    
    return nullptr;
}

bool Stm32fs::ReadFile(std::string_view fileName, uint8_t *data, size_t *length, size_t maxlength) {
    
    return false;
}

bool Stm32fs::GetFilePtr(std::string_view fileName, uint8_t **ptr, size_t *length) {
    
    return false;
}

bool Stm32fs::WriteFile(std::string_view fileName, uint8_t *data, size_t length) {
    
    return false;
}

bool Stm32fs::DeleteFile(std::string_view fileName) {
    
    return false;
}

bool Stm32fs::DeleteFiles(std::string_view fileFilter) {
    
    return false;
}

bool Stm32fs::Optimize() {
    
    return false;
}
