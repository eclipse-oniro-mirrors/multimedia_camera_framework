/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CAMERA_LOG_DETECTOR_H
#define CAMERA_LOG_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>

#include "hilog/log.h"
#include "hilog/log_c.h"

class CameraLogDetector {
public:
    CameraLogDetector()
    {
        LOG_SetCallback(CameraLogDetector::RegisterLogCallback);
    }
    
    ~CameraLogDetector()
    {
        LOG_SetCallback(nullptr);
    }

    bool IsLogContains(const std::string& substr);

private:
    static void RegisterLogCallback(
        const LogType type, const LogLevel level, const unsigned int domain, const char* tag, const char* msg);

    static std::vector<std::string> logs_;
    static std::mutex mutex_;
};
#endif