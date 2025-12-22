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

#include "camera_log_detector.h"

std::vector<std::string> CameraLogDetector::logs_;
std::mutex CameraLogDetector::mutex_;

void CameraLogDetector::RegisterLogCallback(
    const LogType type, const LogLevel level, const unsigned int domain, const char* tag, const char* msg)
{
    if (msg != nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        logs_.emplace_back(msg);
    }
}

bool CameraLogDetector::IsLogContains(const std::string& substr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(logs_.begin(), logs_.end(),
        [&substr](const std::string& log) {
            return log.find(substr) != std::string::npos;
        });

    bool ret = (it != logs_.end());
    logs_.clear();
    return ret;
}