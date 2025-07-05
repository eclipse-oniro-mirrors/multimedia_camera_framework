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

#ifndef TEST_LOG_DETECTOR_H
#define TEST_LOG_DETECTOR_H

#include <iostream>
#include <string>

#include "hilog/log.h"
namespace OHOS {
namespace CameraStandard {

class TestLogDetector {
public:
    TestLogDetector(bool isDebug = false) : isDebug_(isDebug)
    {
        LOG_SetCallback(TestLogDetector::RegisterLogCallback);
    };
    ~TestLogDetector()
    {
        LOG_SetCallback(nullptr);
    };
    bool IsLogContains(const std::string& substr);

private:
    static void RegisterLogCallback(
        const LogType type, const LogLevel, const unsigned int domain, const char* tag, const char* msg);

    static std::string printedLog_;
    bool isDebug_ = false;
};

} // namespace CameraStandard
} // namespace OHOS
#endif
