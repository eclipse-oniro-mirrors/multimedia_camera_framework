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
#include "test_log_detector.h"

namespace OHOS {
namespace CameraStandard {
std::string TestLogDetector::printedLog_;
void TestLogDetector::RegisterLogCallback(
    const LogType type, const LogLevel, const unsigned int domain, const char* tag, const char* msg)
{
    printedLog_ = msg;
}

bool TestLogDetector::IsLogContains(const std::string& substr)
{
    if (isDebug_) {
        std::cout << "checking: " + substr + " [in] " + printedLog_ << std::endl;
    }
    return printedLog_.find(substr) != std::string::npos;
}
} // namespace CameraStandard
} // namespace OHOS