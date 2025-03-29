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

#ifndef CAMERA_PARSER_H
#define CAMERA_PARSER_H

namespace OHOS {
namespace CameraStandard {
struct CameraRotateStrategyInfo {
    std::string bundleName;
    float wideValue;
    int32_t rotateDegree;
    int16_t fps;
};
class Parser {
public:
    virtual ~Parser() {}
    virtual bool LoadConfiguration() = 0;
    virtual void Destroy() = 0;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_PARSER_H
