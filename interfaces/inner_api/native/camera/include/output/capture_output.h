/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_CAPTURE_OUTPUT_H
#define OHOS_CAMERA_CAPTURE_OUTPUT_H

#include <refbase.h>

namespace OHOS {
namespace CameraStandard {
enum CAPTURE_OUTPUT_TYPE {
    PREVIEW_OUTPUT,
    PHOTO_OUTPUT,
    VIDEO_OUTPUT
};
class CaptureOutput : public RefBase {
public:
    CaptureOutput(CAPTURE_OUTPUT_TYPE type);
    virtual ~CaptureOutput() {}
    virtual void Release() = 0;
    CAPTURE_OUTPUT_TYPE GetType();

private:
    CAPTURE_OUTPUT_TYPE type_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAPTURE_OUTPUT_H
