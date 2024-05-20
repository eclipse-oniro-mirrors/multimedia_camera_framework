/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef STREAM_CAPTURE_STUB_FUZZER_H
#define STREAM_CAPTURE_STUB_FUZZER_H

#include "hstream_capture_stub.h"

namespace OHOS {
namespace CameraStandard {
namespace StreamCaptureStubFuzzer {

void Test(uint8_t *rawData, size_t size);
void Test_OnRemoteRequest(uint8_t *rawData, size_t size);
void Test_HandleCapture(uint8_t *rawData, size_t size);
void Test_HandleSetThumbnail(uint8_t *rawData, size_t size);
void Test_HandleSetRawPhotoInfo(uint8_t *rawData, size_t size);
void Test_HandleEnableDeferredType(uint8_t *rawData, size_t size);
void Test_HandleSetCallback(uint8_t *rawData, size_t size);

void CheckPermission();
std::shared_ptr<OHOS::Camera::CameraMetadata> MakeMetadata(uint8_t *rawData, size_t size);

}
}
}
#endif