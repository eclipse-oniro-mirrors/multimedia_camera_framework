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
 
#ifndef CAMERA_OUTPUTCAPABILITY_FUZZER_H
#define CAMERA_OUTPUTCAPABILITY_FUZZER_H
 
 
#include <fuzzer/FuzzedDataProvider.h>
#include "camera_output_capability.h"
 
namespace OHOS {
namespace CameraStandard {
 
 
class CameraOutputCapabilityFuzzer {
public:
    
    static std::shared_ptr<Profile> profilefuzz_;
    static std::shared_ptr<VideoProfile> videoProfilefuzz_;
    static std::shared_ptr<CameraOutputCapability> capabilityfuzz_;
    static void CameraOutputCapabilityFuzzTest(FuzzedDataProvider& fdp);
};
} //CameraStandard
} //OHOS
#endif //CAMERA_OUTPUTCAPABILITY_FUZZER_H