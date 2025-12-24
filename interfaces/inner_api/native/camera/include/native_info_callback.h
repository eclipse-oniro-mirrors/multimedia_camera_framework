/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef NATIVE_INFO_CALLBACK
#define NATIVE_INFO_CALLBACK
namespace OHOS {
namespace CameraStandard {
template<typename InfoTp>
class NativeInfoCallback {
public:
    virtual void OnInfoChanged(InfoTp info) = 0;
    virtual ~NativeInfoCallback() = default;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // NATIVE_INFO_CALLBACK
