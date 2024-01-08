/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_CAMERA_DPS_METADATA_INFO_H
#define OHOS_CAMERA_DPS_METADATA_INFO_H

#include <any>
#include <mutex>
#include <map>
#include "message_parcel.h"

namespace OHOS {
namespace CameraStandard {

enum DpsMetadataError {
    DPS_METADATA_OK = 0,
    DPS_METADATA_INTERNAL_ERROR,
    DPS_METADATA_ERROR_NO_ENTRY,
    DPS_METADATA_ERROR_TYPE_ERROR,
    DPS_METADATA_ERROR_OUT_OF_RANGE
};

const char* const DEFERRED_PROCESSING_TYPE_KEY = "deferredProcessingType";

enum DeferredProcessingType {
    DPS_BACKGROUND = 0,
    DPS_OFFLINE,
};

class DpsMetadata {
public:
    DpsMetadataError ReadFromParcel(MessageParcel &parcel);
    DpsMetadataError WriteToParcel(MessageParcel &parcel);
    DpsMetadataError Get(const std::string &key, int32_t &value) const;
    DpsMetadataError Get(const std::string &key, int64_t &value) const;
    DpsMetadataError Get(const std::string &key, double &value) const;
    DpsMetadataError Get(const std::string &key, std::string &value) const;
    DpsMetadataError Set(const std::string &key, int32_t value);
    DpsMetadataError Set(const std::string &key, int64_t value);
    DpsMetadataError Set(const std::string &key, double value);
    DpsMetadataError Set(const std::string &key, const std::string& value);

private:
    enum class DpsDataType : int32_t {
        i32,
        i64,
        f64,
        string,
    };
    template<class T>
    DpsMetadataError Get(const std::string &key, DpsDataType type, T &value) const;
    DpsMetadataError Set(const std::string &key, DpsDataType type, const std::any& val);

    struct DpsData {
        std::any val;
        DpsDataType type;
    };

    std::map<std::string, struct DpsData> datas;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_METADATA_INFO_H