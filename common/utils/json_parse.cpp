/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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
#include "json_parse.h"
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_set>

namespace OHOS::CameraStandard {
std::pair<std::string, std::string> ParseWatermarkFilter(const std::string& editData)
{
    std::string filterName;
    std::string filterParam;
    nlohmann::json root = nlohmann::json::parse(editData, nullptr, false);
    if (root.contains("edit_data") && root["edit_data"].is_string()) {
        std::string edit_data = root["edit_data"];
        nlohmann::json subRoot = nlohmann::json::parse(edit_data, nullptr, false);
        if (subRoot.contains("imageEffect") && subRoot["imageEffect"].contains("filters")) {
            const nlohmann::json& filters = subRoot["imageEffect"]["filters"];
            for (const auto& filter : filters) {
                if (filter.contains("name") && filter["name"].is_string()) {
                    std::string name = filter["name"].get<std::string>();
                    if (name.find("Sticker") != std::string::npos) {
                        if (filter.contains("values")) {
                            filterName = name;
                            filterParam = filter["values"].dump();
                            break;
                        }
                    }
                }
            }
        }
    }

    return { filterName, filterParam };
}

std::string MergeShotParam(const std::string& editData, const std::string& shotParam)
{
    nlohmann::json root = nlohmann::json::parse(editData, nullptr, false);
    if (root.contains("edit_data") && root["edit_data"].is_string()) {
        std::string edit_data = root["edit_data"];
        nlohmann::json subRoot = nlohmann::json::parse(edit_data, nullptr, false);
        if (subRoot.contains("imageEffect") && subRoot["imageEffect"].contains("filters")) {
            auto& filters = subRoot["imageEffect"]["filters"];
            for (auto& filter : filters) {
                if (filter.contains("name") && filter["name"].is_string()) {
                    std::string name = filter["name"].get<std::string>();
                    if (name.find("Sticker") != std::string::npos) {
                        if (filter.contains("values") && filter["values"].contains("FILTER_SHOT_PARAM") &&
                            filter["values"]["FILTER_SHOT_PARAM"].is_string() &&
                            filter["values"]["FILTER_SHOT_PARAM"].get<std::string>().empty()) {
                            filter["values"]["FILTER_SHOT_PARAM"] = shotParam;
                        }
                    }
                }
            }
        }

        // 将修改后的subRoot序列化为字符串，并确保转义字符正确
        std::string updatedEditData = subRoot.dump();
        root["edit_data"] = updatedEditData;
    }

    return root.dump();
}

std::string ParseThenDelEncodeFormat(std::string& editData)
{
    nlohmann::json root = nlohmann::json::parse(editData, nullptr, false);
    std::string encodeFormat = "";

    if (root.contains("encode_format") && root["encode_format"].is_string()) {
        encodeFormat = root["encode_format"].get<std::string>();
        root.erase("encode_format");
    }

    editData = root.dump();
    return encodeFormat;
}

std::string CreateOrSetFaceBeautifyParamValidToBeautyFilter(const std::string& editData, bool isEnable)
{
    static const std::unordered_set<std::string> BEAUTY_FILTER {
        "EnhancedFaceBeautificationEFilter",
        "ModerateFaceBeautificationEFilter",
        "BaseFaceBeautificationEFilter",
    };
    nlohmann::json root = nlohmann::json::parse(editData, nullptr, false);
    if (root.contains("edit_data") && root["edit_data"].is_string()) {
        std::string edit_data = root["edit_data"];
        nlohmann::json subRoot = nlohmann::json::parse(edit_data, nullptr, false);
        if (subRoot.contains("imageEffect") && subRoot["imageEffect"].contains("filters")) {
            nlohmann::json& filters = subRoot["imageEffect"]["filters"];
            for (auto& filter : filters) {
                if (filter.contains("name") && filter["name"].is_string()) {
                    std::string name = filter["name"].get<std::string>();
                    // check name
                    if (BEAUTY_FILTER.count(name) && filter.contains("values")) {
                        // append
                        nlohmann::json& values = filter["values"];
                        values["faceBeautyParamValid"] = isEnable;
                    }
                }
            }
        }
        root["edit_data"] = subRoot.dump();
    }
    return root.dump();
}
} // namespace OHOS::CameraStandard