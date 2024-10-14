/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_METADATA_OUTPUT_H
#define OHOS_CAMERA_METADATA_OUTPUT_H

#include <cstdint>
#include <iostream>
#include <mutex>
#include <sys/types.h>

#include "camera_metadata_info.h"
#include "camera_metadata_operator.h"
#include "capture_output.h"
#include "hstream_metadata_callback_stub.h"
#include "iconsumer_surface.h"
#include "istream_metadata.h"

#include "nocopyable.h"
#include "singleton.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
static const std::map<MetadataObjectType, int32_t> mapLengthOfType = {
    {MetadataObjectType::FACE, 23},
    {MetadataObjectType::HUMAN_BODY, 9},
    {MetadataObjectType::CAT_FACE, 18},
    {MetadataObjectType::CAT_BODY, 9},
    {MetadataObjectType::DOG_FACE, 18},
    {MetadataObjectType::DOG_BODY, 9},
    {MetadataObjectType::SALIENT_DETECTION, 9},
    {MetadataObjectType::BAR_CODE_DETECTION, 9},
    {MetadataObjectType::BASE_FACE_DETECTION, 9},
};

enum MetadataOutputErrorCode : int32_t {
    ERROR_UNKNOWN = 1,
    ERROR_INSUFFICIENT_RESOURCES,
};

enum Emotion : int32_t { NEUTRAL = 0, SADNESS, SMILE, SUPRISE };

struct Rect {
    double topLeftX;
    double topLeftY;
    double width;
    double height;
};

struct MetaObjectParms {
    MetadataObjectType type;
    int32_t timestamp;
    Rect box;
    int32_t objectId;
    int32_t confidence;
};


class MetadataObject : public RefBase {
public:
    MetadataObject(const MetadataObjectType type, const int32_t timestamp, const Rect rect, const int32_t objectId,
                   const int32_t confidence);
    MetadataObject(const MetaObjectParms& parms);
    virtual ~MetadataObject() = default;
    inline MetadataObjectType GetType()
    {
        return type_;
    };
    inline int32_t GetTimestamp()
    {
        return timestamp_;
    };
    inline Rect GetBoundingBox()
    {
        return box_;
    };
    inline int32_t GetObjectId()
    {
        return objectId_;
    };
    inline int32_t GetConfidence()
    {
        return confidence_;
    };

private:
    MetadataObjectType type_;
    int32_t timestamp_;
    Rect box_;
    int32_t objectId_;
    int32_t confidence_;
};

class MetadataFaceObject : public MetadataObject {
public:
    MetadataFaceObject(const MetaObjectParms& parms, const Rect leftEyeBoundingBox, const Rect rightEyeBoundingBox,
                       const Emotion emotion, const int32_t emotionConfidence, const int32_t pitchAngle,
                       const int32_t yawAngle, const int32_t rollAngle);
    ~MetadataFaceObject() = default;
    inline Rect GetLeftEyeBoundingBox()
    {
        return leftEyeBoundingBox_;
    };
    inline Rect GetRightEyeBoundingBox()
    {
        return rightEyeBoundingBox_;
    };
    inline Emotion GetEmotion()
    {
        return emotion_;
    };
    inline int32_t GetEmotionConfidence()
    {
        return emotionConfidence_;
    };
    inline int32_t GetPitchAngle()
    {
        return pitchAngle_;
    };
    inline int32_t GetYawAngle()
    {
        return yawAngle_;
    };
    inline int32_t GetRollAngle()
    {
        return rollAngle_;
    };

private:
    Rect leftEyeBoundingBox_;
    Rect rightEyeBoundingBox_;
    Emotion emotion_;
    int32_t emotionConfidence_;
    int32_t pitchAngle_;
    int32_t yawAngle_;
    int32_t rollAngle_;
};

class MetadataHumanBodyObject : public MetadataObject {
public:
    MetadataHumanBodyObject(const MetaObjectParms& parms);
    ~MetadataHumanBodyObject() = default;
};

class MetadataCatFaceObject : public MetadataObject {
public:
    MetadataCatFaceObject(const MetaObjectParms& parms, const Rect leftEyeBoundingBox, const Rect rightEyeBoundingBox);
    ~MetadataCatFaceObject() = default;
    inline Rect GetLeftEyeBoundingBox()
    {
        return leftEyeBoundingBox_;
    };
    inline Rect GetRightEyeBoundingBox()
    {
        return rightEyeBoundingBox_;
    };

private:
    Rect leftEyeBoundingBox_;
    Rect rightEyeBoundingBox_;
};

class MetadataCatBodyObject : public MetadataObject {
public:
    MetadataCatBodyObject(const MetaObjectParms& parms);
    ~MetadataCatBodyObject() = default;
};

class MetadataDogFaceObject : public MetadataObject {
public:
    MetadataDogFaceObject(const MetaObjectParms& parms, const Rect leftEyeBoundingBox, const Rect rightEyeBoundingBox);
    ~MetadataDogFaceObject() = default;
    inline Rect GetLeftEyeBoundingBox()
    {
        return leftEyeBoundingBox_;
    };
    inline Rect GetRightEyeBoundingBox()
    {
        return rightEyeBoundingBox_;
    };

private:
    Rect leftEyeBoundingBox_;
    Rect rightEyeBoundingBox_;
};

class MetadataDogBodyObject : public MetadataObject {
public:
    MetadataDogBodyObject(const MetaObjectParms& parms);
    ~MetadataDogBodyObject() = default;
};

class MetadataSalientDetectionObject : public MetadataObject {
public:
    MetadataSalientDetectionObject(const MetaObjectParms& parms);
    ~MetadataSalientDetectionObject() = default;
};

class MetadataBarCodeDetectionObject : public MetadataObject {
public:
    MetadataBarCodeDetectionObject(const MetaObjectParms& parms);
    ~MetadataBarCodeDetectionObject() = default;
};

class MetadataObjectFactory : public RefBase {
public:
    virtual ~MetadataObjectFactory() = default;

    static sptr<MetadataObjectFactory> &GetInstance();
    inline sptr<MetadataObjectFactory> SetType(MetadataObjectType type)
    {
        type_ = type;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetTimestamp(int32_t timestamp)
    {
        timestamp_ = timestamp;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetBox(Rect box)
    {
        box_ = box;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetObjectId(int32_t objectId)
    {
        objectId_ = objectId;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetConfidence(int32_t confidence)
    {
        confidence_ = confidence;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetLeftEyeBoundingBox(Rect leftEyeBoundingBox)
    {
        leftEyeBoundingBox_ = leftEyeBoundingBox;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetRightEyeBoundingBoxd(Rect rightEyeBoundingBox)
    {
        rightEyeBoundingBox_ = rightEyeBoundingBox;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetEmotion(Emotion emotion)
    {
        emotion_ = emotion;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetEmotionConfidence(int32_t emotionConfidence)
    {
        emotionConfidence_ = emotionConfidence;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetPitchAngle(int32_t pitchAngle)
    {
        pitchAngle_ = pitchAngle;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetYawAngle(int32_t yawAngle)
    {
        yawAngle_ = yawAngle;
        return this;
    }
    inline sptr<MetadataObjectFactory> SetRollAngle(int32_t rollAngle)
    {
        rollAngle_ = rollAngle;
        return this;
    }

    sptr<MetadataObject> createMetadataObject(MetadataObjectType type);

private:
    MetadataObjectFactory();
    static sptr<MetadataObjectFactory> metaFactoryInstance_;
    static std::mutex instanceMutex_;
    // Parameters of metadataObject
    MetadataObjectType type_;
    int32_t timestamp_;
    Rect box_;
    int32_t objectId_;
    int32_t confidence_;
    // Parameters of All face metadata
    Rect leftEyeBoundingBox_;
    Rect rightEyeBoundingBox_;
    // Parameters of human face metadata
    Emotion emotion_;
    int32_t emotionConfidence_;
    int32_t pitchAngle_;
    int32_t yawAngle_;
    int32_t rollAngle_;

    void ResetParameters();
};

class MetadataObjectCallback {
public:
    MetadataObjectCallback() = default;
    virtual ~MetadataObjectCallback() = default;
    virtual void OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const = 0;
};

class MetadataStateCallback {
public:
    MetadataStateCallback() = default;
    virtual ~MetadataStateCallback() = default;
    virtual void OnError(int32_t errorCode) const = 0;
};

class MetadataOutput : public CaptureOutput {
public:
    MetadataOutput(sptr<IConsumerSurface> surface, sptr<IStreamMetadata> &streamMetadata);
    ~MetadataOutput();

    /**
     * @brief Get the supported metadata object types.
     *
     * @return Returns vector of MetadataObjectType.
     */
    std::vector<MetadataObjectType> GetSupportedMetadataObjectTypes();

    /**
     * @brief Set the metadata object types
     *
     * @param Vector of MetadataObjectType
     */
    void SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> objectTypes);

    /**
     * @brief Add the metadata object types
     *
     * @param Vector of MetadataObjectType
     */
    int32_t AddMetadataObjectTypes(std::vector<MetadataObjectType> metadataObjectTypes);

    /**
     * @brief Remove the metadata object types
     *
     * @param Vector of MetadataObjectType
     */
    int32_t RemoveMetadataObjectTypes(std::vector<MetadataObjectType> metadataObjectTypes);

    /**
     * @brief Set the metadata object callback for the metadata output.
     *
     * @param MetadataObjectCallback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<MetadataObjectCallback> metadataObjectCallback);

    /**
     * @brief Set the metadata state callback for the metadata output.
     *
     * @param MetadataStateCallback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<MetadataStateCallback> metadataStateCallback);

    int32_t CreateStream() override;

    /**
     * @brief Start the metadata capture.
     */
    int32_t Start();

    /**
     * @brief Stop the metadata capture.
     */
    int32_t Stop();

    /**
     * @brief Releases a instance of the MetadataOutput.
     */
    int32_t Release() override;
    bool reportFaceResults_ = false;
    bool reportLastFaceResults_ = false;
    void ProcessMetadata(const int32_t streamId, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result,
                               std::vector<sptr<MetadataObject>>& metaObjects, bool isNeedMirror);
    int32_t ProcessMetaObjects(const int32_t streamId, std::vector<sptr<MetadataObject>> &metaObjects,
                               const std::vector<camera_metadata_item_t>& metadataItem,
                               const std::vector<uint32_t>& metadataTypes, bool isNeedMirror);
    std::shared_ptr<MetadataObjectCallback> GetAppObjectCallback();
    std::shared_ptr<MetadataStateCallback> GetAppStateCallback();

    friend class MetadataObjectListener;

private:
    void CameraServerDied(pid_t pid) override;
    void ReleaseSurface();
    sptr<IConsumerSurface> GetSurface();
    bool checkValidType(const std::vector<MetadataObjectType>& typeAdded,
                        const std::vector<MetadataObjectType>& supportedType);
    std::vector<int32_t> convert(const std::vector<MetadataObjectType>& typesOfMetadata);
    void GetMetadataResults(const common_metadata_header_t *metadata,
        std::vector<camera_metadata_item_t>& metadataResults, std::vector<uint32_t>& metadataTypes);
    void GenerateObjects(const camera_metadata_item_t& metadataItem, MetadataObjectType type,
        std::vector<sptr<MetadataObject>>& metaObjects, bool isNeedMirror);
    Rect ProcessRectBox(int32_t offsetTopLeftX, int32_t offsetTopLeftY,
                        int32_t offsetBottomRightX, int32_t offsetBottomRightY, bool isNeedMirror);
    void ProcessBaseInfo(sptr<MetadataObjectFactory> factoryPtr,
        const camera_metadata_item_t& metadataItem, int32_t& index, MetadataObjectType typeFromHal, bool isNeedMirror);
    void ProcessExternInfo(sptr<MetadataObjectFactory> factoryPtr,
        const camera_metadata_item_t& metadataItem, int32_t& index, MetadataObjectType typeFromHal, bool isNeedMirror);
    void ProcessHumanFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
        const camera_metadata_item_t& metadataItem, int32_t& index, bool isNeedMirror);
    void ProcessCatFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
        const camera_metadata_item_t& metadataItem, int32_t& index, bool isNeedMirror);
    void ProcessDogFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
        const camera_metadata_item_t& metadataItem, int32_t& index, bool isNeedMirror);
    
    std::mutex surfaceMutex_;
    sptr<IConsumerSurface> surface_;
    std::shared_ptr<MetadataObjectCallback> appObjectCallback_;
    std::shared_ptr<MetadataStateCallback> appStateCallback_;
    sptr<IStreamMetadataCallback> cameraMetadataCallback_;
    std::vector<uint32_t> typesOfMetadata_ = {
        OHOS_STATISTICS_DETECT_HUMAN_FACE_INFOS,
        OHOS_STATISTICS_DETECT_HUMAN_BODY_INFOS,
        OHOS_STATISTICS_DETECT_CAT_FACE_INFOS,
        OHOS_STATISTICS_DETECT_CAT_BODY_INFOS,
        OHOS_STATISTICS_DETECT_DOG_FACE_INFOS,
        OHOS_STATISTICS_DETECT_DOG_BODY_INFOS,
        OHOS_STATISTICS_DETECT_SALIENT_INFOS,
        OHOS_STATISTICS_DETECT_BAR_CODE_INFOS,
        OHOS_STATISTICS_DETECT_BASE_FACE_INFO};
};

class MetadataObjectListener : public IBufferConsumerListener {
public:
    MetadataObjectListener(sptr<MetadataOutput> metadata);
    void OnBufferAvailable() override;

private:
    int32_t ProcessMetadataBuffer(void *buffer, int64_t timestamp);
    wptr<MetadataOutput> metadata_;
};

class HStreamMetadataCallbackImpl : public HStreamMetadataCallbackStub {
public:
    explicit HStreamMetadataCallbackImpl(MetadataOutput *metaDataOutput) : innerMetadataOutput(metaDataOutput) {}

    ~HStreamMetadataCallbackImpl() = default;

    int32_t OnMetadataResult(const int32_t streamId,
                             const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) override;

    inline sptr<MetadataOutput> GetMetadataOutput()
    {
        if (innerMetadataOutput == nullptr) {
            return nullptr;
        }
        return innerMetadataOutput.promote();
    }

private:
    wptr<MetadataOutput> innerMetadataOutput = nullptr;
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // OHOS_CAMERA_METADATA_OUTPUT_H
