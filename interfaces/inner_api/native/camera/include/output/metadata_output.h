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
#include "session/capture_session.h"
#include "stream_metadata_callback_stub.h"
#include "iconsumer_surface.h"
#include "istream_metadata.h"

#include "nocopyable.h"
#include "singleton.h"
#include "surface.h"

namespace OHOS {
namespace CameraStandard {
static const std::map<MetadataObjectType, int32_t> mapLengthOfType = {
    {MetadataObjectType::FACE, 24},
    {MetadataObjectType::HUMAN_BODY, 10},
    {MetadataObjectType::CAT_FACE, 19},
    {MetadataObjectType::CAT_BODY, 10},
    {MetadataObjectType::DOG_FACE, 19},
    {MetadataObjectType::DOG_BODY, 10},
    {MetadataObjectType::SALIENT_DETECTION, 10},
    {MetadataObjectType::BAR_CODE_DETECTION, 10},
    {MetadataObjectType::BASE_FACE_DETECTION, 10},
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
    int64_t timestamp;
    Rect box;
    int32_t objectId;
    int32_t confidence;
};


class MetadataObject : public RefBase {
public:
    MetadataObject(const MetadataObjectType type, const int64_t timestamp, const Rect rect, const int32_t objectId,
                   const int32_t confidence);
    MetadataObject(const MetaObjectParms& parms);
    virtual ~MetadataObject() = default;
    inline MetadataObjectType GetType()
    {
        return type_;
    };
    inline int64_t GetTimestamp()
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
    int64_t timestamp_;
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

class MetadataBasicFaceObject : public MetadataObject {
public:
    MetadataBasicFaceObject(const MetaObjectParms& parms, const Rect leftEyeBoundingBox, const Rect rightEyeBoundingBox,
                       const int32_t pitchAngle, const int32_t yawAngle, const int32_t rollAngle);
    ~MetadataBasicFaceObject() = default;
    inline Rect GetLeftEyeBoundingBox()
    {
        return leftEyeBoundingBox_;
    };
    inline Rect GetRightEyeBoundingBox()
    {
        return rightEyeBoundingBox_;
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
    MetadataObjectFactory();
    virtual ~MetadataObjectFactory() = default;
    void SetType(MetadataObjectType type)
    {
        type_ = type;
    }
    void SetTimestamp(int64_t timestamp)
    {
        timestamp_ = timestamp;
    }
    void SetBox(Rect box)
    {
        box_ = box;
    }
    void SetObjectId(int32_t objectId)
    {
        objectId_ = objectId;
    }
    void SetConfidence(int32_t confidence)
    {
        confidence_ = confidence;
    }
    void SetLeftEyeBoundingBox(Rect leftEyeBoundingBox)
    {
        leftEyeBoundingBox_ = leftEyeBoundingBox;
    }
    void SetRightEyeBoundingBoxd(Rect rightEyeBoundingBox)
    {
        rightEyeBoundingBox_ = rightEyeBoundingBox;
    }
    void SetEmotion(Emotion emotion)
    {
        emotion_ = emotion;
    }
    void SetEmotionConfidence(int32_t emotionConfidence)
    {
        emotionConfidence_ = emotionConfidence;
    }
    void SetPitchAngle(int32_t pitchAngle)
    {
        pitchAngle_ = pitchAngle;
    }
    void SetYawAngle(int32_t yawAngle)
    {
        yawAngle_ = yawAngle;
    }
    void SetRollAngle(int32_t rollAngle)
    {
        rollAngle_ = rollAngle;
    }

    sptr<MetadataObject> createMetadataObject(MetadataObjectType type);

private:
    static sptr<MetadataObjectFactory> metaFactoryInstance_;
    static std::mutex instanceMutex_;
    // Parameters of metadataObject
    MetadataObjectType type_ = MetadataObjectType::INVALID;
    int64_t timestamp_ = 0;
    Rect box_ = {0.0, 0.0, 0.0, 0.0};
    int32_t objectId_ = 0;
    int32_t confidence_ = 0;
    // Parameters of All face metadata
    Rect leftEyeBoundingBox_ = {0.0, 0.0, 0.0, 0.0};
    Rect rightEyeBoundingBox_ = {0.0, 0.0, 0.0, 0.0};
    // Parameters of human face metadata
    Emotion emotion_ = NEUTRAL;
    int32_t emotionConfidence_ = 0;
    int32_t pitchAngle_ = 0;
    int32_t yawAngle_ = 0;
    int32_t rollAngle_ = 0;

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

class FocusTrackingMetaInfo {
public:
    inline FocusTrackingMode GetTrackingMode()
    {
        return trackingMode_;
    }

    inline Rect GetTrackingRegion()
    {
        return trackingRegion_;
    }

    inline int32_t GetTrackingObjectId()
    {
        return trackingObjectId_;
    }

    inline std::vector<sptr<MetadataObject>> GetDetectedObjects()
    {
        return detectedObjects_;
    }

    inline void SetTrackingRegion(Rect& region)
    {
        trackingRegion_ = region;
    }

    inline void SetTrackingMode(FocusTrackingMode mode)
    {
        trackingMode_ = mode;
    }

    inline void SetTrackingObjectId(int32_t trackingObjectId)
    {
        trackingObjectId_ = trackingObjectId;
    }

    inline void SetDetectedObjects(std::vector<sptr<MetadataObject>> detectedObjects)
    {
        detectedObjects_ = detectedObjects;
    }

private:
    FocusTrackingMode trackingMode_{FOCUS_TRACKING_MODE_AUTO};
    Rect trackingRegion_{0.0, 0.0, 0.0, 0.0};
    int32_t trackingObjectId_{-1};
    std::vector<sptr<MetadataObject>> detectedObjects_{};
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
                               std::vector<sptr<MetadataObject>>& metaObjects, bool isNeedMirror, bool isNeedFlip);
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
    
    std::mutex surfaceMutex_;
    sptr<IConsumerSurface> surface_;
    std::shared_ptr<MetadataObjectCallback> appObjectCallback_;
    std::shared_ptr<MetadataStateCallback> appStateCallback_;
    sptr<IStreamMetadataCallback> cameraMetadataCallback_;
};

class MetadataObjectListener : public IBufferConsumerListener {
public:
    MetadataObjectListener(sptr<MetadataOutput> metadata);
    void OnBufferAvailable() override;

private:
    int32_t ProcessMetadataBuffer(void *buffer, int64_t timestamp);
    wptr<MetadataOutput> metadata_;
};

class HStreamMetadataCallbackImpl : public StreamMetadataCallbackStub {
public:
    explicit HStreamMetadataCallbackImpl(MetadataOutput *metaDataOutput) : innerMetadataOutput(metaDataOutput) {}

    ~HStreamMetadataCallbackImpl() = default;

    int32_t OnMetadataResult(const int32_t streamId,
                             const std::shared_ptr<OHOS::Camera::CameraMetadata> &result) override;

    inline sptr<MetadataOutput> GetMetadataOutput()
    {
        return innerMetadataOutput.promote();
    }

private:
    wptr<MetadataOutput> innerMetadataOutput = nullptr;
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // OHOS_CAMERA_METADATA_OUTPUT_H
