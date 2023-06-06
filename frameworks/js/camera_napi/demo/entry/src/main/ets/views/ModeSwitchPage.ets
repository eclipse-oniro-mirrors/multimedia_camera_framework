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

// 反转摄像头_多机位_拍照_摄像

import { RecodeStopDialog } from '../Dialog/RecodeStopDialog';
import { MultiCameraDialog } from '../Dialog/MultiCameraDialog';
import DateTimeUtil from '../model/DateTimeUtil';
import Logger from '../model/Logger';
import CameraService from '../model/CameraService';
import image from '@ohos.multimedia.image';

const TAG: string = 'ModeSwitchPage';

@Component
export struct ModeSwitchPage {
  // 相机摄像头
  @Link cameraDeviceIndex: number;
  // surfaceID值
  @Prop surfaceId: string;
  // 倒计时值
  @Link countdownNum: number;
  // 倒计时定时器
  @State countTimerInt: number = -1;
  @State countTimerOut: number = -1;
  // 拍照缩略图
  @State imgThumbnail: string = undefined;
  // 录制时间
  @State videoRecodeTime: number = 0;
  // 录制时间定时器
  @State timer: number = undefined;
  // 时间管理器
  @State dateTimeUtil: DateTimeUtil = new DateTimeUtil();
  // 选择模式
  @State modelBagCol: string = 'photo';
  // 选择相机或者拍照
  @State @Watch('onChangeIsModeBol') isModeBol: boolean = true;
  // 录像开始暂停
  @State @Watch('onChangeRecord') isRecording: boolean = true;
  // 视频缩略图
  @State videoThumbnail: image.PixelMap = undefined;
  // 确定是否停止录制的弹框
  private recodeStopDialogController: CustomDialogController = new CustomDialogController({
    builder: RecodeStopDialog({
      isModeBol: $isModeBol,
      videoRecodeTime: $videoRecodeTime,
      isRecording: $isRecording,
      timer: this.timer
    }),
    autoCancel: false,
    customStyle: true
  });
  // 多机位弹框
  private MultiCameraDialogController: CustomDialogController = new CustomDialogController({
    builder: MultiCameraDialog({}),
    autoCancel: false,
    customStyle: true
  });

  /**
   * 暂停后点击停止 需要将暂停回复默认
   */
  onChangeIsModeBol(): void {
    this.isRecording = true;
  }

  /**
   * 恢复视频录制
   */
  resumeVideo(): void {
    CameraService.resumeVideo().then(() => {
      this.timer = setInterval(() => {
        this.videoRecodeTime += 1000;
      }, 1000)
    })
  }

  /**
   * 录制 暂停/开始
   */
  onChangeRecord(): void {
    Logger.info(TAG, `onChangeRecord isRecording: ${this.isRecording}`);
    if (this.isRecording) {
      // 开始
      this.resumeVideo();
    } else {
      // 暂停
      if (this.timer) {
        clearInterval(this.timer);
      }
      CameraService.pauseVideo();
    }
  }

  /**
   * 倒计时拍照和录像
   */
  countTakeVideoFn(): void {
    if (this.countdownNum) {
      // 清除定时器
      if (this.countTimerOut) {
        clearTimeout(this.countTimerOut);
      }
      if (this.countTimerInt) {
        clearInterval(this.countTimerInt);
      }
      // 开启定时器
      this.countTimerOut = setTimeout(() => {
        // 判断是录像还是拍照模式
        this.isVideoPhotoFn();
      }, this.countdownNum * 1000);
      // 开启计时器
      this.countTimerInt = setInterval(() => {
        this.countdownNum--;
        if (this.countdownNum === 0) {
          clearInterval(this.countTimerInt);
        }
      }, 1000);
    } else {
      this.isVideoPhotoFn();
    }
  }

  /**
   * 判断录像或者照片模式
   */
  isVideoPhotoFn(): void {
    if (this.modelBagCol == 'photo') {
      CameraService.takePicture();
    } else if (this.modelBagCol == 'video') {
      this.isModeBol = false;
      if (this.timer) {
        clearInterval(this.timer);
      }
      // 开始录制
      CameraService.startVideo().then(() => {
        // 计时器
        this.timer = setInterval(() => {
          this.videoRecodeTime += 1000;
        }, 1000);
      });
    }
  }

  aboutToAppear(): void {
    CameraService.setTakePictureCallback(this.handleTakePicture.bind(this));
  }

  handleTakePicture = (thumbnail: string) => {
    this.imgThumbnail = thumbnail;
    Logger.info(TAG, `takePicture end, thumbnail: ${this.imgThumbnail}`);
  }

  build() {
    if (this.isModeBol) {
      Column() {
        Text('拍照')
          .backgroundColor(this.modelBagCol === 'photo' ? $r('app.color.theme_color') : '')
          .size({ width: 64, height: 28 })
          .borderRadius(14)
          .fontSize(14)
          .fontColor(Color.White)
          .onClick(() => {
            this.modelBagCol = 'photo';
          })
      }.position({ x: '20%', y: '75%' })

      Column() {
        Text('录像')
          .fontSize(14)
          .fontColor(Color.White)
          .borderRadius(14)
          .size({ width: 64, height: 28 })
          .backgroundColor(this.modelBagCol === 'video' ? $r('app.color.theme_color') : '')
          .onClick(() => {
            this.modelBagCol = 'video';
          })
      }.position({ x: '40%', y: '75%' })

      Column() {
        Text('多机位')
          .size({ width: 64, height: 28 })
          .fontSize(14)
          .fontColor(Color.White)
          .backgroundColor(this.modelBagCol === 'multi' ? $r('app.color.theme_color') : '')
          .onClick(() => {
            this.modelBagCol = 'multi';
            this.MultiCameraDialogController.open();
          })
          .borderRadius(14)
      }.position({ x: '60%', y: '75%' })

      // 图库
      Column() {
        Row() {
          if (this.modelBagCol === 'photo') {
            Image(this.imgThumbnail || $r('app.media.pic_avatar_radio02'))
              .aspectRatio(1)
              .objectFit(ImageFit.Fill)
              .border({ width: 2, color: 0xFFFFFF, radius: 40 })
              .width('200px')
              .height('200px')
          } else {
            Image(this.videoThumbnail || $r('app.media.pic_avatar_radio02'))
              .aspectRatio(1)
              .objectFit(ImageFit.Fill)
              .border({ width: 2, color: 0xFFFFFF, radius: 40 })
              .width('200px')
              .height('200px')
          }
        }.onClick(() => {
          globalThis.abilityContext.startAbility({
            bundleName: 'com.ohos.photos',
            abilityName: 'com.ohos.photos.MainAbility'
          });
        })
      }.position({ x: '10%', y: '82%' })

      // 拍照录像按键
      Column() {
        Row() {
          Button() {
            Text()
              .width('120px')
              .height('120px')
              .borderRadius('40px')
              .backgroundColor(this.modelBagCol == 'video' ? $r('app.color.theme_color') : Color.White)
          }
          .border({ width: 3, color: 0xFFFFFF, radius: 70 })
          .width('200px')
          .height('200px')
          .backgroundColor('rgba(255,255,255,0.20)')
          .onClick(() => {
            // 倒计时拍照录像—默认拍照录像
            this.countTakeVideoFn();
          })
        }
        //.margin({ top: 32 })
      }.position({ x: '40%', y: '82%' })

      // 前后置摄像头切换
      Column() {
        Row() {
          Button() {
            Image($r('app.media.switch_camera'))
              .width('120px').height('120px')
          }
          .width('200px')
          .height('200px')
          .backgroundColor('rgba(255,255,255,0.20)')
          .borderRadius('40px')
          .onClick(async () => {
            // 切换摄像头
            this.cameraDeviceIndex ? this.cameraDeviceIndex = 0 : this.cameraDeviceIndex = 1;
            // 清除配置
            await CameraService.releaseSession();
            // 开始预览
            await CameraService.initCamera(this.surfaceId, this.cameraDeviceIndex);
          })
        }
      }.position({ x: '70%', y: '82%' })
    } else {
      Column() {
        Row() {
          Text().size({ width: 12, height: 12 }).backgroundColor($r('app.color.theme_color')).borderRadius(6)
          Text(this.dateTimeUtil.getVideoTime(this.videoRecodeTime))
            .fontSize(30)
            .fontColor(Color.White)
            .margin({ left: 8 })
        }.offset({ x: -580, y: -180 })
      }.position({ x: 120, y: 450 })

      Column() {
        // 录像抓拍键
        Button() {
          Text().width('120px').height('120px').borderRadius('35px').backgroundColor(Color.White)
        }
        .border({ width: 2, color: 0xFFFFFF, radius: 45 })
        .width('200px')
        .height('200px')
        .backgroundColor('rgba(255,255,255,0.20)')
        .onClick(() => {
          CameraService.takePicture();
        })
      }.position({ x: '10%', y: '82%' })

      Column() {
        Row() {
          Column() {
            // 录像停止键
            Button() {
              Image($r('app.media.ic_camera_video_close')).size({ width: 25, height: 25 })
            }
            .width('120px')
            .height('120px')
            .backgroundColor($r('app.color.theme_color'))
            .onClick(() => {
              if (this.timer) {
                clearInterval(this.timer);
              }
              // 弹框无法响应
              // CameraService.pauseVideo();
              // 停止录制
              CameraService.stopVideo().then(async (fileAsset) => {
                this.videoRecodeTime = 0;
                this.isModeBol = true;
                try {
                  // 获取录制缩略图
                  this.videoThumbnail = await fileAsset.getThumbnail();
                } catch (err) {
                  Logger.error(TAG, 'videoThumbnail err:' + JSON.stringify(err.message));
                }
              })
              // 打开停止弹框
              this.recodeStopDialogController.open();
            })
          }
          .width('180px')
          .height('180px')
          .borderRadius('60px')
          .backgroundColor($r('app.color.theme_color'))
          .justifyContent(FlexAlign.SpaceAround)
        }
        .justifyContent(FlexAlign.Center)
        .border({ width: 3, color: 0xFFFFFF, radius: 70 })
        .width('200px')
        .height('200px')
        .backgroundColor('rgba(255,255,255,0.20)')
      }.position({ x: '40%', y: '82%' })

      Column() {
        Row() {
          Column() {
            // 录像暂停-播放键
            Button() {
              Image(this.isRecording ? $r('app.media.ic_camera_video_on') : $r('app.media.ic_camera_video_off'))
                .size({
                  width: 25,
                  height: 25
                })
            }
            .width('120px')
            .height('120px')
            .backgroundColor($r('app.color.theme_color'))
            .onClick(() => {
              this.isRecording = !this.isRecording;
            })
          }
          .width('180px')
          .height('180px')
          .borderRadius('60px')
          .backgroundColor($r('app.color.theme_color'))
          .justifyContent(FlexAlign.SpaceAround)
        }
        .justifyContent(FlexAlign.Center)
        .border({ width: 3, color: 0xFFFFFF, radius: 70 })
        .width('200px')
        .height('200px')
        .backgroundColor('rgba(255,255,255,0.20)')
      }.position({ x: '70%', y: '82%' })
    }
  }
}
