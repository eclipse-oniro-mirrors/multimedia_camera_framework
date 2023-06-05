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

import CameraService from '../model/CameraService';
import DateTimeUtil from '../model/DateTimeUtil';
import Logger from '../model/Logger';

const TAG: string = "RecodeStopDialog";

@CustomDialog
export struct RecodeStopDialog {
  private controller: CustomDialogController;
  @Link isModeBol: boolean;
  @Link videoRecodeTime: number;
  // 时间管理器
  @State dateTimeUtil: DateTimeUtil = new DateTimeUtil();
  @Link isRecording: boolean;
  private timer: number;

  build() {
    Column() {
      Text(`当前视频时长${this.dateTimeUtil.getVideoTime(this.videoRecodeTime)}分钟，是否停止录像？`)
        .fontSize(18)
        .fontWeight(500)
        .fontColor('#182431')
        .margin({ top: 10 })
        .width('99%')
      Row() {
        Button() {
          Text('取消')
            .fontColor('#007DFF')
            .fontSize(17)
            .fontWeight(500)
        }
        .layoutWeight(5)
        .height(50)
        .backgroundColor('#FFFFFF')
        .onClick(() => {
          // 取消定时器继续走
          this.controller.close();
        })

        Text()
          .width(1).height(28)
          .backgroundColor('#8F8F8F')

        Button() {
          Text('停止')
            .fontColor($r('app.color.theme_color'))
            .fontSize(17)
            .fontWeight(500)
        }
        .layoutWeight(5)
        .height(50)
        .backgroundColor('#FFFFFF')
        .onClick(() => {
          this.isModeBol = true;
          // 停止录制
          CameraService.stopVideo()
          .then(() => {
            Logger.error(TAG, 'stopVideo success');
            this.videoRecodeTime = 0;
          })
          .catch((err) => {
            Logger.error(TAG, `stopVideo err: ${JSON.stringify(err)}`);
          })
          this.controller.close();
        })
      }
      .justifyContent(FlexAlign.SpaceAround)
      .width('100%')
    }
    .justifyContent(FlexAlign.SpaceAround)
    .width(336)
    .height(155)
    .padding('2%')
    .borderRadius(32)
    .backgroundColor('#FFFFFF')
  }
}