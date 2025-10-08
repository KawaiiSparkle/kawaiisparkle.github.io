# 通过利用[CVE-2025-31710](https://nvd.nist.gov/vuln/detail/CVE-2025-31710)间接实现给某类完全不可能利用下载模式(FDL1/FDL2)的展讯设备获取Root权限
时间:2025/6/30 作者:[Github@KawaiiSparkle](https://github.com/kawaiiSparkle)、[Github@PurpleHang](https://github.com/purplehang)
## 前言
众所周知，科大讯飞的学习机零售版使用的芯片如下：
ud710(Unisoc T710/T740/T7510): aa/ab/ad (是市场占有率最高的芯片类型，aa/ab都可以通过下载模式，ad完全无公开资料)
ums312(Unisoc T310)：仅Q10
ums9620(Unisoc T760)：较新方案(T30Lite、Lumie10Pro)
骁龙625:X1Pro
骁龙750G:零售版联想合作机型(带流量上网+通话功能)
RK3588(s): T20Pro / T30(Pro/Ultra)
之前很长一段时间（大概3年左右），仅ud710-ad方案一直处于只能解锁Bootloader以及使用我通过精简部分系统组件得到的sGSI但无法被攻克的状态，但随着出现了CVE-2025-31710这个漏洞，事情开始有了转机…………
## 实验环境
因为我总不可能真的去搞一堆ud710-ad的机型回来，所以等效一下就用了一台官解并解了BL锁的CB-C6s-STU机型来尝试使用该漏洞进行利用(感谢[Github@PurpleHang](https://github.com/purplehang)提供平板并花了大概一周陪我搞实验)，这样实验失败砖机时可以通过下载模式重置实验环境至初始状态
顺带一提，本机型的SELinux一直是Enforcing状态
## 实验过程
### 第一次
目标：计划直接使用漏洞以及dd/cp命令，得到recovery/boot 及 其他分区的镜像
实际：其他分区（甚至是userdata）都被成功提取了，但一到system/rec/boot就Permission Denied，所以这个Root是残血的。尝试了使用命令来修改SELinux为Permissive状态，结果没有权限进行修改SELinux状态
### 第二次
想到了之前搞纯system-root方案时会改一下vendor
目标：尝试用magiskinit修补vendor下的precompiled_sepolicy并打包回去看看有没有变化
实际：无任何变化
### 第三~七次
尝试直接把precompiled_sepolicy相关部分删掉并刷回去，发现并没有什么变化
尝试使用早茶光给的方法进行system-root，寄
分别尝试直接给vendor_sepolicy.cil与plat_pub_versioned.cil文件的最底部加上全局宽容，刷回去，不开机了，说明这两个中某项改了可能有用。
另外在乱翻文件内容时发现plat_pub_versioned.cil中dev_type这个属性中有数个块设备，里面就有我提取不出来的boot/recovery/system_block_device_28_0。我又想到了系统在Recovery模式进行OTA阶段时，必定会进行对boot/system进行读写(差量更新)，那表明Recovery模式下，SELinux肯定给了权限导致可以读写boot分区，那我或许可以把这个Recovery下的权限拿来一用。
我虽然完全看不懂SELinux上下文的具体内容,但我能搜索`boot_block_device_28_0`和`recovery_block_device_28_0`并得到与这两个相关的行：

`boot_block_device_28_0`如下
```
(typeattributeset dev_type (device_28_0 alarm_device_28_0 ashmem_device_28_0 audio_device_28_0 audio_timer_device_28_0 audio_seq_device_28_0 binder_device_28_0 hwbinder_device_28_0 vndbinder_device_28_0 block_device_28_0 camera_device_28_0 dm_device_28_0 keychord_device_28_0 loop_control_device_28_0 loop_device_28_0 pmsg_device_28_0 radio_device_28_0 ram_device_28_0 rtc_device_28_0 vold_device_28_0 console_device_28_0 cpuctl_device_28_0 fscklogs_28_0 full_device_28_0 gpu_device_28_0 graphics_device_28_0 hw_random_device_28_0 input_device_28_0 kmem_device_28_0 port_device_28_0 lowpan_device_28_0 mtd_device_28_0 mtp_device_28_0 nfc_device_28_0 ptmx_device_28_0 kmsg_device_28_0 kmsg_debug_device_28_0 null_device_28_0 random_device_28_0 secure_element_device_28_0 sensors_device_28_0 serial_device_28_0 socket_device_28_0 owntty_device_28_0 tty_device_28_0 video_device_28_0 vcs_device_28_0 zero_device_28_0 fuse_device_28_0 iio_device_28_0 ion_device_28_0 qtaguid_device_28_0 watchdog_device_28_0 uhid_device_28_0 uio_device_28_0 tun_device_28_0 usbaccessory_device_28_0 usb_device_28_0 properties_device_28_0 properties_serial_28_0 property_info_28_0 i2c_device_28_0 hci_attach_dev_28_0 rpmsg_device_28_0 root_block_device_28_0 frp_block_device_28_0 system_block_device_28_0 recovery_block_device_28_0 boot_block_device_28_0 userdata_block_device_28_0 cache_block_device_28_0 swap_block_device_28_0 metadata_block_device_28_0 misc_block_device_28_0 ppp_device_28_0 tee_device_28_0))
(typeattribute boot_block_device_28_0)
(roletype object_r boot_block_device_28_0)
(neverallow fsck_28_0 boot_block_device_28_0 (blk_file (ioctl read write create setattr lock relabelfrom append unlink link rename open)))
(neverallow fsck_untrusted_28_0 boot_block_device_28_0 (blk_file (ioctl read write create setattr lock relabelfrom append unlink link rename open)))
(allow install_recovery_28_0 boot_block_device_28_0 (blk_file (ioctl read getattr lock map open)))
(allow update_engine_common boot_block_device_28_0 (blk_file (ioctl read write getattr lock append map open)))
```
`recovery_block_device_28_0`如下
```
(typeattributeset dev_type (device_28_0 alarm_device_28_0 ashmem_device_28_0 audio_device_28_0 audio_timer_device_28_0 audio_seq_device_28_0 binder_device_28_0 hwbinder_device_28_0 vndbinder_device_28_0 block_device_28_0 camera_device_28_0 dm_device_28_0 keychord_device_28_0 loop_control_device_28_0 loop_device_28_0 pmsg_device_28_0 radio_device_28_0 ram_device_28_0 rtc_device_28_0 vold_device_28_0 console_device_28_0 cpuctl_device_28_0 fscklogs_28_0 full_device_28_0 gpu_device_28_0 graphics_device_28_0 hw_random_device_28_0 input_device_28_0 kmem_device_28_0 port_device_28_0 lowpan_device_28_0 mtd_device_28_0 mtp_device_28_0 nfc_device_28_0 ptmx_device_28_0 kmsg_device_28_0 kmsg_debug_device_28_0 null_device_28_0 random_device_28_0 secure_element_device_28_0 sensors_device_28_0 serial_device_28_0 socket_device_28_0 owntty_device_28_0 tty_device_28_0 video_device_28_0 vcs_device_28_0 zero_device_28_0 fuse_device_28_0 iio_device_28_0 ion_device_28_0 qtaguid_device_28_0 watchdog_device_28_0 uhid_device_28_0 uio_device_28_0 tun_device_28_0 usbaccessory_device_28_0 usb_device_28_0 properties_device_28_0 properties_serial_28_0 property_info_28_0 i2c_device_28_0 hci_attach_dev_28_0 rpmsg_device_28_0 root_block_device_28_0 frp_block_device_28_0 system_block_device_28_0 recovery_block_device_28_0 boot_block_device_28_0 userdata_block_device_28_0 cache_block_device_28_0 swap_block_device_28_0 metadata_block_device_28_0 misc_block_device_28_0 ppp_device_28_0 tee_device_28_0))
(typeattribute recovery_block_device_28_0)
(roletype object_r recovery_block_device_28_0)
(neverallow base_typeattr_100_28_0 recovery_block_device_28_0 (blk_file (write append)))
(neverallow fsck_28_0 recovery_block_device_28_0 (blk_file (ioctl read write create setattr lock relabelfrom append unlink link rename open)))
(neverallow fsck_untrusted_28_0 recovery_block_device_28_0 (blk_file (ioctl read write create setattr lock relabelfrom append unlink link rename open)))
(allow init_28_0 recovery_block_device_28_0 (lnk_file (relabelto)))
(allow init_28_0 recovery_block_device_28_0 (blk_file (relabelto)))
(allow install_recovery_28_0 recovery_block_device_28_0 (blk_file (ioctl read write getattr lock append map open)))
```
很明显能通过上文发现，recovery_block_device_28_0 与boot_block_device_28_0 都allow了**install_recovery_28_0**这个对象(?)使用对它们进行块文件上的读写等功能，同时对于fsck_28_0、fsck_untrusted_28_0禁止了这部分的操作
再分析一下`install_recovery_28_0`有什么相关的条目
```
(typeattributeset domain (adbd_28_0 audioserver_28_0 blkid_28_0 blkid_untrusted_28_0 bluetooth_28_0 bootanim_28_0 bootstat_28_0 bufferhubd_28_0 cameraserver_28_0 charger_28_0 clatd_28_0 cppreopts_28_0 crash_dump_28_0 dex2oat_28_0 dhcp_28_0 dnsmasq_28_0 drmserver_28_0 dumpstate_28_0 e2fs_28_0 ephemeral_app_28_0 fingerprintd_28_0 fsck_28_0 fsck_untrusted_28_0 gatekeeperd_28_0 healthd_28_0 hwservicemanager_28_0 idmap_28_0 incident_28_0 incident_helper_28_0 incidentd_28_0 init_28_0 inputflinger_28_0 install_recovery_28_0 installd_28_0 isolated_app_28_0 kernel_28_0 keystore_28_0 lmkd_28_0 logd_28_0 logpersist_28_0 mdnsd_28_0 mediacodec_28_0 mediadrmserver_28_0 mediaextractor_28_0 mediametrics_28_0 mediaprovider_28_0 mediaserver_28_0 modprobe_28_0 mtp_28_0 netd_28_0 netutils_wrapper_28_0 nfc_28_0 otapreopt_chroot_28_0 otapreopt_slot_28_0 performanced_28_0 perfprofd_28_0 platform_app_28_0 postinstall_28_0 postinstall_dexopt_28_0 ppp_28_0 preopt2cachename_28_0 priv_app_28_0 profman_28_0 racoon_28_0 radio_28_0 recovery_28_0 recovery_persist_28_0 recovery_refresh_28_0 runas_28_0 sdcardd_28_0 secure_element_28_0 servicemanager_28_0 sgdisk_28_0 shared_relro_28_0 shell_28_0 slideshow_28_0 su_28_0 surfaceflinger_28_0 system_app_28_0 system_server_28_0 tee_28_0 thermalserviced_28_0 tombstoned_28_0 toolbox_28_0 traced_probes_28_0 traceur_app_28_0 tzdatacheck_28_0 ueventd_28_0 uncrypt_28_0 untrusted_app_28_0 untrusted_app_27_28_0 untrusted_app_25_28_0 untrusted_v2_app_28_0 update_engine_28_0 update_verifier_28_0 usbd_28_0 vdc_28_0 vendor_init_28_0 vendor_shell_28_0 virtual_touchpad_28_0 vndservicemanager_28_0 vold_28_0 vold_prepare_subdirs_28_0 vr_hwc_28_0 watchdogd_28_0 webview_zygote_28_0 wificond_28_0 wpantund_28_0 zygote_28_0 aprd_28_0 cndaemon_28_0 dataLogDaemon_28_0 fsmgr_28_0 ims_bridged_28_0 log_service_28_0 minidumpd_28_0 netbox_28_0 performancemanager_28_0 reboot_28_0 cmd_services_28_0 embmsd_28_0 modemlog_connmgr_service_28_0 slogmodem_28_0 ylog_28_0 zebu_28_0))

注：还在这个里面看到了漏洞利用到的cmd_services_28_0，那看来是程序运行时的SELinux上下文相关的

(typeattribute install_recovery_28_0)
(roletype object_r install_recovery_28_0)

(allow install_recovery_28_0 self (capability (dac_override dac_read_search)))
(allow install_recovery_28_0 self (cap_userns (dac_override dac_read_search)))
(allow install_recovery_28_0 shell_exec_28_0 (file (ioctl read getattr lock map execute execute_no_trans open)))
(allow install_recovery_28_0 system_file_28_0 (file (ioctl read getattr lock map execute execute_no_trans open)))
(allow install_recovery_28_0 toolbox_exec_28_0 (file (ioctl read getattr lock map execute execute_no_trans open)))
(allow install_recovery_28_0 block_device_28_0 (dir (search)))
(allow install_recovery_28_0 boot_block_device_28_0 (blk_file (ioctl read getattr lock map open)))
(allow install_recovery_28_0 recovery_block_device_28_0 (blk_file (ioctl read write getattr lock append map open)))
(allow install_recovery_28_0 cache_file_28_0 (dir (ioctl read write getattr lock add_name remove_name search open)))
(allow install_recovery_28_0 cache_file_28_0 (file (ioctl read write create getattr setattr lock append map unlink rename open)))
(allow install_recovery_28_0 proc_drop_caches_28_0 (file (write lock append map open)))

(typeattributeset base_typeattr_157_28_0 ((not (dnsmasq_28_0 dumpstate_28_0 init_28_0 install_recovery_28_0 installd_28_0 lmkd_28_0 netd_28_0 perfprofd_28_0 postinstall_dexopt_28_0 recovery_28_0 sdcardd_28_0 tee_28_0 traced_probes_28_0 ueventd_28_0 uncrypt_28_0 vendor_init_28_0 vold_28_0 vold_prepare_subdirs_28_0 zygote_28_0))))
(typeattributeset base_typeattr_156_28_0 ((not (dnsmasq_28_0 dumpstate_28_0 init_28_0 install_recovery_28_0 installd_28_0 lmkd_28_0 netd_28_0 perfprofd_28_0 postinstall_dexopt_28_0 recovery_28_0 sdcardd_28_0 tee_28_0 ueventd_28_0 uncrypt_28_0 vendor_init_28_0 vold_28_0 vold_prepare_subdirs_28_0 zygote_28_0))))

(typeattributeset base_typeattr_100_28_0 ((and (domain) ((not (install_recovery_28_0 recovery_28_0))))))
```
从上文的这些条目很明显能看出来，install_recovery_28_0是通过把自己排除出base_typeattr_156_28_0，base_typeattr_157_28_0，base_typeattr_100_28_0的同时，allow了一堆权限导致它能够读出boot和recovery分区的
🤓👆，那为何不直接把这些权限和属性复制一份过去给cmd_services_28_0用呢
说干就干，直接在上面排除了install_recovery_28_0的属性里有样学样加上或者直接替换成cmd_services_28_0😋
然后把allow install_recovery_28_0那几行直接复制到文件内容的最后，把这边的install_recovery_28_0改成cmd_services_28_0，保存打包刷回去，成功启动就OK辣😋😋😋

然后就成功用cmd_services_28_0漏洞和这个美美提取出了boot和recovery，后面就是拿[Tomking062大佬写的Github Actions版签名自动化工具](https://github.com/TomKing062/action_big_resign_with_magisk)跑一下提取出来的boot镜像然后再刷回去

恭喜🎉你成功让ud710-ad方案的也赤上了Magisk和模块😋😋