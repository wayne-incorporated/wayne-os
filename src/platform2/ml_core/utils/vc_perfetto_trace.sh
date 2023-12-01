#!/bin/bash

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Use this file to generate a perfetto trace file for analysis.
# Includes Intel GPU counters

perfetto \
  -c - --txt \
  -o /tmp/trace \
<<EOF

buffers: {
    size_kb: 260096
    fill_policy: DISCARD
}
buffers: {
    size_kb: 2048
    fill_policy: DISCARD
}
data_sources: {
    config {
        name: "android.gpu.memory"
    }
}
data_sources: {
    config {
        name: "android.power"
        android_power_config {
            battery_poll_ms: 1000
            battery_counters: BATTERY_COUNTER_CAPACITY_PERCENT
            battery_counters: BATTERY_COUNTER_CHARGE
            battery_counters: BATTERY_COUNTER_CURRENT
            collect_power_rails: true
        }
    }
}
data_sources: {
    config {
        name: "linux.process_stats"
        target_buffer: 1
        process_stats_config {
            scan_all_processes_on_start: true
            proc_stats_poll_ms: 1000
        }
    }
}
data_sources: {
    config {
        name: "android.log"
        android_log_config {
        }
    }
}
data_sources: {
    config {
        name: "org.chromium.trace_event"
        chrome_config {
            trace_config: "{\"record_mode\":\"record-until-full\",\"included_categories\":[\"accessibility\",\"AccountFetcherService\",\"android_webview\",\"aogh\",\"audio\",\"base\",\"benchmark\",\"blink\",\"blink.animations\",\"blink.bindings\",\"blink.console\",\"blink.net\",\"blink.resource\",\"blink.user_timing\",\"blink.worker\",\"blink_gc\",\"blink_style\",\"Blob\",\"browser\",\"browsing_data\",\"CacheStorage\",\"Calculators\",\"CameraStream\",\"camera\",\"cast_app\",\"cast_perf_test\",\"cast.mdns\",\"cast.mdns.socket\",\"cast.stream\",\"cc\",\"cc.debug\",\"cdp.perf\",\"chromeos\",\"cma\",\"compositor\",\"content\",\"content_capture\",\"device\",\"devtools\",\"devtools.contrast\",\"devtools.timeline\",\"disk_cache\",\"download\",\"download_service\",\"drm\",\"drmcursor\",\"dwrite\",\"DXVA_Decoding\",\"evdev\",\"event\",\"exo\",\"extensions\",\"explore_sites\",\"FileSystem\",\"file_system_provider\",\"fonts\",\"GAMEPAD\",\"gpu\",\"gpu.angle\",\"gpu.capture\",\"headless\",\"hwoverlays\",\"identity\",\"ime\",\"IndexedDB\",\"input\",\"io\",\"ipc\",\"Java\",\"jni\",\"jpeg\",\"latency\",\"latencyInfo\",\"leveldb\",\"loading\",\"log\",\"login\",\"media\",\"media_router\",\"memory\",\"midi\",\"mojom\",\"mus\",\"native\",\"navigation\",\"net\",\"netlog\",\"offline_pages\",\"omnibox\",\"oobe\",\"ozone\",\"partition_alloc\",\"passwords\",\"p2p\",\"page-serialization\",\"paint_preview\",\"pepper\",\"PlatformMalloc\",\"power\",\"ppapi\",\"ppapi_proxy\",\"print\",\"rail\",\"renderer\",\"renderer_host\",\"renderer.scheduler\",\"RLZ\",\"safe_browsing\",\"screenlock_monitor\",\"segmentation_platform\",\"sequence_manager\",\"service_manager\",\"ServiceWorker\",\"sharing\",\"shell\",\"shortcut_viewer\",\"shutdown\",\"SiteEngagement\",\"skia\",\"sql\",\"stadia_media\",\"stadia_rtc\",\"startup\",\"sync\",\"system_apps\",\"test_gpu\",\"thread_pool\",\"toplevel\",\"toplevel.flow\",\"ui\",\"v8\",\"v8.execute\",\"v8.wasm\",\"ValueStoreFrontend::Backend\",\"views\",\"views.frame\",\"viz\",\"vk\",\"wayland\",\"webaudio\",\"weblayer\",\"WebCore\",\"webrtc\",\"xr\"],\"memory_dump_config\":{}}"
        }
    }
}
data_sources: {
    config {
        name: "org.chromium.trace_metadata"
        chrome_config {
            trace_config: "{\"record_mode\":\"record-until-full\",\"included_categories\":[\"accessibility\",\"AccountFetcherService\",\"android_webview\",\"aogh\",\"audio\",\"base\",\"benchmark\",\"blink\",\"blink.animations\",\"blink.bindings\",\"blink.console\",\"blink.net\",\"blink.resource\",\"blink.user_timing\",\"blink.worker\",\"blink_gc\",\"blink_style\",\"Blob\",\"browser\",\"browsing_data\",\"CacheStorage\",\"Calculators\",\"CameraStream\",\"camera\",\"cast_app\",\"cast_perf_test\",\"cast.mdns\",\"cast.mdns.socket\",\"cast.stream\",\"cc\",\"cc.debug\",\"cdp.perf\",\"chromeos\",\"cma\",\"compositor\",\"content\",\"content_capture\",\"device\",\"devtools\",\"devtools.contrast\",\"devtools.timeline\",\"disk_cache\",\"download\",\"download_service\",\"drm\",\"drmcursor\",\"dwrite\",\"DXVA_Decoding\",\"evdev\",\"event\",\"exo\",\"extensions\",\"explore_sites\",\"FileSystem\",\"file_system_provider\",\"fonts\",\"GAMEPAD\",\"gpu\",\"gpu.angle\",\"gpu.capture\",\"headless\",\"hwoverlays\",\"identity\",\"ime\",\"IndexedDB\",\"input\",\"io\",\"ipc\",\"Java\",\"jni\",\"jpeg\",\"latency\",\"latencyInfo\",\"leveldb\",\"loading\",\"log\",\"login\",\"media\",\"media_router\",\"memory\",\"midi\",\"mojom\",\"mus\",\"native\",\"navigation\",\"net\",\"netlog\",\"offline_pages\",\"omnibox\",\"oobe\",\"ozone\",\"partition_alloc\",\"passwords\",\"p2p\",\"page-serialization\",\"paint_preview\",\"pepper\",\"PlatformMalloc\",\"power\",\"ppapi\",\"ppapi_proxy\",\"print\",\"rail\",\"renderer\",\"renderer_host\",\"renderer.scheduler\",\"RLZ\",\"safe_browsing\",\"screenlock_monitor\",\"segmentation_platform\",\"sequence_manager\",\"service_manager\",\"ServiceWorker\",\"sharing\",\"shell\",\"shortcut_viewer\",\"shutdown\",\"SiteEngagement\",\"skia\",\"sql\",\"stadia_media\",\"stadia_rtc\",\"startup\",\"sync\",\"system_apps\",\"test_gpu\",\"thread_pool\",\"toplevel\",\"toplevel.flow\",\"ui\",\"v8\",\"v8.execute\",\"v8.wasm\",\"ValueStoreFrontend::Backend\",\"views\",\"views.frame\",\"viz\",\"vk\",\"wayland\",\"webaudio\",\"weblayer\",\"WebCore\",\"webrtc\",\"xr\"],\"memory_dump_config\":{}}"
        }
    }
}
data_sources: {
    config {
        name: "linux.sys_stats"
        sys_stats_config {
            stat_period_ms: 1000
            stat_counters: STAT_CPU_TIMES
            stat_counters: STAT_FORK_COUNT
        }
    }
}
data_sources: {
    config {
        name: "linux.ftrace"
        ftrace_config {
            ftrace_events: "sched/sched_switch"
            ftrace_events: "power/suspend_resume"
            ftrace_events: "sched/sched_wakeup"
            ftrace_events: "sched/sched_wakeup_new"
            ftrace_events: "sched/sched_waking"
            ftrace_events: "power/cpu_frequency"
            ftrace_events: "power/cpu_idle"
            ftrace_events: "power/gpu_frequency"
            ftrace_events: "gpu_mem/gpu_mem_total"
            ftrace_events: "regulator/regulator_set_voltage"
            ftrace_events: "regulator/regulator_set_voltage_complete"
            ftrace_events: "power/clock_enable"
            ftrace_events: "power/clock_disable"
            ftrace_events: "power/clock_set_rate"
            ftrace_events: "sched/sched_process_exit"
            ftrace_events: "sched/sched_process_free"
            ftrace_events: "task/task_newtask"
            ftrace_events: "task/task_rename"
            ftrace_events: "ftrace/print"
            atrace_apps: "*"
            buffer_size_kb: 2048
            drain_period_ms: 250
        }
    }
}
data_sources {
    config {
        name: "track_event"
        target_buffer: 0
    }
}
data_sources {
    config {
        name: "gpu.counters.i915"
        target_buffer: 0
    }
}
data_sources {
    config {
        name: "gpu.renderstages.intel"
        target_buffer: 0
    }
}
duration_ms: 10000

EOF
