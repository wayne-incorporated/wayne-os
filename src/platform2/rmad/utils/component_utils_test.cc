// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/component_utils.h"

#include <memory>

#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>
#include <hardware_verifier/hardware_verifier.pb.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

namespace rmad {

class ComponentUtilsTest : public testing::Test {
 public:
  ComponentUtilsTest() = default;
  ~ComponentUtilsTest() override = default;
};

TEST_F(ComponentUtilsTest, Battery) {
  constexpr char prototext[] = R"(
    manufacturer: "ABC"
    model_name: "abc"
  )";

  runtime_probe::Battery_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "battery_ABC_abc");
}

TEST_F(ComponentUtilsTest, ComponentFields_Battery) {
  constexpr char prototext[] = R"(
    battery: {
      manufacturer: "ABC"
      model_name: "abc"
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "battery_ABC_abc");
}

TEST_F(ComponentUtilsTest, Storage_MMC) {
  constexpr char prototext[] = R"(
    type: "MMC"
    mmc_manfid: 10
    mmc_name: "abc"
  )";

  runtime_probe::Storage_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "storage(eMMC)_0a_abc");
}

TEST_F(ComponentUtilsTest, ComponentFields_Storage_MMC) {
  constexpr char prototext[] = R"(
    storage: {
      type: "MMC"
      mmc_manfid: 10
      mmc_name: "abc"
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "storage(eMMC)_0a_abc");
}

TEST_F(ComponentUtilsTest, Storage_NVMe) {
  constexpr char prototext[] = R"(
    type: "NVMe"
    pci_vendor: 10
    pci_device: 11
  )";

  runtime_probe::Storage_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "storage(NVMe)_000a_000b");
}

TEST_F(ComponentUtilsTest, ComponentFields_Storage_NVMe) {
  constexpr char prototext[] = R"(
    storage: {
      type: "NVMe"
      pci_vendor: 10
      pci_device: 11
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "storage(NVMe)_000a_000b");
}

TEST_F(ComponentUtilsTest, Storage_ATA) {
  constexpr char prototext[] = R"(
    type: "ATA"
    ata_vendor: "ABC"
    ata_model: "abc"
  )";

  runtime_probe::Storage_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "storage(SATA)_ABC_abc");
}

TEST_F(ComponentUtilsTest, ComponentFields_Storage_ATA) {
  constexpr char prototext[] = R"(
    storage: {
      type: "ATA"
      ata_vendor: "ABC"
      ata_model: "abc"
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "storage(SATA)_ABC_abc");
}

TEST_F(ComponentUtilsTest, Storage_Unknown) {
  constexpr char prototext[] = R"(
    type: "abc"
  )";

  runtime_probe::Storage_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "storage(unknown)");
}

TEST_F(ComponentUtilsTest, ComponentFields_Storage_Unknown) {
  constexpr char prototext[] = R"(
    storage: {
      type: "abc"
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "storage(unknown)");
}

TEST_F(ComponentUtilsTest, Camera) {
  constexpr char prototext[] = R"(
    usb_vendor_id: 10
    usb_product_id: 11
  )";

  runtime_probe::Camera_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "camera_000a_000b");
}

TEST_F(ComponentUtilsTest, ComponentFields_Camera) {
  constexpr char prototext[] = R"(
    camera: {
      usb_vendor_id: 10
      usb_product_id: 11
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "camera_000a_000b");
}

TEST_F(ComponentUtilsTest, InputDevice_Stylus) {
  constexpr char prototext[] = R"(
    device_type: TYPE_STYLUS
    vendor: 10
    product: 11
  )";

  runtime_probe::InputDevice_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "stylus_000a_000b");
}

TEST_F(ComponentUtilsTest, ComponentFields_InputDevice_Stylus) {
  constexpr char prototext[] = R"(
    stylus: {
      device_type: TYPE_STYLUS
      vendor: 10
      product: 11
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "stylus_000a_000b");
}

TEST_F(ComponentUtilsTest, InputDevice_Touchpad) {
  constexpr char prototext[] = R"(
    device_type: TYPE_TOUCHPAD
    vendor: 10
    product: 11
  )";

  runtime_probe::InputDevice_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "touchpad_000a_000b");
}

TEST_F(ComponentUtilsTest, ComponentFields_InputDevice_Touchpad) {
  constexpr char prototext[] = R"(
    touchpad: {
      device_type: TYPE_TOUCHPAD
      vendor: 10
      product: 11
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "touchpad_000a_000b");
}

TEST_F(ComponentUtilsTest, InputDevice_Touchscreen) {
  constexpr char prototext[] = R"(
    device_type: TYPE_TOUCHSCREEN
    vendor: 10
    product: 11
  )";

  runtime_probe::InputDevice_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "touchscreen_000a_000b");
}

TEST_F(ComponentUtilsTest, ComponentFields_InputDevice_Touchscreen) {
  constexpr char prototext[] = R"(
    touchscreen: {
      device_type: TYPE_TOUCHSCREEN
      vendor: 10
      product: 11
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "touchscreen_000a_000b");
}

TEST_F(ComponentUtilsTest, InputDevice_Unknown) {
  constexpr char prototext[] = R"(
    device_type: TYPE_UNKNOWN
  )";

  runtime_probe::InputDevice_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "input_device(unknown)");
}

TEST_F(ComponentUtilsTest, ComponentFields_InputDevice_Unknown) {
  constexpr char prototext[] = R"(
    stylus: {
      device_type: TYPE_UNKNOWN
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "input_device(unknown)");
}

TEST_F(ComponentUtilsTest, Memory) {
  constexpr char prototext[] = R"(
    part: "ABC"
  )";

  runtime_probe::Memory_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "dram_ABC");
}

TEST_F(ComponentUtilsTest, ComponentFields_Memory) {
  constexpr char prototext[] = R"(
    dram: {
      part: "ABC"
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "dram_ABC");
}

TEST_F(ComponentUtilsTest, Display) {
  constexpr char prototext[] = R"(
    vendor: "ABC"
    product_id: 10
  )";

  runtime_probe::Edid_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "display_ABC_000a");
}

TEST_F(ComponentUtilsTest, ComponentFields_Display) {
  constexpr char prototext[] = R"(
    display_panel: {
      vendor: "ABC"
      product_id: 10
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "display_ABC_000a");
}

TEST_F(ComponentUtilsTest, Network_Pci) {
  constexpr char prototext[] = R"(
    bus_type: "pci"
    type: "cellular"
    pci_vendor_id: 10
    pci_device_id: 11
  )";

  runtime_probe::Network_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields),
            "network(cellular:pci)_000a_000b");
}

TEST_F(ComponentUtilsTest, ComponentFields_Network_Pci) {
  constexpr char prototext[] = R"(
    cellular: {
      bus_type: "pci"
      type: "cellular"
      pci_vendor_id: 10
      pci_device_id: 11
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields),
            "network(cellular:pci)_000a_000b");
}

TEST_F(ComponentUtilsTest, Network_Usb) {
  constexpr char prototext[] = R"(
    bus_type: "usb"
    type: "ethernet"
    usb_vendor_id: 10
    usb_product_id: 11
  )";

  runtime_probe::Network_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields),
            "network(ethernet:usb)_000a_000b");
}

TEST_F(ComponentUtilsTest, ComponentFields_Network_Usb) {
  constexpr char prototext[] = R"(
    ethernet: {
      bus_type: "usb"
      type: "ethernet"
      usb_vendor_id: 10
      usb_product_id: 11
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields),
            "network(ethernet:usb)_000a_000b");
}

TEST_F(ComponentUtilsTest, Network_Sdio) {
  constexpr char prototext[] = R"(
    bus_type: "sdio"
    type: "wireless"
    sdio_vendor_id: 10
    sdio_device_id: 11
  )";

  runtime_probe::Network_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields),
            "network(wireless:sdio)_000a_000b");
}

TEST_F(ComponentUtilsTest, ComponentFields_Network_Sdio) {
  constexpr char prototext[] = R"(
    wireless: {
      bus_type: "sdio"
      type: "wireless"
      sdio_vendor_id: 10
      sdio_device_id: 11
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields),
            "network(wireless:sdio)_000a_000b");
}

TEST_F(ComponentUtilsTest, Network_Unknown) {
  constexpr char prototext[] = R"(
    bus_type: "abc"
    type: "cellular"
  )";

  runtime_probe::Network_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "network(cellular:unknown)");
}

TEST_F(ComponentUtilsTest, ComponentFields_Network_Unknown) {
  constexpr char prototext[] = R"(
    cellular: {
      bus_type: "abc"
      type: "cellular"
    }
  )";

  runtime_probe::ComponentFields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "network(cellular:unknown)");
}

TEST_F(ComponentUtilsTest, ComponentFields_Unknown) {
  runtime_probe::ComponentFields fields;
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "unknown_component");
}

TEST_F(ComponentUtilsTest, ApI2c) {
  constexpr char prototext[] = R"(
    data: 1
  )";

  runtime_probe::ApI2c_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "api2c_0001");
}

TEST_F(ComponentUtilsTest, Component_ApI2c) {
  constexpr char prototext[] = R"(
    values: {
      data: 1
    }
  )";

  runtime_probe::ApI2c ap_i2c;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &ap_i2c));
  EXPECT_EQ(GetComponentIdentifier(ap_i2c), "api2c_0001");
}

TEST_F(ComponentUtilsTest, EcI2c) {
  constexpr char prototext[] = R"(
    data: 1
  )";

  runtime_probe::EcI2c_Fields fields;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &fields));
  EXPECT_EQ(GetComponentFieldsIdentifier(fields), "eci2c_0001");
}

TEST_F(ComponentUtilsTest, Component_EcI2c) {
  constexpr char prototext[] = R"(
    values: {
      data: 1
    }
  )";

  runtime_probe::EcI2c ec_i2c;
  EXPECT_TRUE(
      google::protobuf::TextFormat::ParseFromString(prototext, &ec_i2c));
  EXPECT_EQ(GetComponentIdentifier(ec_i2c), "eci2c_0001");
}

}  // namespace rmad
