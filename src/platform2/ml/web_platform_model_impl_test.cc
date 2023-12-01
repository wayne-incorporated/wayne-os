// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/memory/read_only_shared_memory_region.h>
#include <base/run_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "ml/mojom/big_buffer.mojom.h"
#include "ml/process.h"
#include "ml/test_utils.h"
#include "ml/web_platform_model_impl.h"

namespace ml {

// When the input BigBuffer is invalid buffer.
TEST(WebPlatformModelTest, InvalidBuffer) {
  // Set the mlservice to single process mode for testing here.
  Process::GetInstance()->SetTypeForTesting(
      Process::Type::kSingleProcessForTest);

  auto options = model_loader::mojom::CreateModelLoaderOptions::New();

  mojo::Remote<model_loader::mojom::ModelLoader> loader;

  WebPlatformModelLoaderImpl::Create(loader.BindNewPipeAndPassReceiver(),
                                     std::move(options));

  auto buffer = mojo_base::mojom::BigBuffer::NewInvalidBuffer(true);
  bool model_callback_done = false;
  loader->Load(
      std::move(buffer),
      base::BindOnce(
          [](bool* model_callback_done,
             model_loader::mojom::LoadModelResult result,
             mojo::PendingRemote<model_loader::mojom::Model> pending_remote,
             model_loader::mojom::ModelInfoPtr model_info) {
            EXPECT_EQ(result,
                      model_loader::mojom::LoadModelResult::kUnknownError);
            EXPECT_FALSE(pending_remote.is_valid());
            EXPECT_TRUE(model_info.is_null());

            *model_callback_done = true;
          },
          &model_callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(model_callback_done);
}

// When the input BigBuffer is "bytes" and is empty.
TEST(WebPlatformModelTest, LoadEmptyBytes) {
  // Set the mlservice to single process mode for testing here.
  Process::GetInstance()->SetTypeForTesting(
      Process::Type::kSingleProcessForTest);

  auto options = model_loader::mojom::CreateModelLoaderOptions::New();

  mojo::Remote<model_loader::mojom::ModelLoader> loader;

  WebPlatformModelLoaderImpl::Create(loader.BindNewPipeAndPassReceiver(),
                                     std::move(options));
  auto buffer = mojo_base::mojom::BigBuffer::NewBytes(std::vector<uint8_t>());

  bool model_callback_done = false;
  loader->Load(
      std::move(buffer),
      base::BindOnce(
          [](bool* model_callback_done,
             model_loader::mojom::LoadModelResult result,
             mojo::PendingRemote<model_loader::mojom::Model> pending_remote,
             model_loader::mojom::ModelInfoPtr model_info) {
            EXPECT_EQ(result,
                      model_loader::mojom::LoadModelResult::kInvalidModel);
            EXPECT_FALSE(pending_remote.is_valid());
            EXPECT_TRUE(model_info.is_null());

            *model_callback_done = true;
          },
          &model_callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(model_callback_done);
}

// When the input BigBuffer is "bytes" and is a wrong model.
TEST(WebPlatformModelTest, LoadBadBytes) {
  // Set the mlservice to single process mode for testing here.
  Process::GetInstance()->SetTypeForTesting(
      Process::Type::kSingleProcessForTest);

  auto options = model_loader::mojom::CreateModelLoaderOptions::New();

  mojo::Remote<model_loader::mojom::ModelLoader> loader;

  WebPlatformModelLoaderImpl::Create(loader.BindNewPipeAndPassReceiver(),
                                     std::move(options));
  auto buffer = mojo_base::mojom::BigBuffer::NewBytes(
      std::vector<uint8_t>({1, 2, 3}));  // a wrong model.

  bool model_callback_done = false;
  loader->Load(
      std::move(buffer),
      base::BindOnce(
          [](bool* model_callback_done,
             model_loader::mojom::LoadModelResult result,
             mojo::PendingRemote<model_loader::mojom::Model> pending_remote,
             model_loader::mojom::ModelInfoPtr model_info) {
            EXPECT_EQ(result,
                      model_loader::mojom::LoadModelResult::kInvalidModel);
            EXPECT_FALSE(pending_remote.is_valid());
            EXPECT_TRUE(model_info.is_null());

            *model_callback_done = true;
          },
          &model_callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(model_callback_done);
}

// When the input BigBuffer is "shared_buffer" and is a wrong model.
TEST(WebPlatformModelTest, LoadBadSharedBuffer) {
  // Set the mlservice to single process mode for testing here.
  Process::GetInstance()->SetTypeForTesting(
      Process::Type::kSingleProcessForTest);

  auto options = model_loader::mojom::CreateModelLoaderOptions::New();

  mojo::Remote<model_loader::mojom::ModelLoader> loader;

  WebPlatformModelLoaderImpl::Create(loader.BindNewPipeAndPassReceiver(),
                                     std::move(options));

  auto shared_region = base::WritableSharedMemoryRegion::Create(3);
  ASSERT_TRUE(shared_region.IsValid());

  auto shared_map = shared_region.Map();
  ASSERT_TRUE(shared_map.IsValid());

  // An arbitrary invalid model.
  shared_map.GetMemoryAs<char>()[0] = 'a';
  shared_map.GetMemoryAs<char>()[1] = 'b';
  shared_map.GetMemoryAs<char>()[2] = 'c';

  auto shared_memory = mojo_base::mojom::BigBufferSharedMemoryRegion::New();
  shared_memory->buffer_handle =
      mojo::WrapWritableSharedMemoryRegion(std::move(shared_region));
  shared_memory->size = 0;

  auto big_buffer =
      mojo_base::mojom::BigBuffer::NewSharedMemory(std::move(shared_memory));

  bool model_callback_done = false;
  loader->Load(
      std::move(big_buffer),
      base::BindOnce(
          [](bool* model_callback_done,
             model_loader::mojom::LoadModelResult result,
             mojo::PendingRemote<model_loader::mojom::Model> pending_remote,
             model_loader::mojom::ModelInfoPtr model_info) {
            EXPECT_EQ(result,
                      model_loader::mojom::LoadModelResult::kInvalidModel);
            EXPECT_FALSE(pending_remote.is_valid());
            EXPECT_TRUE(model_info.is_null());
            *model_callback_done = true;
          },
          &model_callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(model_callback_done);
}

// When the input BigBuffer is "shared_buffer" and is the test model.
// Loads the model and does computations.
TEST(WebPlatformModelTest, LoadAndComputeWithSharedBufferInput) {
  // Set the mlservice to single process mode for testing here.
  Process::GetInstance()->SetTypeForTesting(
      Process::Type::kSingleProcessForTest);

  auto options = model_loader::mojom::CreateModelLoaderOptions::New();

  mojo::Remote<model_loader::mojom::ModelLoader> loader;

  WebPlatformModelLoaderImpl::Create(loader.BindNewPipeAndPassReceiver(),
                                     std::move(options));

  // Reads the testing model.
  std::string model_string;
  base::ReadFileToString(
      base::FilePath(GetTestModelDir() +
                     "mlservice-model-test_add-20180914.tflite"),
      &model_string);

  auto shared_region =
      base::WritableSharedMemoryRegion::Create(model_string.size());
  ASSERT_TRUE(shared_region.IsValid());

  auto shared_map = shared_region.Map();
  ASSERT_TRUE(shared_map.IsValid());

  memcpy(shared_map.GetMemoryAs<char>(), model_string.c_str(),
         model_string.size());

  auto shared_memory = mojo_base::mojom::BigBufferSharedMemoryRegion::New();
  shared_memory->buffer_handle =
      mojo::WrapWritableSharedMemoryRegion(std::move(shared_region));
  shared_memory->size = model_string.size();

  auto big_buffer =
      mojo_base::mojom::BigBuffer::NewSharedMemory(std::move(shared_memory));

  mojo::Remote<model_loader::mojom::Model> model;

  bool model_callback_done = false;
  loader->Load(
      std::move(big_buffer),
      base::BindOnce(
          [](bool* model_callback_done,
             mojo::Remote<model_loader::mojom::Model>* model_remote,
             model_loader::mojom::LoadModelResult result,
             mojo::PendingRemote<model_loader::mojom::Model> pending_remote,
             model_loader::mojom::ModelInfoPtr model_info) {
            ASSERT_EQ(result, model_loader::mojom::LoadModelResult::kOk);
            EXPECT_TRUE(pending_remote.is_valid());

            // Checks the inputs/outputs are recognized correctly.
            ASSERT_FALSE(model_info.is_null());
            ASSERT_EQ(model_info->input_tensor_info.size(), 2u);
            ASSERT_TRUE(model_info->input_tensor_info.find("x") !=
                        model_info->input_tensor_info.end());
            EXPECT_EQ(model_info->input_tensor_info["x"]->byte_size, 4u);
            EXPECT_EQ(model_info->input_tensor_info["x"]->data_type,
                      model_loader::mojom::DataType::kFloat32);
            ASSERT_EQ(model_info->input_tensor_info["x"]->dimensions.size(),
                      1u);
            EXPECT_EQ(model_info->input_tensor_info["x"]->dimensions[0], 1u);

            ASSERT_TRUE(model_info->input_tensor_info.find("y") !=
                        model_info->input_tensor_info.end());
            EXPECT_EQ(model_info->input_tensor_info["y"]->byte_size, 4u);
            EXPECT_EQ(model_info->input_tensor_info["y"]->data_type,
                      model_loader::mojom::DataType::kFloat32);
            ASSERT_EQ(model_info->input_tensor_info["y"]->dimensions.size(),
                      1u);
            EXPECT_EQ(model_info->input_tensor_info["y"]->dimensions[0], 1u);

            ASSERT_EQ(model_info->output_tensor_info.size(), 1u);

            ASSERT_TRUE(model_info->output_tensor_info.find("Add") !=
                        model_info->output_tensor_info.end());
            EXPECT_EQ(model_info->output_tensor_info["Add"]->byte_size, 4u);
            EXPECT_EQ(model_info->output_tensor_info["Add"]->data_type,
                      model_loader::mojom::DataType::kFloat32);
            ASSERT_EQ(model_info->output_tensor_info["Add"]->dimensions.size(),
                      1u);
            EXPECT_EQ(model_info->output_tensor_info["Add"]->dimensions[0], 1u);

            model_remote->Bind(std::move(pending_remote));

            *model_callback_done = true;
          },
          &model_callback_done, &model));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(model_callback_done);

  {
    // Computes with valid inputs.
    base::flat_map<std::string, std::vector<uint8_t>> inputs;
    inputs["x"].resize(4);
    const float x = 1.23;
    memcpy(inputs["x"].data(), &x, 4);

    inputs["y"].resize(4);
    const float y = 4.56;
    memcpy(inputs["y"].data(), &y, 4);

    bool compute_callback_done = false;
    model->Compute(
        std::move(inputs),
        base::BindOnce(
            [](bool* compute_callback_done,
               model_loader::mojom::ComputeResult result,
               const std::optional<base::flat_map<
                   std::string, std::vector<uint8_t>>>& output_tensors) {
              ASSERT_EQ(result, model_loader::mojom::ComputeResult::kOk);
              ASSERT_TRUE(output_tensors.has_value());
              ASSERT_EQ(output_tensors.value().size(), 1u);
              ASSERT_TRUE(output_tensors.value().find("Add") !=
                          output_tensors.value().end());
              EXPECT_NEAR(
                  *reinterpret_cast<const float*>(
                      output_tensors.value().find("Add")->second.data()),
                  1.23 + 4.56, 1e-4);

              *compute_callback_done = true;
            },
            &compute_callback_done));

    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(compute_callback_done);
  }

  {
    // Computes with missing input.
    base::flat_map<std::string, std::vector<uint8_t>> inputs;
    inputs["x"].resize(4);
    const float x = 1.23;
    memcpy(inputs["x"].data(), &x, 4);

    // "y" is missing.

    bool compute_callback_done = false;
    model->Compute(
        std::move(inputs),
        base::BindOnce(
            [](bool* compute_callback_done,
               model_loader::mojom::ComputeResult result,
               const std::optional<base::flat_map<
                   std::string, std::vector<uint8_t>>>& output_tensors) {
              ASSERT_EQ(
                  result,
                  model_loader::mojom::ComputeResult::kIncorrectNumberOfInputs);
              ASSERT_FALSE(output_tensors.has_value());

              *compute_callback_done = true;
            },
            &compute_callback_done));

    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(compute_callback_done);
  }

  {
    // Computes with wrong input tensor name.
    base::flat_map<std::string, std::vector<uint8_t>> inputs;
    inputs["x"].resize(4);
    const float x = 1.23;
    memcpy(inputs["x"].data(), &x, 4);

    inputs["yy"].resize(4);
    const float yy = 4.56;
    memcpy(inputs["yy"].data(), &yy, 4);

    bool compute_callback_done = false;
    model->Compute(
        std::move(inputs),
        base::BindOnce(
            [](bool* compute_callback_done,
               model_loader::mojom::ComputeResult result,
               const std::optional<base::flat_map<
                   std::string, std::vector<uint8_t>>>& output_tensors) {
              ASSERT_EQ(result,
                        model_loader::mojom::ComputeResult::kMissingInput);
              ASSERT_FALSE(output_tensors.has_value());

              *compute_callback_done = true;
            },
            &compute_callback_done));

    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(compute_callback_done);
  }

  {
    // Compute with wrong input tensor buffer size.
    base::flat_map<std::string, std::vector<uint8_t>> inputs;
    inputs["x"].resize(4);
    const float x = 1.23;
    memcpy(inputs["x"].data(), &x, 4);

    inputs["y"].resize(4);
    const float y = 4.56;
    memcpy(inputs["y"].data(), &y, 4);

    // Make "y" buffer of wrong size;
    inputs["y"].resize(2);

    bool compute_callback_done = false;
    model->Compute(
        std::move(inputs),
        base::BindOnce(
            [](bool* compute_callback_done,
               model_loader::mojom::ComputeResult result,
               const std::optional<base::flat_map<
                   std::string, std::vector<uint8_t>>>& output_tensors) {
              ASSERT_EQ(
                  result,
                  model_loader::mojom::ComputeResult::kInvalidInputBufferSize);
              ASSERT_FALSE(output_tensors.has_value());

              *compute_callback_done = true;
            },
            &compute_callback_done));

    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(compute_callback_done);
  }
}

// When the input BigBuffer is "bytes" and is the test model.
// Loads the model and does computations.
TEST(WebPlatformModelTest, LoadAndComputeWithBytesInput) {
  // Set the mlservice to single process mode for testing here.
  Process::GetInstance()->SetTypeForTesting(
      Process::Type::kSingleProcessForTest);

  auto options = model_loader::mojom::CreateModelLoaderOptions::New();

  mojo::Remote<model_loader::mojom::ModelLoader> loader;

  WebPlatformModelLoaderImpl::Create(loader.BindNewPipeAndPassReceiver(),
                                     std::move(options));

  // Reads the testing model.
  std::string model_string;
  base::ReadFileToString(
      base::FilePath(GetTestModelDir() +
                     "mlservice-model-test_add-20180914.tflite"),
      &model_string);

  std::vector<uint8_t> model_vector(model_string.size());
  memcpy(model_vector.data(), model_string.c_str(), model_string.size());

  auto buffer = mojo_base::mojom::BigBuffer::NewBytes(std::move(model_vector));

  mojo::Remote<model_loader::mojom::Model> model;

  bool model_callback_done = false;
  loader->Load(
      std::move(buffer),
      base::BindOnce(
          [](bool* model_callback_done,
             mojo::Remote<model_loader::mojom::Model>* model_remote,
             model_loader::mojom::LoadModelResult result,
             mojo::PendingRemote<model_loader::mojom::Model> pending_remote,
             model_loader::mojom::ModelInfoPtr model_info) {
            ASSERT_EQ(result, model_loader::mojom::LoadModelResult::kOk);
            EXPECT_TRUE(pending_remote.is_valid());

            // Checks the inputs/outputs are recognized correctly.
            ASSERT_FALSE(model_info.is_null());
            ASSERT_EQ(model_info->input_tensor_info.size(), 2u);
            ASSERT_TRUE(model_info->input_tensor_info.find("x") !=
                        model_info->input_tensor_info.end());
            EXPECT_EQ(model_info->input_tensor_info["x"]->byte_size, 4u);
            EXPECT_EQ(model_info->input_tensor_info["x"]->data_type,
                      model_loader::mojom::DataType::kFloat32);
            ASSERT_EQ(model_info->input_tensor_info["x"]->dimensions.size(),
                      1u);
            EXPECT_EQ(model_info->input_tensor_info["x"]->dimensions[0], 1u);

            ASSERT_TRUE(model_info->input_tensor_info.find("y") !=
                        model_info->input_tensor_info.end());
            EXPECT_EQ(model_info->input_tensor_info["y"]->byte_size, 4u);
            EXPECT_EQ(model_info->input_tensor_info["y"]->data_type,
                      model_loader::mojom::DataType::kFloat32);
            ASSERT_EQ(model_info->input_tensor_info["y"]->dimensions.size(),
                      1u);
            EXPECT_EQ(model_info->input_tensor_info["y"]->dimensions[0], 1u);

            ASSERT_EQ(model_info->output_tensor_info.size(), 1u);

            ASSERT_TRUE(model_info->output_tensor_info.find("Add") !=
                        model_info->output_tensor_info.end());
            EXPECT_EQ(model_info->output_tensor_info["Add"]->byte_size, 4u);
            EXPECT_EQ(model_info->output_tensor_info["Add"]->data_type,
                      model_loader::mojom::DataType::kFloat32);
            ASSERT_EQ(model_info->output_tensor_info["Add"]->dimensions.size(),
                      1u);
            EXPECT_EQ(model_info->output_tensor_info["Add"]->dimensions[0], 1u);

            model_remote->Bind(std::move(pending_remote));

            *model_callback_done = true;
          },
          &model_callback_done, &model));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(model_callback_done);

  {
    // Computes with valid inputs.
    base::flat_map<std::string, std::vector<uint8_t>> inputs;
    inputs["x"].resize(4);
    const float x = 3.21;
    memcpy(inputs["x"].data(), &x, 4);

    inputs["y"].resize(4);
    const float y = 6.54;
    memcpy(inputs["y"].data(), &y, 4);

    bool compute_callback_done = false;
    model->Compute(
        std::move(inputs),
        base::BindOnce(
            [](bool* compute_callback_done,
               model_loader::mojom::ComputeResult result,
               const std::optional<base::flat_map<
                   std::string, std::vector<uint8_t>>>& output_tensors) {
              ASSERT_EQ(result, model_loader::mojom::ComputeResult::kOk);
              ASSERT_TRUE(output_tensors.has_value());
              ASSERT_EQ(output_tensors.value().size(), 1u);
              ASSERT_TRUE(output_tensors.value().find("Add") !=
                          output_tensors.value().end());
              EXPECT_NEAR(
                  *reinterpret_cast<const float*>(
                      output_tensors.value().find("Add")->second.data()),
                  3.21 + 6.54, 1e-4);

              *compute_callback_done = true;
            },
            &compute_callback_done));

    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(compute_callback_done);
  }

  {
    // Computes with missing input.
    base::flat_map<std::string, std::vector<uint8_t>> inputs;
    // "x" is missing.
    inputs["y"].resize(4);
    const float y = 3.21;
    memcpy(inputs["y"].data(), &y, 4);

    bool compute_callback_done = false;
    model->Compute(
        std::move(inputs),
        base::BindOnce(
            [](bool* compute_callback_done,
               model_loader::mojom::ComputeResult result,
               const std::optional<base::flat_map<
                   std::string, std::vector<uint8_t>>>& output_tensors) {
              ASSERT_EQ(
                  result,
                  model_loader::mojom::ComputeResult::kIncorrectNumberOfInputs);
              ASSERT_FALSE(output_tensors.has_value());

              *compute_callback_done = true;
            },
            &compute_callback_done));

    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(compute_callback_done);
  }

  {
    // Computes with wrong input tensor name.
    base::flat_map<std::string, std::vector<uint8_t>> inputs;
    inputs["xx"].resize(4);
    const float xx = 3.21;
    memcpy(inputs["xx"].data(), &xx, 4);

    inputs["y"].resize(4);
    const float y = 6.54;
    memcpy(inputs["y"].data(), &y, 4);

    bool compute_callback_done = false;
    model->Compute(
        std::move(inputs),
        base::BindOnce(
            [](bool* compute_callback_done,
               model_loader::mojom::ComputeResult result,
               const std::optional<base::flat_map<
                   std::string, std::vector<uint8_t>>>& output_tensors) {
              ASSERT_EQ(result,
                        model_loader::mojom::ComputeResult::kMissingInput);
              ASSERT_FALSE(output_tensors.has_value());

              *compute_callback_done = true;
            },
            &compute_callback_done));

    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(compute_callback_done);
  }

  {
    // Compute with wrong input tensor buffer size.
    base::flat_map<std::string, std::vector<uint8_t>> inputs;
    inputs["x"].resize(4);
    const float x = 3.21;
    memcpy(inputs["x"].data(), &x, 4);

    inputs["y"].resize(4);
    const float y = 6.54;
    memcpy(inputs["y"].data(), &y, 4);

    // Make "x" buffer of wrong size;
    inputs["x"].resize(100);

    bool compute_callback_done = false;
    model->Compute(
        std::move(inputs),
        base::BindOnce(
            [](bool* compute_callback_done,
               model_loader::mojom::ComputeResult result,
               const std::optional<base::flat_map<
                   std::string, std::vector<uint8_t>>>& output_tensors) {
              ASSERT_EQ(
                  result,
                  model_loader::mojom::ComputeResult::kInvalidInputBufferSize);
              ASSERT_FALSE(output_tensors.has_value());

              *compute_callback_done = true;
            },
            &compute_callback_done));

    base::RunLoop().RunUntilIdle();
    ASSERT_TRUE(compute_callback_done);
  }
}

}  // namespace ml
