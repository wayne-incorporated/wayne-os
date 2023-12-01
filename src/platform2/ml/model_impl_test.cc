// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <tensorflow/lite/model.h>

#include "ml/model_impl.h"
#include "ml/mojom/graph_executor.mojom.h"
#include "ml/mojom/model.mojom.h"
#include "ml/tensor_view.h"
#include "ml/test_utils.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::CreateGraphExecutorResult;
using ::chromeos::machine_learning::mojom::ExecuteResult;
using ::chromeos::machine_learning::mojom::GraphExecutor;
using ::chromeos::machine_learning::mojom::GraphExecutorOptions;
using ::chromeos::machine_learning::mojom::Model;
using ::chromeos::machine_learning::mojom::TensorPtr;
using ::testing::ElementsAre;
using ::testing::Eq;

class ModelImplTest : public testing::Test {
 protected:
  // Metadata for the example model:
  // A simple model that adds up two tensors. Inputs and outputs are 1x1 float
  // tensors.
  const std::string model_path_ =
      GetTestModelDir() + "mlservice-model-test_add-20180914.tflite";
  const std::map<std::string, int> model_inputs_ = {{"x", 1}, {"y", 2}};
  const std::map<std::string, int> model_outputs_ = {{"z", 0}};
};

// Tests that AlignedModelData ensures that short strings have aligned .c_str().
TEST(AlignedModelData, MaybeUnalignedInput) {
  // Short strings can have unaligned .c_str() because they are stored directly
  // inside the string struct rather than on the heap.
  const std::string test_str = "short string";
  std::string maybe_unaligned_str = test_str;
  // Note: Whether `maybe_unaligned_str` *actually* has unaligned .c_str()
  // depends on the particular impl of std::string. At the time of writing, it
  // is indeed unaligned on e.g. amd64-generic.
  const AlignedModelData aligned_model_data(std::move(maybe_unaligned_str));
  // The .data() should now be aligned.
  EXPECT_THAT(reinterpret_cast<std::uintptr_t>(aligned_model_data.data()) % 4,
              Eq(0));
  // The contents agree.
  EXPECT_TRUE(
      std::equal(test_str.begin(), test_str.end(), aligned_model_data.data()));
}

// Test loading an invalid model.
TEST_F(ModelImplTest, TestBadModel) {
  // Pass nullptr instead of a valid model.
  mojo::Remote<Model> model;
  ModelImpl::Create(
      std::make_unique<ModelDelegate>(model_inputs_, model_outputs_,
                                      nullptr /*model*/, "TestModel"),
      model.BindNewPipeAndPassReceiver());

  ASSERT_TRUE(model.is_bound());

  // Ensure that creating a graph executor fails.
  bool callback_done = false;
  mojo::Remote<GraphExecutor> graph_executor;
  model->CreateGraphExecutor(
      GraphExecutorOptions::New(), graph_executor.BindNewPipeAndPassReceiver(),
      base::BindOnce(
          [](bool* callback_done, const CreateGraphExecutorResult result) {
            EXPECT_EQ(result,
                      CreateGraphExecutorResult::MODEL_INTERPRETATION_ERROR);
            *callback_done = true;
          },
          &callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback_done);
}

// Test loading the valid example model.
TEST_F(ModelImplTest, TestExampleModel) {
  // Read the example TF model from disk.
  std::unique_ptr<tflite::FlatBufferModel> tflite_model =
      tflite::FlatBufferModel::BuildFromFile(model_path_.c_str());
  ASSERT_NE(tflite_model.get(), nullptr);

  // Create model object.
  mojo::Remote<Model> model;
  ModelImpl::Create(
      std::make_unique<ModelDelegate>(model_inputs_, model_outputs_,
                                      std::move(tflite_model), "TestModel"),
      model.BindNewPipeAndPassReceiver());
  ASSERT_TRUE(model.is_bound());

  // Create a graph executor.
  bool cge_callback_done = false;
  mojo::Remote<GraphExecutor> graph_executor;
  model->CreateGraphExecutor(
      GraphExecutorOptions::New(), graph_executor.BindNewPipeAndPassReceiver(),
      base::BindOnce(
          [](bool* cge_callback_done, const CreateGraphExecutorResult result) {
            EXPECT_EQ(result, CreateGraphExecutorResult::OK);
            *cge_callback_done = true;
          },
          &cge_callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(cge_callback_done);

  // Construct input/output for graph execution.
  base::flat_map<std::string, TensorPtr> inputs;
  inputs.emplace("x", NewTensor<double>({1}, {0.5}));
  inputs.emplace("y", NewTensor<double>({1}, {0.25}));
  std::vector<std::string> outputs({"z"});

  // Execute graph.
  bool exe_callback_done = false;
  graph_executor->Execute(
      std::move(inputs), std::move(outputs),
      base::BindOnce(
          [](bool* exe_callback_done, const ExecuteResult result,
             std::optional<std::vector<TensorPtr>> outputs) {
            // Check that the inference succeeded and gives the expected number
            // of outputs.
            EXPECT_EQ(result, ExecuteResult::OK);
            ASSERT_TRUE(outputs.has_value());
            ASSERT_EQ(outputs->size(), 1);

            // Check that the output tensor has the right type and format.
            const TensorView<double> out_tensor((*outputs)[0]);
            EXPECT_TRUE(out_tensor.IsValidType());
            EXPECT_TRUE(out_tensor.IsValidFormat());

            // Check the output tensor has the expected shape and values.
            EXPECT_THAT(out_tensor.GetShape(), ElementsAre(1));
            EXPECT_THAT(out_tensor.GetValues(), ElementsAre(0.75));

            *exe_callback_done = true;
          },
          &exe_callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(exe_callback_done);
}

TEST_F(ModelImplTest, TestGraphExecutorCleanup) {
  // Read the example TF model from disk.
  std::unique_ptr<tflite::FlatBufferModel> tflite_model =
      tflite::FlatBufferModel::BuildFromFile(model_path_.c_str());
  ASSERT_NE(tflite_model.get(), nullptr);

  // Create model object.
  mojo::Remote<Model> model;
  const ModelImpl* model_impl = ModelImpl::Create(
      std::make_unique<ModelDelegate>(model_inputs_, model_outputs_,
                                      std::move(tflite_model), "TestModel"),
      model.BindNewPipeAndPassReceiver());
  ASSERT_TRUE(model.is_bound());

  // Create one graph executor.
  bool cge1_callback_done = false;
  mojo::Remote<GraphExecutor> graph_executor_1;
  model->CreateGraphExecutor(
      GraphExecutorOptions::New(),
      graph_executor_1.BindNewPipeAndPassReceiver(),
      base::BindOnce(
          [](bool* cge1_callback_done, const CreateGraphExecutorResult result) {
            EXPECT_EQ(result, CreateGraphExecutorResult::OK);
            *cge1_callback_done = true;
          },
          &cge1_callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(cge1_callback_done);
  ASSERT_TRUE(graph_executor_1.is_bound());
  ASSERT_EQ(model_impl->num_graph_executors_for_testing(), 1);

  // Create another graph executor.
  bool cge2_callback_done = false;
  mojo::Remote<GraphExecutor> graph_executor_2;
  model->CreateGraphExecutor(
      GraphExecutorOptions::New(),
      graph_executor_2.BindNewPipeAndPassReceiver(),
      base::BindOnce(
          [](bool* cge2_callback_done, const CreateGraphExecutorResult result) {
            EXPECT_EQ(result, CreateGraphExecutorResult::OK);
            *cge2_callback_done = true;
          },
          &cge2_callback_done));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(cge2_callback_done);
  ASSERT_TRUE(graph_executor_2.is_bound());
  ASSERT_EQ(model_impl->num_graph_executors_for_testing(), 2);

  // Destroy one graph executor.
  graph_executor_1.reset();
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(graph_executor_2.is_bound());
  ASSERT_EQ(model_impl->num_graph_executors_for_testing(), 1);

  // Destroy the other graph executor.
  graph_executor_2.reset();
  base::RunLoop().RunUntilIdle();
  ASSERT_EQ(model_impl->num_graph_executors_for_testing(), 0);
}

}  // namespace
}  // namespace ml
