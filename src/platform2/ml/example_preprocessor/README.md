# Example preprocessor

This is used in a feature-level ml-service. `RankerExample` proto contains a
feature map from name to value, and `ExamplePreprocessor` can vectorize it to a
float list with an `ExamplePreprocessorConfig`. The vectorized list can be used
as tensor and fed to tflite models.

Files in this directory are copied from chromium repo:
//components/assist_ranker/.

ranker_example.proto and example_preprocessor.proto in ../proto are copied from
chromium repo: //components/assist_ranker/proto/
