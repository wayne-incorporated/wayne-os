#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputYTexture;
layout(binding = 1) uniform highp sampler2D uInputUvTexture;
layout(binding = 2) uniform highp sampler2D uInverseGammaLutTexture;
layout(binding = 3) uniform highp sampler2D uInverseGtmLutTexture;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

// Intel's GL ES implementation always samples the YUV image with narrow range
// color space and it's crushing the shadow areas on the images. Before we
// have a fix in the mesa, sample and covert the YUV image to RGB ourselves.
vec3 sample_input_as_rgb() {
  float y = texture(uInputYTexture, vTexCoord).x;
  vec2 uv = texture(uInputUvTexture, vTexCoord).xy;

  vec3 yuv_in = vec3(y, uv - vec2(0.5));
  const vec3 yuv_2_rgb_0 = vec3(1.0,     0.0,  1.4017);
  const vec3 yuv_2_rgb_1 = vec3(1.0, -0.3437, -0.7142);
  const vec3 yuv_2_rgb_2 = vec3(1.0,  1.7722,  0.0);

  return clamp(vec3(
    dot(yuv_in, yuv_2_rgb_0),
    dot(yuv_in, yuv_2_rgb_1),
    dot(yuv_in, yuv_2_rgb_2)
  ), 0.0, 1.0);
}

float max_rgb(vec3 v) {
  return max(max(v.r, v.g), v.b);
}

void main() {
  vec3 rgb = sample_input_as_rgb();

  // Apply inverse Gamma.
  vec3 gamma_inversed_rgb = vec3(
      texture(uInverseGammaLutTexture, vec2(rgb.r, 0.0)).r,
      texture(uInverseGammaLutTexture, vec2(rgb.g, 0.0)).r,
      texture(uInverseGammaLutTexture, vec2(rgb.b, 0.0)).r);

  // Apply inverse GTM.
  float max_value = max_rgb(gamma_inversed_rgb);
  float gain = texture(uInverseGtmLutTexture, vec2(max_value, 0.0)).r;
  outColor = vec4(gamma_inversed_rgb / gain, 1.0);
}
