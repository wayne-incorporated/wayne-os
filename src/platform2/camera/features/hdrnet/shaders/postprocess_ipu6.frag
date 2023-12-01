#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputTexture;
layout(binding = 1) uniform highp sampler2D uGammaLutTexture;
layout(binding = 2) uniform highp sampler2D uGtmLutTexture;

layout(location = 0) uniform bool uIsYPlane;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

float max_rgb(vec3 v) {
  return max(max(v.r, v.g), v.b);
}

void main() {
  vec3 rgb = texture(uInputTexture, vTexCoord).rgb;

  // Re-apply GTM.
  float max_value = max_rgb(rgb);
  float gain = texture(uGtmLutTexture, vec2(max_value, 0.0)).r;
  vec3 gtm_rgb = clamp(rgb * gain, 0.0, 1.0);

  // Re-apply Gamma.
  vec3 out_rgb = vec3(
      texture(uGammaLutTexture, vec2(gtm_rgb.r, 0.0)).r,
      texture(uGammaLutTexture, vec2(gtm_rgb.g, 0.0)).r,
      texture(uGammaLutTexture, vec2(gtm_rgb.b, 0.0)).r);

  // Convert to NV12.
  if (uIsYPlane) {
    float y = 0.299 * out_rgb.r + 0.587 * out_rgb.g + 0.114 * out_rgb.b;
    outColor = vec4(y, 0.0, 0.0, 0.0);
  } else {
    float u = -0.16874 * out_rgb.r - 0.33126 * out_rgb.g + 0.5 * out_rgb.b + 0.5;
    float v = 0.5 * out_rgb.r - 0.41869 * out_rgb.g - 0.08131 * out_rgb.b + 0.5;
    outColor = vec4(u, v, 0.0, 0.0);
  }
}
