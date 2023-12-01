#version 310 es

precision highp float;

layout(binding = 0) uniform highp sampler2D uInputRgbaTexture;
layout(location = 0) uniform float uGammaValue;

layout(location = 0) in highp vec2 vTexCoord;
layout(location = 0) out highp vec4 outColor;

vec3 apply_gamma(vec3 inputRgb, vec3 gamma) {
  return pow(inputRgb, 1.0 / gamma);
}

void main() {
  vec3 gamma = vec3(uGammaValue, uGammaValue, uGammaValue);
  outColor = vec4(
      apply_gamma(texture(uInputRgbaTexture, vTexCoord).rgb, gamma), 1.0);
}

